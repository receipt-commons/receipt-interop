/**
 * Tests for the agent-passport Action Receipts v1.1 verifier.
 *
 * All fixtures are minted in-test with tweetnacl (real Ed25519 signatures)
 * using an INDEPENDENT port of the APS canonical JSON (written from
 * docs/CANONICAL-SPEC.md, not copied from the verifier under test), so a
 * canonicalization bug in src/ fails signature verification here.
 * Key encoding matches the reference: raw 32-byte keys as lowercase hex,
 * 64-byte signatures as lowercase hex (src/crypto/keys.ts).
 *
 * The verifier's own canonicalizer is additionally checked byte-for-byte
 * against the published conformance vectors in
 * specs/test-vectors-canonicalization.json (expected_legacy).
 *
 * Run: npx tsx --test test/agent-passport.test.ts   (from the package dir)
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import nacl from "tweetnacl";

import agentPassport, { apsCanonicalize } from "../src/formats/agent-passport.js";
import type { VerifyOptions } from "../src/model.js";

// ---------------------------------------------------------------------------
// Independent fixture minting (second port of the canonicalization spec)
// ---------------------------------------------------------------------------

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}
function unhex(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "hex"));
}

/** Independent APS canonical JSON port (from CANONICAL-SPEC.md text). */
function canon(v: unknown): string {
  if (v === null || v === undefined) return "null";
  if (typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  const rec = v as Record<string, unknown>;
  const parts: string[] = [];
  for (const k of Object.keys(rec).sort()) {
    const val = rec[k];
    if (val === null || val === undefined) continue;
    parts.push(JSON.stringify(k) + ":" + canon(val));
  }
  return "{" + parts.join(",") + "}";
}

function edSign(unsigned: Record<string, unknown>, privHex: string): string {
  const msg = new TextEncoder().encode(canon(unsigned));
  return hex(nacl.sign.detached(msg, unhex(privHex)));
}

interface Key { pub: string; priv: string }
function keypair(): Key {
  const kp = nacl.sign.keyPair();
  // tweetnacl signs with the full 64-byte secret key; the repo's hex format
  // (src/crypto/keys.ts) stores the 32-byte seed, but for minting fixtures the
  // full secret key is what sign.detached needs.
  return { pub: hex(kp.publicKey), priv: hex(kp.secretKey) };
}

const NOW = Date.now();
const iso = (ms: number) => new Date(ms).toISOString();

interface DelegationOpts {
  delegatedTo: string;
  delegatedBy: string;
  scope: string[];
  maxDepth?: number;
  currentDepth?: number;
  expiresAt?: string;
  notBefore?: string;
  spendLimit?: number;
  spentAmount?: number;
  spendLimitUnit?: string;
  revoked?: boolean;
  signerPriv: string;
  delegationId?: string;
}

function mintDelegation(o: DelegationOpts): Record<string, unknown> {
  const unsigned: Record<string, unknown> = {
    delegationId: o.delegationId ?? "del_test_" + Math.random().toString(36).slice(2, 10),
    delegatedTo: o.delegatedTo,
    delegatedBy: o.delegatedBy,
    scope: o.scope,
    expiresAt: o.expiresAt ?? iso(NOW + 24 * 3600_000),
    spendLimit: o.spendLimit,
    spentAmount: o.spentAmount ?? 0,
    spendLimitUnit: o.spendLimitUnit,
    maxDepth: o.maxDepth,
    currentDepth: o.currentDepth ?? 0,
    createdAt: iso(NOW - 3600_000),
    notBefore: o.notBefore,
    revoked: o.revoked,
  };
  return { ...unsigned, signature: edSign(unsigned, o.signerPriv) };
}

interface ReceiptOpts {
  agentId: string;
  delegationId: string;
  action: Record<string, unknown>;
  result?: Record<string, unknown>;
  delegationChain: string[];
  signerPriv: string;
  timestamp?: string;
  receiptId?: string;
  previousReceiptHash?: string;
}

function mintReceipt(o: ReceiptOpts): Record<string, unknown> {
  const unsigned: Record<string, unknown> = {
    receipt_id: o.receiptId ?? "rcpt_test_" + Math.random().toString(36).slice(2, 10),
    version: "1.1",
    timestamp: o.timestamp ?? iso(NOW - 60_000),
    agent_id: o.agentId,
    delegation_id: o.delegationId,
    action: o.action,
    result: o.result ?? { status: "success", summary: "ok" },
    delegation_chain: o.delegationChain,
    previousReceiptHash: o.previousReceiptHash,
  };
  return { ...unsigned, signature: edSign(unsigned, o.signerPriv) };
}

function mintRevocation(
  delegationId: string,
  revokedBy: string,
  revokerPriv: string
): Record<string, unknown> {
  const unsigned: Record<string, unknown> = {
    revocation_id: "rev_test_" + Math.random().toString(36).slice(2, 8),
    delegation_id: delegationId,
    revoked_by: revokedBy,
    revoked_at: iso(NOW - 1000),
    reason: "agent_compromised",
  };
  return { ...unsigned, signature: edSign(unsigned, revokerPriv) };
}

/** A standard principal -> agent delegation pair for receipt tests. */
function basicSetup() {
  const principal = keypair();
  const agent = keypair();
  const delegation = mintDelegation({
    delegatedTo: agent.pub,
    delegatedBy: principal.pub,
    scope: ["book_flights", "search_hotels"],
    maxDepth: 2,
    currentDepth: 0,
    spendLimit: 1000,
    signerPriv: principal.priv,
  });
  return { principal, agent, delegation };
}

// ---------------------------------------------------------------------------
// detect()
// ---------------------------------------------------------------------------

describe("detect()", () => {
  it("detects a bare Action Receipt v1.1", () => {
    const { principal, agent, delegation } = basicSetup();
    const receipt = mintReceipt({
      agentId: "agent-a",
      delegationId: delegation["delegationId"] as string,
      action: { type: "api_call", target: "booking.example.com", scope_used: "book_flights" },
      delegationChain: [principal.pub, agent.pub],
      signerPriv: agent.priv,
    });
    assert.equal(agentPassport.detect(receipt), true);
  });

  it("detects a chain envelope and a JSON string", () => {
    const { principal, agent, delegation } = basicSetup();
    const receipt = mintReceipt({
      agentId: "agent-a",
      delegationId: delegation["delegationId"] as string,
      action: { type: "api_call", target: "booking.example.com", scope_used: "book_flights" },
      delegationChain: [principal.pub, agent.pub],
      signerPriv: agent.priv,
    });
    assert.equal(agentPassport.detect({ receipt, delegations: [delegation] }), true);
    assert.equal(agentPassport.detect(JSON.stringify(receipt)), true);
  });

  it("rejects non-receipt inputs", () => {
    assert.equal(agentPassport.detect(null), false);
    assert.equal(agentPassport.detect("not json"), false);
    assert.equal(agentPassport.detect({ foo: "bar" }), false);
    // missing action.scope_used
    assert.equal(
      agentPassport.detect({ receipt_id: "x", agent_id: "a", delegation_id: "d", signature: "s", timestamp: "t", action: {} }),
      false
    );
  });
});

// ---------------------------------------------------------------------------
// Canonicalization conformance (published vectors)
// ---------------------------------------------------------------------------

describe("APS canonical JSON conformance", () => {
  // From specs/test-vectors-canonicalization.json (expected_legacy column)
  const vectors: Array<[string, unknown, string]> = [
    ["cv-001", { agentId: "agent-001", scope: "read" }, '{"agentId":"agent-001","scope":"read"}'],
    ["cv-002", { agentId: "agent-001", metadata: null, scope: "read" }, '{"agentId":"agent-001","scope":"read"}'],
    ["cv-003", { zebra: 1, alpha: 2, middle: 3 }, '{"alpha":2,"middle":3,"zebra":1}'],
    ["null-strip-nested", { z: { b: 2, a: 1 }, a: 0 }, '{"a":0,"z":{"a":1,"b":2}}'],
    ["array-nulls-kept", [1, null, 3], "[1,null,3]"],
    ["empty", {}, "{}"],
  ];
  for (const [id, input, expected] of vectors) {
    it(`${id} matches the published legacy vector`, () => {
      assert.equal(apsCanonicalize(input), expected);
    });
  }
  it("independent test port agrees with the verifier's port", () => {
    const sample = {
      receipt_id: "rcpt_x",
      version: "1.1",
      action: { type: "t", scope_used: "s", spend: { amount: 5, currency: "USD" }, extra: null },
      delegation_chain: ["a", "b"],
    };
    assert.equal(apsCanonicalize(sample), canon(sample));
  });
});

// ---------------------------------------------------------------------------
// verify(): happy paths
// ---------------------------------------------------------------------------

describe("verify() — valid receipts", () => {
  it("verifies a valid bare receipt (signature + version)", async () => {
    const { principal, agent, delegation } = basicSetup();
    const receipt = mintReceipt({
      agentId: "agent-a",
      delegationId: delegation["delegationId"] as string,
      action: { type: "api_call", target: "booking.example.com", method: "POST /reservations", scope_used: "book_flights", spend: { amount: 450, currency: "USD" } },
      delegationChain: [principal.pub, agent.pub],
      signerPriv: agent.priv,
    });
    const v = await agentPassport.verify(receipt, {});
    assert.equal(v.valid, true);
    assert.deepEqual(v.errors, []);
    assert.ok(v.receipt);
    assert.equal(v.receipt.format, "agent-passport");
    assert.equal(v.receipt.receiptId, receipt["receipt_id"]);
    assert.equal(v.receipt.issuer, agent.pub);
    assert.equal(v.receipt.issuerKey.kty, "OKP");
    assert.equal(v.receipt.issuerKey.crv, "Ed25519");
    assert.equal(v.receipt.agent, "agent-a");
    // offline: revocation is unknown, and the chain was not supplied
    assert.equal(v.receipt.revocation.status, "unknown");
    assert.ok(v.warnings.some((w) => w.includes("REVOCATION_UNCHECKED_OFFLINE")));
    assert.ok(v.warnings.some((w) => w.includes("AP_CHAIN_NOT_SUPPLIED")));
  });

  it("verifies a multi-hop chain with scope narrowing", async () => {
    const principal = keypair();
    const agentA = keypair();
    const agentB = keypair();
    const root = mintDelegation({
      delegatedTo: agentA.pub,
      delegatedBy: principal.pub,
      scope: ["commerce:*"],
      maxDepth: 2,
      currentDepth: 0,
      signerPriv: principal.priv,
      expiresAt: iso(NOW + 48 * 3600_000),
    });
    const child = mintDelegation({
      delegatedTo: agentB.pub,
      delegatedBy: agentA.pub,
      scope: ["commerce:checkout"], // narrower than commerce:* per scopeCovers
      maxDepth: 2, // inherited ceiling, not increased
      currentDepth: 1,
      signerPriv: agentA.priv,
      expiresAt: iso(NOW + 24 * 3600_000), // narrower than parent
    });
    const receipt = mintReceipt({
      agentId: "agent-b",
      delegationId: child["delegationId"] as string,
      action: { type: "api_call", target: "pay.example.com", scope_used: "commerce:checkout" },
      delegationChain: [principal.pub, agentA.pub, agentB.pub],
      signerPriv: agentB.priv,
    });
    const v = await agentPassport.verify({ receipt, delegations: [root, child] }, {});
    assert.equal(v.valid, true);
    assert.deepEqual(v.errors, []);
    assert.equal(v.receipt?.parentId, child["delegationId"]);
    assert.equal(v.receipt?.notAfter, child["expiresAt"]);
  });

  it("keeps revocation unknown when the only evidence names another delegation", async () => {
    // Regression (issue #216 finding #3): a validly signed revocation for an
    // UNRELATED delegation must not move the status away from 'unknown'.
    const principal = keypair();
    const agent = keypair();
    const stranger = keypair();
    const delegation = mintDelegation({
      delegatedTo: agent.pub,
      delegatedBy: principal.pub,
      scope: ["read"],
      signerPriv: principal.priv,
    });
    const rv = mintRevocation("del_someone_else", stranger.pub, stranger.priv);
    const receipt = mintReceipt({
      agentId: "agent-a",
      delegationId: delegation["delegationId"] as string,
      action: { type: "read", target: "db", scope_used: "read" },
      delegationChain: [principal.pub, agent.pub],
      signerPriv: agent.priv,
    });
    const v = await agentPassport.verify(
      { receipt, delegations: [delegation], revocations: [rv] },
      {}
    );
    assert.equal(v.valid, true);
    assert.equal(v.receipt?.revocation.status, "unknown");
    assert.ok(v.warnings.some((w) => w.includes("REVOCATION_UNCHECKED_OFFLINE")));
  });

  it("keeps revocation unknown when the revocation is not signed by the delegator", async () => {
    // Regression (issue #216 finding #3): a revocation naming the chain's
    // delegation but signed by a NON-delegator key must not move the status
    // away from 'unknown'.
    const principal = keypair();
    const agent = keypair();
    const stranger = keypair();
    const delegation = mintDelegation({
      delegatedTo: agent.pub,
      delegatedBy: principal.pub,
      scope: ["read"],
      signerPriv: principal.priv,
    });
    const rv = mintRevocation(
      delegation["delegationId"] as string,
      stranger.pub,
      stranger.priv
    );
    const receipt = mintReceipt({
      agentId: "agent-a",
      delegationId: delegation["delegationId"] as string,
      action: { type: "read", target: "db", scope_used: "read" },
      delegationChain: [principal.pub, agent.pub],
      signerPriv: agent.priv,
    });
    const v = await agentPassport.verify(
      { receipt, delegations: [delegation], revocations: [rv] },
      {}
    );
    assert.equal(v.valid, true);
    assert.equal(v.receipt?.revocation.status, "unknown");
    assert.ok(v.warnings.some((w) => w.includes("REVOCATION_UNCHECKED_OFFLINE")));
  });
});

// ---------------------------------------------------------------------------
// verify(): rejections
// ---------------------------------------------------------------------------

describe("verify() — rejections", () => {
  it("rejects a receipt with a tampered field (AP_BAD_SIGNATURE)", async () => {
    const { principal, agent, delegation } = basicSetup();
    const receipt = mintReceipt({
      agentId: "agent-a",
      delegationId: delegation["delegationId"] as string,
      action: { type: "api_call", target: "booking.example.com", scope_used: "book_flights" },
      result: { status: "success", summary: "Booked LAX->JFK" },
      delegationChain: [principal.pub, agent.pub],
      signerPriv: agent.priv,
    });
    const tampered = {
      ...receipt,
      result: { status: "success", summary: "Booked LAX->JFK, also wired $1M" },
    };
    const v = await agentPassport.verify(tampered, {});
    assert.equal(v.valid, false);
    assert.equal(v.receipt, null);
    assert.ok(v.errors.some((e) => e.startsWith("AP_BAD_SIGNATURE")));
  });

  it("rejects a wrong-version receipt (AP_UNSUPPORTED_VERSION)", async () => {
    const { principal, agent, delegation } = basicSetup();
    const receipt = mintReceipt({
      agentId: "agent-a",
      delegationId: delegation["delegationId"] as string,
      action: { type: "t", target: "x", scope_used: "book_flights" },
      delegationChain: [principal.pub, agent.pub],
      signerPriv: agent.priv,
    });
    (receipt as Record<string, unknown>)["version"] = "2.0";
    const v = await agentPassport.verify(receipt, {});
    assert.equal(v.valid, false);
    assert.ok(v.errors.some((e) => e.startsWith("AP_UNSUPPORTED_VERSION")));
  });

  it("rejects depth exceeding maxDepth (AP_DEPTH_EXCEEDED)", async () => {
    const principal = keypair();
    const agentA = keypair();
    const agentB = keypair();
    const root = mintDelegation({
      delegatedTo: agentA.pub,
      delegatedBy: principal.pub,
      scope: ["code"],
      maxDepth: 1, // only one hop allowed
      currentDepth: 0,
      signerPriv: principal.priv,
    });
    const child = mintDelegation({
      delegatedTo: agentB.pub,
      delegatedBy: agentA.pub,
      scope: ["code"],
      maxDepth: 1,
      currentDepth: 1,
      signerPriv: agentA.priv,
    });
    // hand-minted grandchild at depth 2 > maxDepth 1 (bypasses the mint-time guard)
    const agentC = keypair();
    const grandchild = mintDelegation({
      delegatedTo: agentC.pub,
      delegatedBy: agentB.pub,
      scope: ["code"],
      maxDepth: 1,
      currentDepth: 2,
      signerPriv: agentB.priv,
    });
    const receipt = mintReceipt({
      agentId: "agent-c",
      delegationId: grandchild["delegationId"] as string,
      action: { type: "t", target: "x", scope_used: "code" },
      delegationChain: [principal.pub, agentA.pub, agentB.pub, agentC.pub],
      signerPriv: agentC.priv,
    });
    void child;
    const v = await agentPassport.verify(
      { receipt, delegations: [root, child, grandchild] },
      {}
    );
    assert.equal(v.valid, false);
    assert.ok(v.errors.some((e) => e.startsWith("AP_DEPTH_EXCEEDED")), JSON.stringify(v.errors));
  });

  it("defaults omitted maxDepth to 1 per SPEC-v1.1 section 3.4", async () => {
    const principal = keypair();
    const agentA = keypair();
    const agentB = keypair();
    const root = mintDelegation({
      delegatedTo: agentA.pub,
      delegatedBy: principal.pub,
      scope: ["code"],
      // maxDepth omitted entirely
      currentDepth: 0,
      signerPriv: principal.priv,
    });
    delete (root as Record<string, unknown>)["maxDepth"];
    const child = mintDelegation({
      delegatedTo: agentB.pub,
      delegatedBy: agentA.pub,
      scope: ["code"],
      currentDepth: 1,
      signerPriv: agentA.priv,
    });
    delete (child as Record<string, unknown>)["maxDepth"];
    const receipt = mintReceipt({
      agentId: "agent-b",
      delegationId: child["delegationId"] as string,
      action: { type: "t", target: "x", scope_used: "code" },
      delegationChain: [principal.pub, agentA.pub, agentB.pub],
      signerPriv: agentB.priv,
    });
    // depth 1 with default maxDepth 1 is fine
    const ok = await agentPassport.verify({ receipt, delegations: [root, child] }, {});
    assert.equal(ok.valid, true);

    // but a second hop (depth 2) exceeds the default ceiling
    const agentC = keypair();
    const grandchild = mintDelegation({
      delegatedTo: agentC.pub,
      delegatedBy: agentB.pub,
      scope: ["code"],
      currentDepth: 2,
      signerPriv: agentB.priv,
    });
    delete (grandchild as Record<string, unknown>)["maxDepth"];
    const receipt2 = mintReceipt({
      agentId: "agent-c",
      delegationId: grandchild["delegationId"] as string,
      action: { type: "t", target: "x", scope_used: "code" },
      delegationChain: [principal.pub, agentA.pub, agentB.pub, agentC.pub],
      signerPriv: agentC.priv,
    });
    const bad = await agentPassport.verify(
      { receipt: receipt2, delegations: [root, child, grandchild] },
      {}
    );
    assert.equal(bad.valid, false);
    assert.ok(bad.errors.some((e) => e.startsWith("AP_DEPTH_EXCEEDED")));
  });

  it("rejects a widened child scope (AP_NARROWING_VIOLATION)", async () => {
    const principal = keypair();
    const agentA = keypair();
    const agentB = keypair();
    const root = mintDelegation({
      delegatedTo: agentA.pub,
      delegatedBy: principal.pub,
      scope: ["commerce:*"],
      maxDepth: 2,
      currentDepth: 0,
      signerPriv: principal.priv,
    });
    const child = mintDelegation({
      delegatedTo: agentB.pub,
      delegatedBy: agentA.pub,
      scope: ["commerce:checkout", "admin"], // 'admin' not covered by parent
      maxDepth: 2,
      currentDepth: 1,
      signerPriv: agentA.priv,
    });
    const receipt = mintReceipt({
      agentId: "agent-b",
      delegationId: child["delegationId"] as string,
      action: { type: "t", target: "x", scope_used: "commerce:checkout" },
      delegationChain: [principal.pub, agentA.pub, agentB.pub],
      signerPriv: agentB.priv,
    });
    const v = await agentPassport.verify({ receipt, delegations: [root, child] }, {});
    assert.equal(v.valid, false);
    assert.ok(v.errors.some((e) => e.startsWith("AP_NARROWING_VIOLATION")));
  });

  it("rejects scope_used outside the leaf delegation scope (AP_SCOPE_VIOLATION)", async () => {
    const { principal, agent, delegation } = basicSetup();
    const receipt = mintReceipt({
      agentId: "agent-a",
      delegationId: delegation["delegationId"] as string,
      action: { type: "t", target: "x", scope_used: "delete_everything" },
      delegationChain: [principal.pub, agent.pub],
      signerPriv: agent.priv,
    });
    const v = await agentPassport.verify({ receipt, delegations: [delegation] }, {});
    assert.equal(v.valid, false);
    assert.ok(v.errors.some((e) => e.startsWith("AP_SCOPE_VIOLATION")));
  });

  it("rejects spend over the delegation's remaining budget (AP_OVER_BUDGET)", async () => {
    const { principal, agent, delegation } = basicSetup();
    const receipt = mintReceipt({
      agentId: "agent-a",
      delegationId: delegation["delegationId"] as string,
      action: { type: "t", target: "x", scope_used: "book_flights", spend: { amount: 99999, currency: "USD" } },
      delegationChain: [principal.pub, agent.pub],
      signerPriv: agent.priv,
    });
    const v = await agentPassport.verify({ receipt, delegations: [delegation] }, {});
    assert.equal(v.valid, false);
    assert.ok(v.errors.some((e) => e.startsWith("AP_OVER_BUDGET")));
  });

  it("rejects a receipt issued after delegation expiry (AP_EXPIRED)", async () => {
    const { principal, agent, delegation } = basicSetup();
    (delegation as Record<string, unknown>)["expiresAt"] = iso(NOW - 3600_000);
    // re-sign after mutating
    const unsigned = { ...(delegation as Record<string, unknown>) };
    delete unsigned["signature"];
    (delegation as Record<string, unknown>)["signature"] = edSign(unsigned, principal.priv);
    const receipt = mintReceipt({
      agentId: "agent-a",
      delegationId: delegation["delegationId"] as string,
      action: { type: "t", target: "x", scope_used: "book_flights" },
      delegationChain: [principal.pub, agent.pub],
      signerPriv: agent.priv,
      timestamp: iso(NOW - 60_000),
    });
    const v = await agentPassport.verify({ receipt, delegations: [delegation] }, {});
    assert.equal(v.valid, false);
    assert.ok(v.errors.some((e) => e.startsWith("AP_EXPIRED")));
  });

  it("rejects a signer outside trustedIssuers (AP_UNTRUSTED_ISSUER)", async () => {
    const { principal, agent } = basicSetup();
    const receipt = mintReceipt({
      agentId: "agent-a",
      delegationId: "del_x",
      action: { type: "t", target: "x", scope_used: "s" },
      delegationChain: [principal.pub, agent.pub],
      signerPriv: agent.priv,
    });
    const opts: VerifyOptions = { trustedIssuers: [principal.pub] };
    const v = await agentPassport.verify(receipt, opts);
    assert.equal(v.valid, false);
    assert.ok(v.errors.some((e) => e.startsWith("AP_UNTRUSTED_ISSUER")));
  });

  it("rejects a revoked chain with cascade (AP_REVOKED)", async () => {
    const principal = keypair();
    const agentA = keypair();
    const agentB = keypair();
    const root = mintDelegation({
      delegatedTo: agentA.pub,
      delegatedBy: principal.pub,
      scope: ["commerce:*"],
      maxDepth: 3,
      currentDepth: 0,
      signerPriv: principal.priv,
    });
    const child = mintDelegation({
      delegatedTo: agentB.pub,
      delegatedBy: agentA.pub,
      scope: ["commerce:checkout"],
      maxDepth: 3,
      currentDepth: 1,
      signerPriv: agentA.priv,
    });
    // principal revokes the ROOT delegation; cascade must kill the child too
    const rv = mintRevocation(root["delegationId"] as string, principal.pub, principal.priv);
    const receipt = mintReceipt({
      agentId: "agent-b",
      delegationId: child["delegationId"] as string,
      action: { type: "t", target: "x", scope_used: "commerce:checkout" },
      delegationChain: [principal.pub, agentA.pub, agentB.pub],
      signerPriv: agentB.priv,
    });
    const v = await agentPassport.verify(
      { receipt, delegations: [root, child], revocations: [rv] },
      {}
    );
    assert.equal(v.valid, false);
    assert.ok(v.errors.some((e) => e.startsWith("AP_REVOKED")));
  });

  it("ignores a revocation with a bad signature (warning) and still verifies", async () => {
    const { principal, agent, delegation } = basicSetup();
    const rv = mintRevocation(delegation["delegationId"] as string, principal.pub, principal.priv);
    (rv as Record<string, unknown>)["signature"] = "ab".repeat(64); // corrupt
    const receipt = mintReceipt({
      agentId: "agent-a",
      delegationId: delegation["delegationId"] as string,
      action: { type: "t", target: "x", scope_used: "book_flights" },
      delegationChain: [principal.pub, agent.pub],
      signerPriv: agent.priv,
    });
    const v = await agentPassport.verify(
      { receipt, delegations: [delegation], revocations: [rv] },
      {}
    );
    assert.equal(v.valid, true);
    assert.ok(v.warnings.some((w) => w.includes("AP_BAD_REVOCATION_SIGNATURE")));
  });

  it("rejects a chain break (delegatedBy mismatch, AP_CHAIN_BREAK)", async () => {
    const principal = keypair();
    const agentA = keypair();
    const agentB = keypair();
    const stranger = keypair();
    const root = mintDelegation({
      delegatedTo: agentA.pub,
      delegatedBy: principal.pub,
      scope: ["code"],
      maxDepth: 2,
      currentDepth: 0,
      signerPriv: principal.priv,
    });
    const child = mintDelegation({
      delegatedTo: agentB.pub,
      delegatedBy: stranger.pub, // does not match root.delegatedTo
      scope: ["code"],
      maxDepth: 2,
      currentDepth: 1,
      signerPriv: stranger.priv,
    });
    const receipt = mintReceipt({
      agentId: "agent-b",
      delegationId: child["delegationId"] as string,
      action: { type: "t", target: "x", scope_used: "code" },
      delegationChain: [principal.pub, stranger.pub, agentB.pub],
      signerPriv: agentB.priv,
    });
    const v = await agentPassport.verify({ receipt, delegations: [root, child] }, {});
    assert.equal(v.valid, false);
    assert.ok(v.errors.some((e) => e.startsWith("AP_CHAIN_BREAK")));
  });

  it("rejects garbage input with AP_UNKNOWN_FORMAT", async () => {
    const v = await agentPassport.verify({ nope: true }, {});
    assert.equal(v.valid, false);
    assert.equal(v.receipt, null);
    assert.ok(v.errors.some((e) => e.startsWith("AP_UNKNOWN_FORMAT")));
  });
});

// ---------------------------------------------------------------------------
// normalize()
// ---------------------------------------------------------------------------

describe("normalize()", () => {
  it("maps a receipt to the shared NormalizedReceipt shape", () => {
    const { principal, agent, delegation } = basicSetup();
    const receipt = mintReceipt({
      agentId: "agent-a",
      delegationId: delegation["delegationId"] as string,
      action: { type: "api_call", target: "booking.example.com", method: "POST /x", scope_used: "book_flights", spend: { amount: 10, currency: "USD" } },
      result: { status: "success", summary: "done" },
      delegationChain: [principal.pub, agent.pub],
      signerPriv: agent.priv,
    });
    const n = agentPassport.normalize({ receipt, delegations: [delegation] });
    assert.equal(n.format, "agent-passport");
    assert.equal(n.receiptId, receipt["receipt_id"]);
    assert.equal(n.issuer, agent.pub);
    assert.equal(n.issuerKey.kty, "OKP");
    assert.equal(n.issuerKey.crv, "Ed25519");
    assert.equal(
      Buffer.from(n.issuerKey.x, "base64url").toString("hex"),
      agent.pub
    );
    assert.equal(n.agent, "agent-a");
    assert.equal(n.scope.kind, "structured");
    assert.deepEqual(n.scope.actions, ["book_flights"]);
    assert.deepEqual(n.scope.resources, ["booking.example.com"]);
    assert.equal(n.scope.constraints["actionType"], "api_call");
    assert.equal(n.notAfter, delegation["expiresAt"]);
    assert.equal(n.instructionsHash, null);
    assert.equal(n.parentId, delegation["delegationId"]);
    assert.equal(n.revocation.status, "unknown");
    assert.ok(n.lossy.length > 0);
    assert.deepEqual(n.raw, {
      receipt,
      delegations: [delegation],
      revocations: [],
    });
  });

  it("throws on non-receipt input", () => {
    assert.throws(() => agentPassport.normalize({ nope: 1 }), /AP_UNKNOWN_FORMAT/);
  });
});

// ---------------------------------------------------------------------------
// Dual member-name spelling (issue #216, maintainer-confirmed 2026-10-11)
//
// The reference TypeScript SDK emits camelCase; the spec documents snake_case.
// The adapter accepts either complete convention per signed object, verifies
// signatures over the original member names, and rejects mixed spellings and
// duplicate aliases.
// ---------------------------------------------------------------------------

describe("dual member-name spelling (issue #216)", () => {
  /** Mint a receipt in the SDK's camelCase spelling. */
  function mintReceiptCamel(o: ReceiptOpts): Record<string, unknown> {
    const unsigned: Record<string, unknown> = {
      receiptId: o.receiptId ?? "rcpt_test_" + Math.random().toString(36).slice(2, 10),
      version: "1.1",
      timestamp: o.timestamp ?? iso(NOW - 60_000),
      agentId: o.agentId,
      delegationId: o.delegationId,
      action: o.action,
      result: o.result ?? { status: "success", summary: "ok" },
      delegationChain: o.delegationChain,
    };
    return { ...unsigned, signature: edSign(unsigned, o.signerPriv) };
  }

  /** Mint a delegation in the spec's snake_case spelling. */
  function mintDelegationSnake(o: DelegationOpts): Record<string, unknown> {
    const unsigned: Record<string, unknown> = {
      delegation_id: o.delegationId ?? "del_test_" + Math.random().toString(36).slice(2, 10),
      delegated_to: o.delegatedTo,
      delegated_by: o.delegatedBy,
      scope: o.scope,
      expires_at: o.expiresAt ?? iso(NOW + 24 * 3600_000),
      spend_limit: o.spendLimit,
      spent_amount: o.spentAmount ?? 0,
      spend_limit_unit: o.spendLimitUnit,
      max_depth: o.maxDepth,
      current_depth: o.currentDepth ?? 0,
      created_at: iso(NOW - 3600_000),
      not_before: o.notBefore,
    };
    return { ...unsigned, signature: edSign(unsigned, o.signerPriv) };
  }

  function mintRevocationCamel(
    delegationId: string,
    revokedBy: string,
    revokerPriv: string
  ): Record<string, unknown> {
    const unsigned: Record<string, unknown> = {
      revocationId: "rev_test_" + Math.random().toString(36).slice(2, 8),
      delegationId,
      revokedBy,
      revokedAt: iso(NOW - 1000),
      reason: "agent_compromised",
    };
    return { ...unsigned, signature: edSign(unsigned, revokerPriv) };
  }

  it("verifies a camelCase receipt (the SDK spelling)", async () => {
    const { principal, agent, delegation } = basicSetup();
    const receipt = mintReceiptCamel({
      agentId: "agent-a",
      delegationId: delegation["delegationId"] as string,
      action: { type: "api_call", target: "booking.example.com", scopeUsed: "book_flights" },
      delegationChain: [principal.pub, agent.pub],
      signerPriv: agent.priv,
    });
    assert.equal(agentPassport.detect(receipt), true);
    const v = await agentPassport.verify({ receipt, delegations: [delegation] });
    assert.equal(v.valid, true);
    assert.equal(v.receipt!.receiptId, receipt["receiptId"]);
    assert.deepEqual(v.receipt!.scope.actions, ["book_flights"]);
    // The observed convention is recorded.
    assert.ok(
      v.receipt!.lossy.some((l) => l.includes("receipt=camelCase")),
      "lossy should record receipt=camelCase"
    );
  });

  it("verifies a snake_case delegation", async () => {
    const principal = keypair();
    const agent = keypair();
    const delegation = mintDelegationSnake({
      delegatedTo: agent.pub,
      delegatedBy: principal.pub,
      scope: ["book_flights"],
      maxDepth: 2,
      currentDepth: 0,
      signerPriv: principal.priv,
    });
    const receipt = mintReceipt({
      agentId: "agent-a",
      delegationId: delegation["delegation_id"] as string,
      action: { type: "t", target: "x", scope_used: "book_flights" },
      delegationChain: [principal.pub, agent.pub],
      signerPriv: agent.priv,
    });
    const v = await agentPassport.verify({ receipt, delegations: [delegation] });
    assert.equal(v.valid, true);
    assert.ok(
      v.receipt!.lossy.some((l) => l.includes("delegations[0]=snake_case")),
      "lossy should record delegations[0]=snake_case"
    );
  });

  it("verifies a camelCase revocation", async () => {
    const principal = keypair();
    const agent = keypair();
    const delegation = mintDelegation({
      delegatedTo: agent.pub,
      delegatedBy: principal.pub,
      scope: ["book_flights"],
      maxDepth: 2,
      currentDepth: 0,
      signerPriv: principal.priv,
    });
    const revocation = mintRevocationCamel(
      delegation["delegationId"] as string,
      principal.pub,
      principal.priv
    );
    const receipt = mintReceipt({
      agentId: "agent-a",
      delegationId: delegation["delegationId"] as string,
      action: { type: "t", target: "x", scope_used: "book_flights" },
      delegationChain: [principal.pub, agent.pub],
      signerPriv: agent.priv,
    });
    const v = await agentPassport.verify({
      receipt,
      delegations: [delegation],
      revocations: [revocation],
    });
    assert.equal(v.valid, false);
    assert.match(v.errors[0], /AP_REVOKED/);
  });

  it("rejects mixed naming within a receipt (AP_MIXED_NAMING)", async () => {
    const receipt = {
      receipt_id: "rcpt_x",
      agentId: "agent-a", // camelCase mixed into a snake_case receipt
      delegation_id: "d",
      signature: "s",
      timestamp: iso(NOW),
      action: { type: "t", scope_used: "s" },
      result: { status: "ok", summary: "ok" },
    };
    assert.equal(agentPassport.detect(receipt), false);
    const v = await agentPassport.verify(receipt);
    assert.equal(v.valid, false);
    assert.match(v.errors[0], /AP_MIXED_NAMING/);
  });

  it("rejects duplicate aliases even when one is null (AP_DUPLICATE_ALIAS)", async () => {
    const receipt = {
      receipt_id: "rcpt_x",
      receiptId: null, // duplicate alias with a null value
      agent_id: "agent-a",
      delegation_id: "d",
      signature: "s",
      timestamp: iso(NOW),
      action: { type: "t", scope_used: "s" },
      result: { status: "ok", summary: "ok" },
    };
    const v = await agentPassport.verify(receipt);
    assert.equal(v.valid, false);
    assert.match(v.errors[0], /AP_DUPLICATE_ALIAS/);
  });

  it("rejects mixed naming within a delegation (AP_MIXED_NAMING)", async () => {
    const principal = keypair();
    const agent = keypair();
    const delegation = {
      delegationId: "del_x",
      delegated_to: agent.pub, // snake_case mixed into a camelCase delegation
      delegatedBy: principal.pub,
      scope: ["s"],
      expiresAt: iso(NOW + 3600_000),
      signature: "s",
    };
    const receipt = mintReceipt({
      agentId: "agent-a",
      delegationId: "del_x",
      action: { type: "t", target: "x", scope_used: "s" },
      delegationChain: [principal.pub, agent.pub],
      signerPriv: agent.priv,
    });
    const v = await agentPassport.verify({ receipt, delegations: [delegation] });
    assert.equal(v.valid, false);
    assert.match(v.errors[0], /AP_MIXED_NAMING/);
  });

  it("verifies the signature over the original member names, not the normalized ones", async () => {
    // Sign the snake_case bytes but present a camelCase receipt. If the
    // verifier normalized before verifying, this would pass; it must fail
    // with AP_BAD_SIGNATURE because the preimage carries the received names.
    const { principal, agent, delegation } = basicSetup();
    const unsignedCamel: Record<string, unknown> = {
      receiptId: "rcpt_respelling",
      version: "1.1",
      timestamp: iso(NOW - 60_000),
      agentId: "agent-a",
      delegationId: delegation["delegationId"] as string,
      action: { type: "t", target: "x", scopeUsed: "book_flights" },
      result: { status: "success", summary: "ok" },
      delegationChain: [principal.pub, agent.pub],
    };
    const unsignedSnake: Record<string, unknown> = {
      receipt_id: unsignedCamel["receiptId"],
      version: "1.1",
      timestamp: unsignedCamel["timestamp"],
      agent_id: unsignedCamel["agentId"],
      delegation_id: unsignedCamel["delegationId"],
      action: { type: "t", target: "x", scope_used: "book_flights" },
      result: { status: "success", summary: "ok" },
      delegation_chain: unsignedCamel["delegationChain"],
    };
    const receipt = { ...unsignedCamel, signature: edSign(unsignedSnake, agent.priv) };
    const v = await agentPassport.verify({ receipt, delegations: [delegation] });
    assert.equal(v.valid, false);
    assert.match(v.errors[0], /AP_BAD_SIGNATURE/);
  });

  it("still verifies a fully snake_case document end to end", async () => {
    const principal = keypair();
    const agent = keypair();
    const delegation = mintDelegationSnake({
      delegatedTo: agent.pub,
      delegatedBy: principal.pub,
      scope: ["book_flights"],
      maxDepth: 2,
      currentDepth: 0,
      signerPriv: principal.priv,
    });
    const receipt = mintReceipt({
      agentId: "agent-a",
      delegationId: delegation["delegation_id"] as string,
      action: { type: "t", target: "x", scope_used: "book_flights" },
      delegationChain: [principal.pub, agent.pub],
      signerPriv: agent.priv,
    });
    const v = await agentPassport.verify({ receipt, delegations: [delegation] });
    assert.equal(v.valid, true);
    assert.ok(
      v.receipt!.lossy.some((l) => l.includes("receipt=snake_case")),
      "lossy should record receipt=snake_case"
    );
  });
});
