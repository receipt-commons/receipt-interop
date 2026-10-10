/**
 * Tests for the UCAN 0.9-style JWT format verifier.
 *
 * All fixtures are minted in-test with tweetnacl (real Ed25519 signatures):
 *   root keypair -> delegate keypair -> sub-delegate keypair
 *
 * Run: npx tsx --test test/ucan.test.ts   (from the package dir)
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import nacl from "tweetnacl";

import ucan from "../src/formats/ucan.js";
import type { VerifyOptions } from "../src/model.js";

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Encode(bytes: Uint8Array): string {
  let num = 0n;
  for (const b of bytes) num = (num << 8n) | BigInt(b);
  let out = "";
  while (num > 0n) {
    out = B58[Number(num % 58n)] + out;
    num = num / 58n;
  }
  let zeros = 0;
  for (const b of bytes) {
    if (b === 0) zeros++;
    else break;
  }
  return "1".repeat(zeros) + out;
}

function didKey(pubkey: Uint8Array): string {
  // did:key:z + base58btc(multicodec 0xed01 || 32-byte ed25519 pubkey)
  return "did:key:z" + base58Encode(new Uint8Array([0xed, 0x01, ...pubkey]));
}

function b64u(bytes: Uint8Array | string): string {
  return Buffer.from(bytes).toString("base64url");
}

interface MintParams {
  iss: string;
  aud: string;
  exp?: number;
  nbf?: number;
  att?: Array<{ with: string; can: string }>;
  prf?: string[];
  alg?: string;
}

function mint(secretKey: Uint8Array, params: MintParams): string {
  const now = Math.floor(Date.now() / 1000);
  const header = {
    alg: params.alg ?? "EdDSA",
    typ: "JWT",
    ucv: "0.9.0",
  };
  const payload = {
    iss: params.iss,
    aud: params.aud,
    exp: params.exp ?? now + 3600,
    ...(params.nbf !== undefined ? { nbf: params.nbf } : {}),
    att: params.att ?? [],
    prf: params.prf ?? [],
  };
  const h = b64u(JSON.stringify(header));
  const p = b64u(JSON.stringify(payload));
  const sig = nacl.sign.detached(new TextEncoder().encode(`${h}.${p}`), secretKey);
  return `${h}.${p}.${b64u(sig)}`;
}

function makeChain() {
  const root = nacl.sign.keyPair();
  const delegate = nacl.sign.keyPair();
  const sub = nacl.sign.keyPair();
  const rootDid = didKey(root.publicKey);
  const delegateDid = didKey(delegate.publicKey);
  const subDid = didKey(sub.publicKey);
  const now = Math.floor(Date.now() / 1000);

  const rootToken = mint(root.secretKey, {
    iss: rootDid,
    aud: delegateDid,
    exp: now + 7200,
    att: [{ with: "db://app/users", can: "db/WRITE" }],
  });
  const delegateToken = mint(delegate.secretKey, {
    iss: delegateDid,
    aud: subDid,
    exp: now + 3600,
    att: [{ with: "db://app/users", can: "db/WRITE" }],
    prf: [rootToken],
  });
  return { root, delegate, sub, rootDid, delegateDid, subDid, rootToken, delegateToken, now };
}

const opts: VerifyOptions = {};

// ---------------------------------------------------------------------------
// detect()
// ---------------------------------------------------------------------------

describe("ucan.detect", () => {
  it("detects a real UCAN JWT", () => {
    const { delegateToken } = makeChain();
    assert.equal(ucan.detect(delegateToken), true);
  });

  it("rejects non-strings and garbage", () => {
    assert.equal(ucan.detect(null), false);
    assert.equal(ucan.detect(42), false);
    assert.equal(ucan.detect(""), false);
    assert.equal(ucan.detect("not.a.jwt.at.all"), false);
    assert.equal(ucan.detect("a.b.c"), false);
  });

  it("rejects a JWT that is not a UCAN (no ucv, no att/prf)", () => {
    const h = b64u(JSON.stringify({ alg: "HS256", typ: "JWT" }));
    const p = b64u(JSON.stringify({ sub: "1234", name: "x" }));
    assert.equal(ucan.detect(`${h}.${p}.sig`), false);
  });
});

// ---------------------------------------------------------------------------
// verify(): happy path
// ---------------------------------------------------------------------------

describe("ucan.verify — valid chain", () => {
  it("verifies a valid 2-chain (root -> delegate)", async () => {
    const { delegateToken, delegateDid, subDid } = makeChain();
    const v = await ucan.verify(delegateToken, opts);
    assert.equal(v.valid, true, JSON.stringify(v.errors));
    assert.equal(v.format, "ucan");
    assert.deepEqual(v.errors, []);
    assert.ok(v.receipt, "receipt should be populated on success");
    assert.equal(v.receipt.issuer, delegateDid);
    assert.equal(v.receipt.agent, subDid);
  });

  it("normalizes scope/actions/resources from att", async () => {
    const { delegateToken } = makeChain();
    const v = await ucan.verify(delegateToken, opts);
    const scope = v.receipt!.scope;
    assert.equal(scope.kind, "capability");
    assert.deepEqual(scope.actions, ["db/WRITE"]);
    assert.deepEqual(scope.resources, ["db://app/users"]);
    assert.equal(scope.enforced, true);
    assert.equal(v.receipt!.instructionsHash, null);
    assert.deepEqual(v.receipt!.boundaries, []);
  });

  it("sets issuerKey from the did:key pubkey", async () => {
    const { delegateToken, delegate } = makeChain();
    const v = await ucan.verify(delegateToken, opts);
    assert.deepEqual(v.receipt!.issuerKey, {
      kty: "OKP",
      crv: "Ed25519",
      x: b64u(delegate.publicKey),
    });
  });

  it("sets parentId to sha256 of the first proof", async () => {
    const { delegateToken, rootToken } = makeChain();
    const v = await ucan.verify(delegateToken, opts);
    const expected = createHash("sha256").update(rootToken, "utf8").digest("hex");
    assert.equal(v.receipt!.parentId, expected);
  });

  it("root token has parentId null and receiptId = sha256 of compact JWT", async () => {
    const { rootToken } = makeChain();
    const v = await ucan.verify(rootToken, opts);
    assert.equal(v.valid, true, JSON.stringify(v.errors));
    assert.equal(v.receipt!.parentId, null);
    const expected = createHash("sha256").update(rootToken, "utf8").digest("hex");
    assert.equal(v.receipt!.receiptId, expected);
  });

  it("marks revocation status unknown with the lossy note", async () => {
    const { delegateToken } = makeChain();
    const v = await ucan.verify(delegateToken, opts);
    assert.deepEqual(v.receipt!.revocation, {
      required: false,
      pointer: null,
      status: "unknown",
    });
    assert.ok(
      v.receipt!.lossy.includes("UCAN has no revocation registry; status always unknown")
    );
    assert.ok(v.receipt!.lossy.includes("fct (facts) not mapped"));
    assert.ok(v.receipt!.lossy.includes("no advisory text scope"));
  });

  it("maps notBefore/notAfter from nbf/exp", async () => {
    const { root, rootDid, delegateDid, now } = makeChain();
    const t = mint(root.secretKey, {
      iss: rootDid,
      aud: delegateDid,
      exp: now + 3600,
      nbf: now - 60,
      att: [],
    });
    const v = await ucan.verify(t, opts);
    assert.equal(v.valid, true, JSON.stringify(v.errors));
    assert.equal(v.receipt!.notBefore, new Date((now - 60) * 1000).toISOString());
    assert.equal(v.receipt!.notAfter, new Date((now + 3600) * 1000).toISOString());
  });

  it("uses epoch notBefore + lossy note when nbf is absent", async () => {
    const { rootToken } = makeChain();
    const v = await ucan.verify(rootToken, opts);
    assert.equal(v.receipt!.notBefore, "1970-01-01T00:00:00.000Z");
    assert.ok(v.receipt!.lossy.includes("no nbf claim"));
  });
});

// ---------------------------------------------------------------------------
// verify(): failure cases
// ---------------------------------------------------------------------------

describe("ucan.verify — failures", () => {
  it("rejects a tampered payload (BAD_SIGNATURE)", async () => {
    const { delegateToken } = makeChain();
    const [h, p, s] = delegateToken.split(".");
    // Tamper that keeps the JSON parseable: change a claim value so the
    // bytes no longer match the Ed25519 signature.
    const payload = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
    payload.att[0].can = "db/WRITF";
    const tampered = b64u(JSON.stringify(payload));
    const v = await ucan.verify(`${h}.${tampered}.${s}`, opts);
    assert.equal(v.valid, false);
    assert.ok(v.errors.some((e) => e.startsWith("BAD_SIGNATURE")), JSON.stringify(v.errors));
    assert.equal(v.receipt, null);
  });

  it("rejects an expired token (EXPIRED)", async () => {
    const { root, rootDid, delegateDid, now } = makeChain();
    const t = mint(root.secretKey, {
      iss: rootDid,
      aud: delegateDid,
      exp: now - 10,
      att: [],
    });
    const v = await ucan.verify(t, opts);
    assert.equal(v.valid, false);
    assert.ok(v.errors.some((e) => e.startsWith("EXPIRED")), JSON.stringify(v.errors));
  });

  it("rejects a not-yet-valid token (NOT_YET_VALID)", async () => {
    const { root, rootDid, delegateDid, now } = makeChain();
    const t = mint(root.secretKey, {
      iss: rootDid,
      aud: delegateDid,
      exp: now + 7200,
      nbf: now + 600,
      att: [],
    });
    const v = await ucan.verify(t, opts);
    assert.equal(v.valid, false);
    assert.ok(v.errors.some((e) => e.startsWith("NOT_YET_VALID")), JSON.stringify(v.errors));
  });

  it("supports rights amplification across multiple proofs (union of att)", async () => {
    const { root, delegate, delegateDid, subDid, now } = makeChain();
    const rootDid = didKey(root.publicKey);
    // Two separate grants to the delegate: one READ, one WRITE.
    const readProof = mint(root.secretKey, {
      iss: rootDid,
      aud: delegateDid,
      exp: now + 7200,
      att: [{ with: "db://app/users", can: "db/READ" }],
    });
    const writeProof = mint(root.secretKey, {
      iss: rootDid,
      aud: delegateDid,
      exp: now + 7200,
      att: [{ with: "db://app/users", can: "db/WRITE" }],
    });
    // Delegate combines both grants in one token.
    const combined = mint(delegate.secretKey, {
      iss: delegateDid,
      aud: subDid,
      exp: now + 3600,
      att: [
        { with: "db://app/users", can: "db/READ" },
        { with: "db://app/users", can: "db/WRITE" },
      ],
      prf: [readProof, writeProof],
    });
    const v = await ucan.verify(combined, opts);
    assert.equal(v.valid, true, JSON.stringify(v.errors));
  });

  it("still catches attenuation violations under multi-proof (union) semantics", async () => {
    const { delegate, rootToken, rootDid, delegateDid, subDid, now } = makeChain();
    const bad = mint(delegate.secretKey, {
      iss: delegateDid,
      aud: subDid,
      exp: now + 3600,
      // root granted db/WRITE; delegate tries to widen to db/DELETE
      att: [{ with: "db://app/users", can: "db/DELETE" }],
      prf: [rootToken],
    });
    const v = await ucan.verify(bad, opts);
    assert.equal(v.valid, false);
    assert.ok(
      v.errors.some((e) => e.startsWith("ATTENUATION_VIOLATION")),
      JSON.stringify(v.errors)
    );
    void rootDid;
  });

  it("rejects audience mismatch: proof aud != child iss (AUDIENCE_MISMATCH)", async () => {
    const { root, delegate, delegateDid, subDid, now } = makeChain();
    const strangerDid = didKey(nacl.sign.keyPair().publicKey);
    // root issues to a stranger, but delegate tries to use it as its proof
    const wrongProof = mint(root.secretKey, {
      iss: didKey(root.publicKey),
      aud: strangerDid,
      exp: now + 7200,
      att: [{ with: "db://app/users", can: "db/WRITE" }],
    });
    const t = mint(delegate.secretKey, {
      iss: delegateDid,
      aud: subDid,
      exp: now + 3600,
      att: [{ with: "db://app/users", can: "db/WRITE" }],
      prf: [wrongProof],
    });
    const v = await ucan.verify(t, opts);
    assert.equal(v.valid, false);
    assert.ok(
      v.errors.some((e) => e.startsWith("AUDIENCE_MISMATCH")),
      JSON.stringify(v.errors)
    );
  });

  it("rejects a non-EdDSA alg", async () => {
    const { root, rootDid, delegateDid } = makeChain();
    const t = mint(root.secretKey, {
      iss: rootDid,
      aud: delegateDid,
      alg: "RS256",
      att: [],
    });
    const v = await ucan.verify(t, opts);
    assert.equal(v.valid, false);
  });

  it("rejects a non-did:key issuer (UNSUPPORTED_DID_METHOD)", async () => {
    const { root, delegateDid, now } = makeChain();
    const t = mint(root.secretKey, {
      iss: "did:web:example.com",
      aud: delegateDid,
      exp: now + 3600,
      att: [],
    });
    const v = await ucan.verify(t, opts);
    assert.equal(v.valid, false);
    assert.ok(
      v.errors.some((e) => e.startsWith("UNSUPPORTED_DID_METHOD")),
      JSON.stringify(v.errors)
    );
  });

  it("rejects garbage input (UNKNOWN_FORMAT)", async () => {
    const v = await ucan.verify("definitely-not-a-ucan", opts);
    assert.equal(v.valid, false);
    assert.ok(v.errors.some((e) => e.startsWith("UNKNOWN_FORMAT")));
  });

  it("rejects when depth exceeds maxChainDepth (DEPTH_EXCEEDED)", async () => {
    const { delegateToken } = makeChain();
    const v = await ucan.verify(delegateToken, { maxChainDepth: 1 });
    assert.equal(v.valid, false);
    assert.ok(
      v.errors.some((e) => e.startsWith("DEPTH_EXCEEDED")),
      JSON.stringify(v.errors)
    );
  });

  it("rejects an untrusted issuer when trustedIssuers is set", async () => {
    const { delegateToken, delegateDid } = makeChain();
    const v = await ucan.verify(delegateToken, {
      trustedIssuers: ["did:key:zSomebodyElse"],
    });
    assert.equal(v.valid, false);
    assert.ok(
      v.errors.some((e) => e.startsWith("UNTRUSTED_ISSUER")),
      JSON.stringify(v.errors)
    );
    const ok = await ucan.verify(delegateToken, { trustedIssuers: [delegateDid] });
    assert.equal(ok.valid, true, JSON.stringify(ok.errors));
  });

  it("checks time against opts.at instead of now", async () => {
    const { root, rootDid, delegateDid, now } = makeChain();
    const t = mint(root.secretKey, {
      iss: rootDid,
      aud: delegateDid,
      exp: now + 3600,
      att: [],
    });
    const future = new Date((now + 7200) * 1000);
    const v = await ucan.verify(t, { at: future });
    assert.equal(v.valid, false);
    assert.ok(v.errors.some((e) => e.startsWith("EXPIRED")));
  });
});

// ---------------------------------------------------------------------------
// capabilityCovers (attenuation unit checks)
// ---------------------------------------------------------------------------

describe("ucan.capabilityCovers", async () => {
  const { capabilityCovers } = await import("../src/formats/ucan.js");
  it("equal capabilities cover", () => {
    assert.equal(
      capabilityCovers(
        { with: "db://app/users", can: "db/WRITE" },
        { with: "db://app/users", can: "db/WRITE" }
      ),
      true
    );
  });
  it("superuser can covers narrower can", () => {
    assert.equal(
      capabilityCovers(
        { with: "db://app/users", can: "*" },
        { with: "db://app/users", can: "db/WRITE" }
      ),
      true
    );
  });
  it("different ability does not cover", () => {
    assert.equal(
      capabilityCovers(
        { with: "db://app/users", can: "db/WRITE" },
        { with: "db://app/users", can: "db/DELETE" }
      ),
      false
    );
  });
  it("different resource does not cover", () => {
    assert.equal(
      capabilityCovers(
        { with: "db://app/users", can: "db/WRITE" },
        { with: "db://app/orders", can: "db/WRITE" }
      ),
      false
    );
  });
});

// ---------------------------------------------------------------------------
// verifier identity
// ---------------------------------------------------------------------------

describe("ucan verifier shape", () => {
  it("exports id 'ucan' with detect/verify/normalize", () => {
    assert.equal(ucan.id, "ucan");
    assert.equal(typeof ucan.detect, "function");
    assert.equal(typeof ucan.verify, "function");
    assert.equal(typeof ucan.normalize, "function");
  });
});
