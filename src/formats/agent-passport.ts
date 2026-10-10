/**
 * agent-passport Action Receipts v1.1 verifier.
 *
 * Format: the Action Receipt defined in docs/SPEC-v1.1.md of
 * agent-passport-system/agent-passport-system (cloned 2026-10-09, commit
 * c31d94aad86713ae9b2e4cbc811deeab4b5d91ed), implemented in
 * src/core/delegation.ts (createReceipt / verifyReceipt) and typed in
 * src/types/passport.ts (ActionReceipt, Delegation).
 *
 * Signing (byte-exact, per their code):
 *   signature input = UTF-8 bytes of APS canonical JSON (docs/CANONICAL-SPEC.md,
 *   src/core/canonical.ts) of the receipt WITH the `signature` field removed.
 *   Canonical JSON: object keys sorted alphabetically (UTF-16 code-unit order),
 *   null/undefined object values OMITTED, array nulls preserved, no whitespace.
 *   Algorithm: Ed25519 (RFC 8032). Keys are raw 32-byte Ed25519 keys encoded as
 *   lowercase hex (64 chars). Signatures are 64-byte Ed25519 signatures encoded
 *   as lowercase hex (128 chars). Their reference uses node:crypto; this
 *   adapter uses tweetnacl (same RFC 8032 math over identical input bytes).
 *
 * Scope narrowing (per-hop rule, quoted verbatim from the scopeCovers() comment
 * in src/core/delegation.ts):
 *   - Exact match: 'code' covers 'code'
 *   - Hierarchical: 'code' covers 'code:deploy' (parent covers child)
 *   - Universal wildcard: '*' covers everything
 *   - Prefix wildcard: 'commerce:*' covers 'commerce' and 'commerce:checkout'
 *   - NO reverse: 'code:deploy' does NOT cover 'code' (child does not satisfy parent)
 * Every scope string in a child delegation must be covered by at least one
 * scope string in its parent (src/core/delegation.ts subDelegate()).
 *
 * max_depth (their rule): each delegation carries maxDepth / currentDepth
 * (docs/SPEC-v1.1.md section 3, src/core/delegation.ts createDelegation).
 * Sub-delegating sets newDepth = parent.currentDepth + 1 and MUST be refused
 * when newDepth > parent.maxDepth; children inherit the parent's maxDepth
 * ceiling and cannot increase it. If maxDepth is omitted, SPEC-v1.1 section
 * 3.4 says implementations MUST default to max_depth: 1. (Note: section 4.1
 * of the same doc contradicts this and says "unlimited if absent"; the
 * reference code uses `maxDepth ?? 1`, and this adapter follows the code.)
 *
 * Revocation (offline boundary): revocation checking in their system needs
 * either their gateway DelegationStore (moved out of the pure SDK — the pure
 * functions are deprecation stubs that throw) or a network fetch (inline
 * revocation list URL / challenge-response, docs/SPEC-v1.1.md section 2.4, or
 * the optional Delegation.revocationCheckUrl in src/types/passport.ts).
 * Offline, this adapter can only honor revocation evidence carried in the
 * input: signed RevocationRecords (docs/SPEC-v1.1.md section 2.2 /
 * docs/CASCADE-REVOCATION-SPEC.md section 2.2) supplied alongside the chain,
 * or a baked-in `revoked: true` marker on a delegation record (the
 * CASCADE-REVOCATION-SPEC section 2.1 Delegation schema carries it; the
 * shipped Delegation type in src/types/passport.ts does not). When no such
 * evidence is present, revocation.status is 'unknown' with warning
 * REVOCATION_UNCHECKED_OFFLINE. Their own default revocation policy is
 * fail_open (src/core/delegation.ts RevocationCheckOptions), so this matches
 * the protocol's shipped posture.
 *
 * The v2 `aps:action:v1` accountability receipts (src/v2/accountability) are a
 * DIFFERENT artifact and are out of scope for this format id.
 *
 * Shared types are defined by the core track in src/model.ts and imported
 * here; the exported object matches the FormatVerifier shape.
 */

import nacl from "tweetnacl";
import { createHash } from "node:crypto";
import type {
  NormalizedReceipt,
  VerifyOptions,
  Verdict,
} from "../model.js";

// ---------------------------------------------------------------------------
// Error codes (AP_ prefix) and warnings
// ---------------------------------------------------------------------------

export const AGENT_PASSPORT_ERRORS = {
  UNKNOWN_FORMAT: "AP_UNKNOWN_FORMAT",
  BAD_SIGNATURE: "AP_BAD_SIGNATURE",
  UNSUPPORTED_VERSION: "AP_UNSUPPORTED_VERSION",
  UNKNOWN_SIGNER_KEY: "AP_UNKNOWN_SIGNER_KEY",
  UNTRUSTED_ISSUER: "AP_UNTRUSTED_ISSUER", // adapter extension
  EXPIRED: "AP_EXPIRED",
  NOT_YET_VALID: "AP_NOT_YET_VALID",
  BAD_TIMESTAMP: "AP_BAD_TIMESTAMP",
  DEPTH_EXCEEDED: "AP_DEPTH_EXCEEDED",
  CHAIN_BREAK: "AP_CHAIN_BREAK",
  NARROWING_VIOLATION: "AP_NARROWING_VIOLATION",
  SCOPE_VIOLATION: "AP_SCOPE_VIOLATION",
  OVER_BUDGET: "AP_OVER_BUDGET",
  REVOKED: "AP_REVOKED",
} as const;

export const AGENT_PASSPORT_WARNINGS = {
  REVOCATION_UNCHECKED_OFFLINE: "REVOCATION_UNCHECKED_OFFLINE",
  CHAIN_NOT_SUPPLIED: "AP_CHAIN_NOT_SUPPLIED",
  DELEGATION_NOW_EXPIRED: "AP_DELEGATION_NOW_EXPIRED",
  PREVIOUS_LINK_UNCHECKED: "AP_PREVIOUS_LINK_UNCHECKED",
  BAD_REVOCATION_SIGNATURE: "AP_BAD_REVOCATION_SIGNATURE",
} as const;

const FORMAT_ID = "agent-passport" as const;

// ---------------------------------------------------------------------------
// APS canonical JSON (port of src/core/canonical.ts, per docs/CANONICAL-SPEC.md)
// ---------------------------------------------------------------------------

const HEX64 = /^[0-9a-fA-F]{64}$/;
const HEX128 = /^[0-9a-fA-F]{128}$/;

/** Reject values CANONICAL-SPEC.md forbids in signed objects. */
function assertCanonicalSafe(value: unknown): void {
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("non-finite number is forbidden in signed objects");
    }
    if (Number.isInteger(value) && Math.abs(value) > Number.MAX_SAFE_INTEGER) {
      throw new Error("integer outside IEEE 754 safe range is forbidden");
    }
  } else if (typeof value === "string") {
    // Unpaired surrogates are forbidden; JSON.stringify would emit lone
    // surrogates, which are not valid Unicode and serialize inconsistently.
    for (let i = 0; i < value.length; i++) {
      const c = value.charCodeAt(i);
      if (c >= 0xd800 && c <= 0xdbff) {
        const d = value.charCodeAt(i + 1);
        if (!(d >= 0xdc00 && d <= 0xdfff)) {
          throw new Error("unpaired surrogate is forbidden in signed objects");
        }
        i++;
      } else if (c >= 0xdc00 && c <= 0xdfff) {
        throw new Error("unpaired surrogate is forbidden in signed objects");
      }
    }
  }
}

/**
 * Deterministic serialization used for ALL APS signing operations.
 * Byte-identical to canonicalize() in src/core/canonical.ts for every value
 * it accepts (see conformance vectors in specs/test-vectors-canonicalization.json).
 * Exported so tests can validate it against the published vectors.
 */
export function apsCanonicalize(value: unknown, ancestors?: WeakSet<object>): string {
  if (value === null || value === undefined) return "null";
  if (value instanceof Date) return JSON.stringify(value);
  if (typeof value !== "object") {
    assertCanonicalSafe(value);
    return JSON.stringify(value);
  }
  const seen = ancestors ?? new WeakSet<object>();
  if (seen.has(value)) throw new Error("circular reference in canonicalize()");
  seen.add(value);
  let out: string;
  if (Array.isArray(value)) {
    out = "[" + value.map((item) => apsCanonicalize(item, seen)).join(",") + "]";
  } else {
    const rec = value as Record<string, unknown>;
    const pairs: string[] = [];
    for (const key of Object.keys(rec).sort()) {
      const v = rec[key];
      if (v === null || v === undefined) continue; // null asymmetry rule
      pairs.push(JSON.stringify(key) + ":" + apsCanonicalize(v, seen));
    }
    out = "{" + pairs.join(",") + "}";
  }
  seen.delete(value);
  return out;
}

function sha256hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

function b64uEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    out[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Scope resolution — SINGLE SOURCE OF TRUTH port of scopeCovers /
// scopeAuthorizes in src/core/delegation.ts (verbatim rule).
// ---------------------------------------------------------------------------

function scopeCovers(granted: string, required: string): boolean {
  if (granted === required) return true;
  if (granted === "*") return true;
  if (required.startsWith(granted + ":")) return true;
  if (granted.endsWith(":*")) {
    const prefix = granted.slice(0, -2);
    if (required === prefix || required.startsWith(prefix + ":")) return true;
  }
  return false;
}

function scopeAuthorizes(grantedScopes: string[], required: string): boolean {
  return grantedScopes.some((g) => scopeCovers(g, required));
}

// ---------------------------------------------------------------------------
// Input shapes (docs/SPEC-v1.1.md section 1.1 + src/types/passport.ts)
// ---------------------------------------------------------------------------

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export interface AgentPassportAction {
  type: string;
  target: string;
  method?: string;
  scope_used: string;
  spend?: { amount: number; currency: string };
  [k: string]: unknown;
}

export interface AgentPassportReceipt {
  receipt_id: string;
  version: string;
  timestamp: string;
  agent_id: string;
  delegation_id: string;
  action: AgentPassportAction;
  result: { status: string; summary: string; [k: string]: unknown };
  delegation_chain: string[];
  signature: string;
  previousReceiptHash?: string;
  [k: string]: unknown;
}

export interface AgentPassportDelegation {
  delegationId: string;
  delegatedTo: string;
  delegatedBy: string;
  scope: string[];
  scopeInterpretation?: string;
  expiresAt: string;
  notBefore?: string;
  spendLimit?: number;
  spentAmount?: number;
  spendLimitUnit?: string;
  maxDepth?: number;
  currentDepth?: number;
  createdAt?: string;
  revocationCheckUrl?: string;
  revoked?: boolean; // CASCADE-REVOCATION-SPEC section 2.1 schema carries this
  signature: string;
  [k: string]: unknown;
}

export interface AgentPassportRevocation {
  revocation_id?: string;
  delegation_id?: string;
  delegationId?: string;
  revoked_by?: string;
  revokedBy?: string;
  revoked_at?: string;
  revokedAt?: string;
  reason?: string;
  signature: string;
  [k: string]: unknown;
}

interface ParsedInput {
  receipt: AgentPassportReceipt;
  delegations: AgentPassportDelegation[];
  revocations: AgentPassportRevocation[];
  envelope: boolean;
}

class FormatError extends Error {}

/** Parse the input into a receipt plus optional chain envelope. Throws FormatError. */
function parseInput(input: unknown): ParsedInput {
  let obj = input;
  if (typeof obj === "string") {
    try {
      obj = JSON.parse(obj);
    } catch {
      throw new FormatError(
        `${AGENT_PASSPORT_ERRORS.UNKNOWN_FORMAT}: input string is not JSON`
      );
    }
  }
  if (!isRecord(obj)) {
    throw new FormatError(
      `${AGENT_PASSPORT_ERRORS.UNKNOWN_FORMAT}: input must be a receipt object`
    );
  }

  let envelope = false;
  let receiptObj: unknown = obj;
  let delegations: unknown = undefined;
  let revocations: unknown = undefined;
  if (isRecord(obj["receipt"])) {
    // Chain envelope: { receipt, delegations?, revocations? }
    envelope = true;
    receiptObj = obj["receipt"];
    delegations = obj["delegations"];
    revocations = obj["revocations"];
  }

  if (!isRecord(receiptObj)) {
    throw new FormatError(
      `${AGENT_PASSPORT_ERRORS.UNKNOWN_FORMAT}: receipt must be a JSON object`
    );
  }
  const r = receiptObj as Record<string, unknown>;
  const action = r["action"];
  for (const [field, check] of [
    ["receipt_id", (v: unknown) => typeof v === "string"],
    ["agent_id", (v: unknown) => typeof v === "string"],
    ["delegation_id", (v: unknown) => typeof v === "string"],
    ["signature", (v: unknown) => typeof v === "string"],
    ["timestamp", (v: unknown) => typeof v === "string"],
  ] as const) {
    if (!check(r[field])) {
      throw new FormatError(
        `${AGENT_PASSPORT_ERRORS.UNKNOWN_FORMAT}: receipt.${field} must be a string`
      );
    }
  }
  if (!isRecord(action) || typeof action["scope_used"] !== "string") {
    throw new FormatError(
      `${AGENT_PASSPORT_ERRORS.UNKNOWN_FORMAT}: receipt.action.scope_used must be a string`
    );
  }
  if (!isRecord(r["result"])) {
    throw new FormatError(
      `${AGENT_PASSPORT_ERRORS.UNKNOWN_FORMAT}: receipt.result must be an object`
    );
  }

  const parsedDelegations: AgentPassportDelegation[] = [];
  if (delegations !== undefined) {
    if (!Array.isArray(delegations)) {
      throw new FormatError(
        `${AGENT_PASSPORT_ERRORS.UNKNOWN_FORMAT}: delegations must be an array`
      );
    }
    for (const d of delegations) parsedDelegations.push(parseDelegation(d));
  }
  const parsedRevocations: AgentPassportRevocation[] = [];
  if (revocations !== undefined) {
    if (!Array.isArray(revocations)) {
      throw new FormatError(
        `${AGENT_PASSPORT_ERRORS.UNKNOWN_FORMAT}: revocations must be an array`
      );
    }
    for (const rv of revocations) {
      if (!isRecord(rv) || typeof rv["signature"] !== "string") {
        throw new FormatError(
          `${AGENT_PASSPORT_ERRORS.UNKNOWN_FORMAT}: revocation records must be objects with a signature`
        );
      }
      parsedRevocations.push(rv as AgentPassportRevocation);
    }
  }

  return {
    receipt: r as unknown as AgentPassportReceipt,
    delegations: parsedDelegations,
    revocations: parsedRevocations,
    envelope,
  };
}

function parseDelegation(d: unknown): AgentPassportDelegation {
  if (!isRecord(d)) {
    throw new FormatError(
      `${AGENT_PASSPORT_ERRORS.UNKNOWN_FORMAT}: delegation must be an object`
    );
  }
  for (const [field, check] of [
    ["delegationId", (v: unknown) => typeof v === "string"],
    ["delegatedTo", (v: unknown) => typeof v === "string"],
    ["delegatedBy", (v: unknown) => typeof v === "string"],
    ["expiresAt", (v: unknown) => typeof v === "string"],
    ["signature", (v: unknown) => typeof v === "string"],
  ] as const) {
    if (!check(d[field])) {
      throw new FormatError(
        `${AGENT_PASSPORT_ERRORS.UNKNOWN_FORMAT}: delegation.${field} must be a string`
      );
    }
  }
  if (!Array.isArray(d["scope"]) || !d["scope"].every((s) => typeof s === "string")) {
    throw new FormatError(
      `${AGENT_PASSPORT_ERRORS.UNKNOWN_FORMAT}: delegation.scope must be a string array`
    );
  }
  return d as unknown as AgentPassportDelegation;
}

/** Verify an Ed25519 hex signature over the APS canonical form of an artifact. */
function verifyApsSignature(
  artifact: Record<string, unknown>,
  signatureHex: string,
  pubkeyHex: string
): boolean {
  if (!HEX64.test(pubkeyHex) || !HEX128.test(signatureHex)) return false;
  const { signature: _sig, ...unsigned } = artifact;
  let canonical: string;
  try {
    canonical = apsCanonicalize(unsigned);
  } catch {
    return false;
  }
  try {
    return nacl.sign.detached.verify(
      new TextEncoder().encode(canonical),
      hexToBytes(signatureHex.toLowerCase()),
      hexToBytes(pubkeyHex.toLowerCase())
    );
  } catch {
    return false;
  }
}

function parseInstant(label: string, value: string): number {
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) {
    throw new FormatError(
      `${AGENT_PASSPORT_ERRORS.BAD_TIMESTAMP}: ${label} is not a readable instant: ${JSON.stringify(value)}`
    );
  }
  return ms;
}

/** Resolve the receipt signer's public key (hex). Throws FormatError. */
function resolveExecutorKey(
  receipt: AgentPassportReceipt,
  delegations: AgentPassportDelegation[]
): string {
  const chain = receipt.delegation_chain;
  if (Array.isArray(chain) && chain.length > 0) {
    const last = chain[chain.length - 1];
    if (typeof last === "string" && HEX64.test(last)) {
      return last.toLowerCase();
    }
  }
  if (delegations.length > 0) {
    const leafKey = delegations[delegations.length - 1].delegatedTo;
    if (HEX64.test(leafKey)) return leafKey.toLowerCase();
  }
  throw new FormatError(
    `${AGENT_PASSPORT_ERRORS.UNKNOWN_SIGNER_KEY}: no 64-hex Ed25519 public key found for the executing agent (checked delegation_chain tail and leaf delegation delegatedTo)`
  );
}

// ---------------------------------------------------------------------------
// detect / verify / normalize
// ---------------------------------------------------------------------------

/** True for an agent-passport v1.1 Action Receipt (bare or in a chain envelope). */
export function detect(input: unknown): boolean {
  try {
    parseInput(input);
    return true;
  } catch {
    return false;
  }
}

export function verify(input: unknown, opts: VerifyOptions = {}): Promise<Verdict> {
  return Promise.resolve(verifySync(input, opts));
}

function verifySync(input: unknown, opts: VerifyOptions): Verdict {
  const errors: string[] = [];
  const warnings: string[] = [];
  const fail = (code: string, msg: string): never => {
    throw new FormatError(`${code}: ${msg}`);
  };

  let parsed: ParsedInput;
  try {
    parsed = parseInput(input);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { valid: false, format: FORMAT_ID, receipt: null, errors: [msg], warnings: [] };
  }
  const { receipt, delegations, revocations } = parsed;
  const atMs = opts.at ? opts.at.getTime() : Date.now();
  const maxChainDepth = opts.maxChainDepth ?? 5;

  // receipt_id of the verdict so far; normalize only once we trust the signature
  let normalized: NormalizedReceipt | null = null;
  let revocationStatus: "unknown" | "active" | "revoked" = "unknown";
  let revocationPointer: string | null = null;
  let executorKey = "";

  try {
    // --- version gate (mirrors verifyReceipt: version !== '1.1' is an error)
    if (receipt.version !== "1.1") {
      fail(
        AGENT_PASSPORT_ERRORS.UNSUPPORTED_VERSION,
        `unsupported receipt version ${JSON.stringify(receipt.version)} (expected "1.1")`
      );
    }

    // --- receipt timestamp must be a readable instant
    const receiptMs = parseInstant("receipt.timestamp", receipt.timestamp);

    // --- resolve signer key and verify the Ed25519 signature
    executorKey = resolveExecutorKey(receipt, delegations);
    if (!verifyApsSignature(receipt, receipt.signature, executorKey)) {
      fail(
        AGENT_PASSPORT_ERRORS.BAD_SIGNATURE,
        "Ed25519 signature over APS canonical JSON (signature field excluded) does not verify with the executing agent's key"
      );
    }

    // --- trusted issuers gate (adapter extension; identity here is key material)
    if (opts.trustedIssuers && opts.trustedIssuers.length > 0) {
      const trusted = new Set(opts.trustedIssuers.map((s) => s.toLowerCase()));
      if (!trusted.has(executorKey)) {
        fail(
          AGENT_PASSPORT_ERRORS.UNTRUSTED_ISSUER,
          "receipt signer key is not in trustedIssuers"
        );
      }
    }

    // --- delegation chain checks
    if (delegations.length > 0) {
      if (delegations.length > maxChainDepth) {
        fail(
          AGENT_PASSPORT_ERRORS.DEPTH_EXCEEDED,
          `chain length ${delegations.length} exceeds verifier cap maxChainDepth=${maxChainDepth} (adapter-level safety cap; their per-delegation max_depth is checked per link below)`
        );
      }

      let prev: AgentPassportDelegation | null = null;
      for (let i = 0; i < delegations.length; i++) {
        const d = delegations[i];
        const tag = `delegations[${i}] (${d.delegationId})`;

        // signature by the delegator (delegatedBy key), canonical input
        if (!HEX64.test(d.delegatedBy) || !HEX64.test(d.delegatedTo)) {
          fail(
            AGENT_PASSPORT_ERRORS.CHAIN_BREAK,
            `${tag}: delegatedBy/delegatedTo must be 64-hex Ed25519 keys`
          );
        }
        if (!verifyApsSignature(d, d.signature, d.delegatedBy)) {
          fail(
            AGENT_PASSPORT_ERRORS.BAD_SIGNATURE,
            `${tag}: delegation signature does not verify with the delegator key`
          );
        }

        // window: receipt must be inside the delegation's validity window
        const expiresMs = parseInstant(`${tag}.expiresAt`, d.expiresAt);
        if (d.notBefore !== undefined) {
          const nbMs = parseInstant(`${tag}.notBefore`, String(d.notBefore));
          if (receiptMs < nbMs) {
            fail(
              AGENT_PASSPORT_ERRORS.NOT_YET_VALID,
              `${tag}: receipt predates the delegation's notBefore window`
            );
          }
        }
        if (receiptMs > expiresMs) {
          fail(
            AGENT_PASSPORT_ERRORS.EXPIRED,
            `${tag}: receipt was issued after the delegation expired`
          );
        }
        if (atMs > expiresMs) {
          warnings.push(
            `${AGENT_PASSPORT_WARNINGS.DELEGATION_NOW_EXPIRED}: ${tag} has since expired (receipt itself was timely)`
          );
        }

        // per-link depth rule (mirrors verifyDelegation: currentDepth > maxDepth)
        const effMax = d.maxDepth ?? prev?.maxDepth ?? 1;
        const curDepth = d.currentDepth ?? (prev ? (prev.currentDepth ?? i - 1) + 1 : 0);
        if (curDepth > effMax) {
          fail(
            AGENT_PASSPORT_ERRORS.DEPTH_EXCEEDED,
            `${tag}: currentDepth ${curDepth} exceeds maxDepth ${effMax}`
          );
        }

        if (prev) {
          // continuity: child must extend the parent exactly one hop
          const expectedDepth = (prev.currentDepth ?? i - 1) + 1;
          if (curDepth !== expectedDepth) {
            fail(
              AGENT_PASSPORT_ERRORS.CHAIN_BREAK,
              `${tag}: currentDepth ${curDepth} is not parent depth + 1 (expected ${expectedDepth})`
            );
          }
          if (d.delegatedBy.toLowerCase() !== prev.delegatedTo.toLowerCase()) {
            fail(
              AGENT_PASSPORT_ERRORS.CHAIN_BREAK,
              `${tag}: delegatedBy does not match parent's delegatedTo (chain break)`
            );
          }
          // maxDepth ceiling is inherited and cannot be increased
          const parentMax = prev.maxDepth ?? 1;
          if ((d.maxDepth ?? parentMax) > parentMax) {
            fail(
              AGENT_PASSPORT_ERRORS.DEPTH_EXCEEDED,
              `${tag}: maxDepth ${d.maxDepth} exceeds parent ceiling ${parentMax}`
            );
          }
          if (curDepth > parentMax) {
            fail(
              AGENT_PASSPORT_ERRORS.DEPTH_EXCEEDED,
              `${tag}: depth ${curDepth} exceeds parent maxDepth ${parentMax}`
            );
          }
          // per-hop scope narrowing: every child scope covered by a parent scope
          const badScopes = d.scope.filter(
            (s) => !scopeAuthorizes(prev!.scope, s)
          );
          if (badScopes.length > 0) {
            fail(
              AGENT_PASSPORT_ERRORS.NARROWING_VIOLATION,
              `${tag}: child scopes [${badScopes.join(", ")}] are not covered by parent scope [${prev.scope.join(", ")}] (scopeCovers rule)`
            );
          }
          // spend narrowing: child budget must not exceed parent remaining
          const parentUnit = prev.spendLimitUnit ?? (prev.spendLimit !== undefined ? "currency" : undefined);
          const childUnit = d.spendLimitUnit ?? parentUnit;
          if (
            parentUnit !== undefined &&
            childUnit === parentUnit &&
            prev.spendLimit !== undefined &&
            d.spendLimit !== undefined
          ) {
            const parentRemaining = prev.spendLimit - (prev.spentAmount ?? 0);
            if (d.spendLimit > parentRemaining) {
              fail(
                AGENT_PASSPORT_ERRORS.NARROWING_VIOLATION,
                `${tag}: child spendLimit ${d.spendLimit} exceeds parent remaining ${parentRemaining}`
              );
            }
          }
          // temporal narrowing: child must not outlive the parent
          const parentExpiresMs = parseInstant("parent.expiresAt", prev.expiresAt);
          if (expiresMs > parentExpiresMs) {
            fail(
              AGENT_PASSPORT_ERRORS.NARROWING_VIOLATION,
              `${tag}: child expiry is later than the parent's expiry`
            );
          }
        }
        prev = d;
      }

      // receipt <-> leaf binding
      const leaf = delegations[delegations.length - 1];
      if (leaf.delegationId !== receipt.delegation_id) {
        fail(
          AGENT_PASSPORT_ERRORS.CHAIN_BREAK,
          `receipt.delegation_id ${JSON.stringify(receipt.delegation_id)} does not match leaf delegation ${JSON.stringify(leaf.delegationId)}`
        );
      }
      if (leaf.delegatedTo.toLowerCase() !== executorKey) {
        fail(
          AGENT_PASSPORT_ERRORS.CHAIN_BREAK,
          "leaf delegation's delegatedTo does not match the receipt signer key"
        );
      }

      // the action actually used must be authorized by the leaf delegation scope
      if (!scopeAuthorizes(leaf.scope, receipt.action.scope_used)) {
        fail(
          AGENT_PASSPORT_ERRORS.SCOPE_VIOLATION,
          `action.scope_used ${JSON.stringify(receipt.action.scope_used)} is not covered by delegation scope [${leaf.scope.join(", ")}]`
        );
      }

      // spend must not exceed the delegation's remaining budget
      const spend = receipt.action.spend;
      if (spend && typeof spend.amount === "number") {
        const remaining = (leaf.spendLimit ?? Infinity) - (leaf.spentAmount ?? 0);
        if (spend.amount > remaining) {
          fail(
            AGENT_PASSPORT_ERRORS.OVER_BUDGET,
            `action spend ${spend.amount} exceeds delegation remaining ${remaining}`
          );
        }
      }

      revocationPointer = leaf.revocationCheckUrl ?? null;

      // --- revocation (offline evidence only)
      const revokedIds = new Set<string>();
      let evidenceSeen = false;

      for (const d of delegations) {
        if (d.revoked === true) {
          // baked-in marker per CASCADE-REVOCATION-SPEC section 2.1 schema
          evidenceSeen = true;
          revokedIds.add(d.delegationId);
        }
      }

      // child map for cascade: a child extends a parent when its delegator is
      // the parent's delegatee and its depth is exactly one more
      const childrenOf = new Map<string, string[]>();
      for (let i = 1; i < delegations.length; i++) {
        const parent = delegations[i - 1];
        const child = delegations[i];
        if (
          child.delegatedBy.toLowerCase() === parent.delegatedTo.toLowerCase() &&
          (child.currentDepth ?? i) === (parent.currentDepth ?? i - 1) + 1
        ) {
          const list = childrenOf.get(parent.delegationId) ?? [];
          list.push(child.delegationId);
          childrenOf.set(parent.delegationId, list);
        }
      }

      for (const rv of revocations) {
        const targetId = rv.delegation_id ?? rv.delegationId;
        const revoker = (rv.revoked_by ?? rv.revokedBy ?? "") as string;
        if (typeof targetId !== "string" || !HEX64.test(revoker)) continue;
        if (!verifyApsSignature(rv as unknown as Record<string, unknown>, rv.signature, revoker)) {
          warnings.push(
            `${AGENT_PASSPORT_WARNINGS.BAD_REVOCATION_SIGNATURE}: revocation for ${targetId} has an invalid signature; ignored`
          );
          continue;
        }
        // A validly signed revocation record is revocation evidence the
        // verifier consulted — even when it names a delegation outside this
        // chain (proof the caller has a live revocation feed).
        evidenceSeen = true;
        const target = delegations.find((d) => d.delegationId === targetId);
        if (!target) {
          warnings.push(
            `${AGENT_PASSPORT_WARNINGS.BAD_REVOCATION_SIGNATURE}: revocation for unknown delegation ${JSON.stringify(targetId)} ignored`
          );
          continue;
        }
        // Only the delegation's creator can revoke it (SPEC-v1.1 section 2.3).
        if (revoker.toLowerCase() !== target.delegatedBy.toLowerCase()) {
          warnings.push(
            `${AGENT_PASSPORT_WARNINGS.BAD_REVOCATION_SIGNATURE}: revocation for ${targetId} not signed by the delegating key; ignored`
          );
          continue;
        }
        // cascade: the target and all descendants die (SPEC-v1.1 section 2.3)
        const stack = [targetId];
        while (stack.length > 0) {
          const id = stack.pop() as string;
          if (revokedIds.has(id)) continue;
          revokedIds.add(id);
          for (const c of childrenOf.get(id) ?? []) stack.push(c);
        }
      }

      const revokedLink = delegations.find((d) => revokedIds.has(d.delegationId));
      if (revokedLink) {
        revocationStatus = "revoked";
        fail(
          AGENT_PASSPORT_ERRORS.REVOKED,
          `delegation ${revokedLink.delegationId} is revoked (cascade revocation honored offline from supplied evidence)`
        );
      } else if (evidenceSeen) {
        revocationStatus = "active";
      } else {
        warnings.push(
          `${AGENT_PASSPORT_WARNINGS.REVOCATION_UNCHECKED_OFFLINE}: no revocation evidence was supplied; the registry fetch (SPEC-v1.1 section 2.4) needs network, which this offline verifier never performs`
        );
      }
    } else {
      warnings.push(
        `${AGENT_PASSPORT_WARNINGS.CHAIN_NOT_SUPPLIED}: bare receipt — depth, narrowing, scope and spend checks were skipped`
      );
      warnings.push(
        `${AGENT_PASSPORT_WARNINGS.REVOCATION_UNCHECKED_OFFLINE}: no delegation chain was supplied, so revocation status is unknown (registry fetch needs network)`
      );
    }

    // append-only linkage note (digest pin is an adapter decision — their spec
    // does not pin the previousReceiptHash digest; see notes)
    if (typeof receipt.previousReceiptHash === "string") {
      warnings.push(
        `${AGENT_PASSPORT_WARNINGS.PREVIOUS_LINK_UNCHECKED}: previousReceiptHash present but the prior receipt was not supplied, so the append-only link was not verified`
      );
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return {
      valid: false,
      format: FORMAT_ID,
      receipt: normalized,
      errors: [msg],
      warnings,
    };
  }

  normalized = normalizeParsed(parsed, {
    executorKey,
    revocationStatus,
    revocationPointer,
  });
  return { valid: true, format: FORMAT_ID, receipt: normalized, errors: [], warnings };
}

// ---------------------------------------------------------------------------
// normalize
// ---------------------------------------------------------------------------

export function normalize(input: unknown): NormalizedReceipt {
  const parsed = parseInput(input); // throws FormatError on bad shape
  let executorKey = "";
  try {
    executorKey = resolveExecutorKey(parsed.receipt, parsed.delegations);
  } catch {
    executorKey = "";
  }
  return normalizeParsed(parsed, {
    executorKey,
    revocationStatus: "unknown",
    revocationPointer:
      parsed.delegations.length > 0
        ? (parsed.delegations[parsed.delegations.length - 1].revocationCheckUrl ?? null)
        : null,
  });
}

function normalizeParsed(
  parsed: ParsedInput,
  ctx: {
    executorKey: string;
    revocationStatus: "unknown" | "active" | "revoked";
    revocationPointer: string | null;
  }
): NormalizedReceipt {
  const { receipt, delegations } = parsed;
  const leaf = delegations.length > 0 ? delegations[delegations.length - 1] : null;

  const lossy: string[] = [];
  lossy.push(
    "action.result (status/summary) has no normalized field; preserved in raw"
  );
  lossy.push(
    "action.type/method/spend flattened into scope.constraints; spend currency-unit semantics are not modeled"
  );
  lossy.push(
    "delegation_chain fingerprints are not modeled; only the executing agent's key is normalized as issuer"
  );
  if (receipt.previousReceiptHash !== undefined) {
    lossy.push(
      "previousReceiptHash append-only linkage is not represented in the normalized parent model; preserved in raw"
    );
  }
  for (const f of [
    "witnessSignature",
    "witnessAttestation",
    "finality",
    "authorizationRef",
  ]) {
    if (receipt[f] !== undefined) {
      lossy.push(
        `optional ${f} (notary/maturation field) is not modeled; preserved in raw`
      );
    }
  }
  lossy.push(
    "delegation bounds (spendLimit/spendLimitUnit/maxDepth/currentDepth/scopeInterpretation) are not modeled; preserved in raw"
  );
  lossy.push(
    "per-hop scope narrowing is verified at verify() time; the normalized scope carries only the leaf action's scope_used"
  );
  if (!leaf) {
    lossy.push(
      "no delegation chain supplied: notBefore/notAfter fall back to the receipt timestamp"
    );
  }

  const pubkeyBytes =
    ctx.executorKey && HEX64.test(ctx.executorKey)
      ? hexToBytes(ctx.executorKey)
      : new Uint8Array(32);

  const scopeUsed = receipt.action.scope_used;
  const constraints: Record<string, unknown> = {
    actionType: receipt.action.type,
  };
  if (receipt.action.method !== undefined) constraints["method"] = receipt.action.method;
  if (receipt.action.spend !== undefined) constraints["spend"] = receipt.action.spend;

  const notBefore =
    leaf?.notBefore ?? receipt.timestamp;
  const notAfter = leaf?.expiresAt ?? receipt.timestamp;

  return {
    format: FORMAT_ID,
    receiptId: receipt.receipt_id,
    issuer: ctx.executorKey || receipt.agent_id,
    issuerKey: {
      kty: "OKP",
      crv: "Ed25519",
      x: b64uEncode(pubkeyBytes),
    },
    agent: typeof receipt.agent_id === "string" ? receipt.agent_id : null,
    scope: {
      kind: "structured",
      actions: [scopeUsed],
      resources: [receipt.action.target],
      constraints,
      text: null,
      enforced: true,
    },
    boundaries: [`scope:${scopeUsed}`, `target:${receipt.action.target}`],
    notBefore,
    notAfter,
    instructionsHash: null,
    parentId: receipt.delegation_id,
    revocation: {
      required: false,
      pointer: ctx.revocationPointer,
      status: ctx.revocationStatus,
    },
    raw: parsed.envelope
      ? { receipt: parsed.receipt, delegations: parsed.delegations, revocations: parsed.revocations }
      : parsed.receipt,
    lossy,
  };
}

// ---------------------------------------------------------------------------
// FormatVerifier-shaped export
// ---------------------------------------------------------------------------

export interface AgentPassportVerifier {
  id: typeof FORMAT_ID;
  detect: (input: unknown) => boolean;
  verify: (input: unknown, opts?: VerifyOptions) => Promise<Verdict>;
  normalize: (input: unknown) => NormalizedReceipt;
}

const agentPassportVerifier: AgentPassportVerifier = {
  id: FORMAT_ID,
  detect,
  verify,
  normalize,
};

export default agentPassportVerifier;
