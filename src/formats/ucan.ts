/**
 * UCAN (User Controlled Authorization Network) 0.9-style JWT verifier.
 *
 * Scope: UCANs as JSON Web Tokens (compact serialization) with embedded
 * proof chains, per ucan-wg/ts-ucan (the reference implementation behind the
 * 0.7.0 / 0.8.1 / 0.9.0 spec fixtures). Signatures are Ed25519 (JWT alg
 * "EdDSA") over ASCII(header_b64 + "." + payload_b64); issuers and audiences
 * are did:key DIDs with the ed25519 multicodec prefix (0xED 0x01).
 *
 * OUT OF SCOPE (documented boundary):
 * - UCAN 1.0 IPLD-CID proofs (needs IPFS/CID resolution). If a `prf` entry
 *   is a CID rather than an embedded JWT, verification fails with CHAIN_BREAK
 *   and a message explaining the boundary.
 * - Non-Ed25519 key types (RSA / P-256 / secp256k1 algs exist in the spec
 *   family but this adapter only accepts `alg: "EdDSA"` with did:key).
 * - Pluggable delegation semantics. The spec leaves resource/ability
 *   attenuation semantics open; this adapter applies the reference
 *   implementation's default ("equalCanDelegate") semantics, fail-closed:
 *   resource pointers must match (scheme case-insensitive), abilities must
 *   match (namespace + segments case-insensitive), with `*` (superuser)
 *   covering anything it appears in.
 *
 * Spec sources (read during build, 2026-10-09):
 * - https://github.com/ucan-wg/ts-ucan (packages/core/src/token.ts,
 *   verify.ts, attenuation.ts, capability/*, default-plugins/src/ed25519/*)
 * - https://github.com/ucan-wg/spec (fixtures/0.8.1/{valid,invalid}.json)
 *
 * Shared types are defined by the core track in src/model.ts and imported
 * here; the exported object matches the FormatVerifier shape.
 */

import nacl from "tweetnacl";
import { createHash } from "node:crypto";
import type {
  FormatId,
  NormalizedReceipt,
  VerifyOptions,
  Verdict,
} from "../model.js";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

export const UCAN_ERRORS = {
  UNKNOWN_FORMAT: "UNKNOWN_FORMAT",
  BAD_SIGNATURE: "BAD_SIGNATURE",
  EXPIRED: "EXPIRED",
  NOT_YET_VALID: "NOT_YET_VALID",
  CHAIN_BREAK: "CHAIN_BREAK",
  ATTENUATION_VIOLATION: "ATTENUATION_VIOLATION",
  AUDIENCE_MISMATCH: "AUDIENCE_MISMATCH",
  DEPTH_EXCEEDED: "DEPTH_EXCEEDED",
  UNSUPPORTED_DID_METHOD: "UNSUPPORTED_DID_METHOD",
  UNTRUSTED_ISSUER: "UNTRUSTED_ISSUER", // adapter extension (not in the task's base list)
} as const;

// ---------------------------------------------------------------------------
// Small encodings
// ---------------------------------------------------------------------------

const B58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Decode(s: string): Uint8Array {
  let num = 0n;
  for (const ch of s) {
    const digit = B58_ALPHABET.indexOf(ch);
    if (digit < 0) throw new Error(`invalid base58 character: ${ch}`);
    num = num * 58n + BigInt(digit);
  }
  let hex = num.toString(16);
  if (hex.length % 2 !== 0) hex = "0" + hex;
  const body = Buffer.from(hex, "hex");
  let leadingZeros = 0;
  for (const ch of s) {
    if (ch === "1") leadingZeros++;
    else break;
  }
  const out = new Uint8Array(leadingZeros + body.length);
  out.set(body, leadingZeros);
  return out;
}

function b64uDecode(s: string): Uint8Array {
  // Node accepts "base64url" natively; throw a clean error on garbage.
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("invalid base64url");
  return new Uint8Array(Buffer.from(s, "base64url"));
}

function b64uEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function sha256hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

// ---------------------------------------------------------------------------
// did:key (Ed25519)
// ---------------------------------------------------------------------------

const DID_KEY_PREFIX = "did:key:z";
// multicodec varint for ed25519-pub: 0xED 0x01 (ucan-wg/ts-ucan
// packages/default-plugins/src/prefixes.ts: EDWARDS_DID_PREFIX)
const ED25519_MULTICODEC = [0xed, 0x01] as const;

/** Extract the raw 32-byte Ed25519 public key from a did:key DID. */
function ed25519PubkeyFromDid(did: string): Uint8Array {
  if (!did.startsWith(DID_KEY_PREFIX)) {
    throw new Error(
      `UNSUPPORTED_DID_METHOD: expected did:key DID, got ${did.slice(0, 16)}...`
    );
  }
  const decoded = base58Decode(did.slice(DID_KEY_PREFIX.length));
  if (
    decoded.length !== 34 ||
    decoded[0] !== ED25519_MULTICODEC[0] ||
    decoded[1] !== ED25519_MULTICODEC[1]
  ) {
    throw new Error(
      "UNSUPPORTED_DID_METHOD: did:key is not an ed25519 key (multicodec 0xed01)"
    );
  }
  return decoded.slice(2);
}

// ---------------------------------------------------------------------------
// UCAN structure
// ---------------------------------------------------------------------------

export interface UcanHeader {
  alg: string;
  typ?: string;
  ucv?: string;
  [k: string]: unknown;
}

export interface EncodedCapability {
  with: string;
  can: string;
}

export interface UcanPayload {
  iss: string;
  aud: string;
  exp: number;
  nbf?: number;
  nnc?: string;
  fct?: unknown[];
  att: EncodedCapability[];
  prf: string[];
  [k: string]: unknown;
}

interface ParsedUcan {
  encoded: string;
  headerB64: string;
  payloadB64: string;
  header: UcanHeader;
  payload: UcanPayload;
}

/** Split a compact JWT and JSON-decode header/payload. Throws on malformed. */
function parseUcan(encoded: string): ParsedUcan {
  if (typeof encoded !== "string") {
    throw new Error("UNKNOWN_FORMAT: UCAN input must be a string");
  }
  const parts = encoded.split(".");
  if (parts.length !== 3 || parts.some((p) => p.length === 0)) {
    throw new Error(
      "UNKNOWN_FORMAT: expected compact JWT with 3 dot-separated segments"
    );
  }
  const [headerB64, payloadB64] = parts;
  let header: unknown;
  let payload: unknown;
  try {
    header = JSON.parse(Buffer.from(b64uDecode(headerB64)).toString("utf8"));
  } catch {
    throw new Error("UNKNOWN_FORMAT: header is not base64url JSON");
  }
  try {
    payload = JSON.parse(Buffer.from(b64uDecode(payloadB64)).toString("utf8"));
  } catch {
    throw new Error("UNKNOWN_FORMAT: payload is not base64url JSON");
  }
  if (typeof header !== "object" || header === null) {
    throw new Error("UNKNOWN_FORMAT: header must be a JSON object");
  }
  if (typeof payload !== "object" || payload === null) {
    throw new Error("UNKNOWN_FORMAT: payload must be a JSON object");
  }
  const h = header as Record<string, unknown>;
  const p = payload as Record<string, unknown>;

  if (typeof p["iss"] !== "string" || typeof p["aud"] !== "string") {
    throw new Error("UNKNOWN_FORMAT: iss and aud must be string DIDs");
  }
  if (typeof p["exp"] !== "number" || !Number.isFinite(p["exp"])) {
    // Fail-closed adapter decision: the reference implementation always
    // mints exp; a UCAN without expiry is not verifiable as a receipt.
    throw new Error("UNKNOWN_FORMAT: exp must be a numeric unix timestamp");
  }
  if (p["nbf"] !== undefined && typeof p["nbf"] !== "number") {
    throw new Error("UNKNOWN_FORMAT: nbf must be a numeric unix timestamp");
  }
  if (p["att"] !== undefined && !Array.isArray(p["att"])) {
    throw new Error("UNKNOWN_FORMAT: att must be an array");
  }
  if (p["prf"] !== undefined && !Array.isArray(p["prf"])) {
    throw new Error("UNKNOWN_FORMAT: prf must be an array");
  }

  const att: EncodedCapability[] = [];
  for (const raw of (p["att"] as unknown[] | undefined) ?? []) {
    if (typeof raw !== "object" || raw === null) {
      throw new Error("UNKNOWN_FORMAT: att entries must be objects");
    }
    const r = raw as Record<string, unknown>;
    // The spec wire form is { with, can }. Accept { wn, cap } as aliases
    // for hand-built tokens; they are documented in the notes.
    const withVal = r["with"] ?? r["wn"];
    const canVal = r["can"] ?? r["cap"];
    if (typeof withVal !== "string" || typeof canVal !== "string") {
      throw new Error(
        "UNKNOWN_FORMAT: att entries need string with/can (or wn/cap)"
      );
    }
    att.push({ with: withVal, can: canVal });
  }

  const prf: string[] = [];
  for (const raw of (p["prf"] as unknown[] | undefined) ?? []) {
    if (typeof raw !== "string") {
      throw new Error("UNKNOWN_FORMAT: prf entries must be strings");
    }
    prf.push(raw);
  }

  return {
    encoded,
    headerB64,
    payloadB64,
    header: {
      alg: typeof h["alg"] === "string" ? h["alg"] : "",
      typ: typeof h["typ"] === "string" ? h["typ"] : undefined,
      ucv: typeof h["ucv"] === "string" ? h["ucv"] : undefined,
    },
    payload: {
      iss: p["iss"] as string,
      aud: p["aud"] as string,
      exp: p["exp"] as number,
      nbf: p["nbf"] as number | undefined,
      nnc: typeof p["nnc"] === "string" ? p["nnc"] : undefined,
      fct: Array.isArray(p["fct"]) ? (p["fct"] as unknown[]) : undefined,
      att,
      prf,
    },
  };
}

// ---------------------------------------------------------------------------
// Capability attenuation (default reference semantics, fail-closed)
// ---------------------------------------------------------------------------

function parseWith(withStr: string): { scheme: string; hierPart: string } {
  const idx = withStr.indexOf(":");
  if (idx < 0) return { scheme: withStr.toLowerCase(), hierPart: "" };
  return {
    scheme: withStr.slice(0, idx).toLowerCase(),
    hierPart: withStr.slice(idx + 1),
  };
}

function parseCan(canStr: string): { namespace: string; segments: string[] } {
  if (canStr === "*") return { namespace: "*", segments: [] };
  const [namespace, ...segments] = canStr.split("/");
  return { namespace: (namespace ?? "").toLowerCase(), segments };
}

/**
 * Whether a parent capability covers a child capability (delegation).
 * Mirrors ts-ucan's default `equalCanDelegate` semantics:
 *  - resource: same scheme (case-insensitive) and same hierPart; a "*"
 *    hierPart covers any hierPart under the same scheme, a "*" scheme
 *    covers any resource.
 *  - ability: parent "*" (superuser) covers anything; otherwise equal
 *    namespace and equal segment list (case-insensitive).
 */
export function capabilityCovers(
  parent: EncodedCapability,
  child: EncodedCapability
): boolean {
  const pw = parseWith(parent.with);
  const cw = parseWith(child.with);
  const resourceOk =
    (pw.scheme === "*" && pw.hierPart === "*") ||
    (pw.scheme === cw.scheme &&
      (pw.hierPart === "*" || pw.hierPart === cw.hierPart));

  const pc = parseCan(parent.can);
  const cc = parseCan(child.can);
  const abilityOk =
    pc.namespace === "*" ||
    (pc.namespace === cc.namespace &&
      pc.segments.length === cc.segments.length &&
      pc.segments.every(
        (seg, i) => seg.toLowerCase() === cc.segments[i].toLowerCase()
      ));

  return resourceOk && abilityOk;
}

// ---------------------------------------------------------------------------
// Chain verification
// ---------------------------------------------------------------------------

interface ChainResult {
  parsed: ParsedUcan;
  errors: string[];
  warnings: string[];
}

/**
 * Recursively verify one UCAN layer plus its embedded proof chain.
 *
 * `depth` counts UCAN layers (the outermost token is depth 1).
 * `childIss` is the iss of the token this layer is a proof for, used for
 * the audience-chaining check (proof.aud === child.iss).
 */
function verifyLayer(
  encoded: string,
  opts: Required<Pick<VerifyOptions, "at" | "maxChainDepth">> &
    Pick<VerifyOptions, "trustedIssuers">,
  depth: number,
  childIss: string | null,
  errors: string[],
  warnings: string[]
): ParsedUcan | null {
  if (depth > (opts.maxChainDepth ?? 5)) {
    errors.push(
      `${UCAN_ERRORS.DEPTH_EXCEEDED}: chain depth ${depth} exceeds max ${opts.maxChainDepth}`
    );
    return null;
  }

  let parsed: ParsedUcan;
  try {
    parsed = parseUcan(encoded);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    errors.push(
      msg.startsWith("UNKNOWN_FORMAT")
        ? msg
        : `${UCAN_ERRORS.CHAIN_BREAK}: proof at depth ${depth} is malformed: ${msg}`
    );
    return null;
  }

  // --- audience chaining: proof.aud must equal the child's iss
  if (childIss !== null && parsed.payload.aud !== childIss) {
    errors.push(
      `${UCAN_ERRORS.AUDIENCE_MISMATCH}: proof at depth ${depth} aud ${parsed.payload.aud} !== child iss ${childIss}`
    );
  }

  // --- algorithm: EdDSA only (adapter scope)
  if (parsed.header.alg !== "EdDSA") {
    errors.push(
      `${UCAN_ERRORS.UNKNOWN_FORMAT}: header.alg must be EdDSA, got "${parsed.header.alg}"`
    );
  }

  // --- issuer: must be a did:key with an ed25519 key
  let pubkey: Uint8Array | null = null;
  try {
    pubkey = ed25519PubkeyFromDid(parsed.payload.iss);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    errors.push(
      msg.startsWith("UNSUPPORTED_DID_METHOD")
        ? msg
        : `${UCAN_ERRORS.UNSUPPORTED_DID_METHOD}: ${msg}`
    );
  }
  // The audience must at least be a syntactically valid did:key ed25519 DID
  // (its key is not needed for verification, only its identity).
  try {
    ed25519PubkeyFromDid(parsed.payload.aud);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    errors.push(
      msg.startsWith("UNSUPPORTED_DID_METHOD")
        ? msg
        : `${UCAN_ERRORS.UNSUPPORTED_DID_METHOD}: aud: ${msg}`
    );
  }

  // --- signature: Ed25519 over ASCII(header_b64 + "." + payload_b64)
  if (pubkey) {
    let sigBytes: Uint8Array;
    try {
      const sigB64 = parsed.encoded.split(".")[2];
      sigBytes = b64uDecode(sigB64);
    } catch {
      errors.push(
        `${UCAN_ERRORS.BAD_SIGNATURE}: signature segment is not valid base64url`
      );
      sigBytes = new Uint8Array(0);
    }
    if (sigBytes.length !== nacl.sign.signatureLength) {
      errors.push(
        `${UCAN_ERRORS.BAD_SIGNATURE}: signature must be ${nacl.sign.signatureLength} bytes, got ${sigBytes.length}`
      );
    } else {
      const signedData = new TextEncoder().encode(
        `${parsed.headerB64}.${parsed.payloadB64}`
      );
      if (!nacl.sign.detached.verify(signedData, sigBytes, pubkey)) {
        errors.push(`${UCAN_ERRORS.BAD_SIGNATURE}: Ed25519 signature invalid`);
      }
    }
  }

  // --- trusted issuers (outermost layer only)
  if (
    depth === 1 &&
    opts.trustedIssuers &&
    !opts.trustedIssuers.includes(parsed.payload.iss)
  ) {
    errors.push(
      `${UCAN_ERRORS.UNTRUSTED_ISSUER}: ${parsed.payload.iss} not in trustedIssuers`
    );
  }

  // --- time bounds (no leeway; the reference implementation uses none)
  const nowSec = Math.floor(opts.at.getTime() / 1000);
  if (parsed.payload.exp <= nowSec) {
    errors.push(
      `${UCAN_ERRORS.EXPIRED}: exp ${parsed.payload.exp} <= now ${nowSec}`
    );
  }
  if (parsed.payload.nbf !== undefined && parsed.payload.nbf > nowSec) {
    errors.push(
      `${UCAN_ERRORS.NOT_YET_VALID}: nbf ${parsed.payload.nbf} > now ${nowSec}`
    );
  }

  // --- version sanity (warn only; we accept any 0.x embedded-JWT UCAN)
  if (parsed.header.ucv === undefined) {
    warnings.push("header.ucv missing; expected a UCAN version string");
  } else if (!/^0\./.test(parsed.header.ucv)) {
    warnings.push(
      `header.ucv ${parsed.header.ucv} is not a 0.x embedded-JWT UCAN; ` +
        `UCAN 1.0 CID proofs are unsupported`
    );
  }

  // --- recurse into embedded proofs
  const verifiedProofAtt: EncodedCapability[] = [];
  for (const proofToken of parsed.payload.prf) {
    if (typeof proofToken !== "string" || proofToken.split(".").length !== 3) {
      errors.push(
        `${UCAN_ERRORS.CHAIN_BREAK}: prf entry at depth ${depth} is not an ` +
          `embedded JWT (UCAN 1.0 IPLD-CID proofs are out of scope)`
      );
      continue;
    }
    const proofParsed = verifyLayer(
      proofToken,
      opts,
      depth + 1,
      parsed.payload.iss,
      errors,
      warnings
    );
    if (proofParsed) verifiedProofAtt.push(...proofParsed.payload.att);
  }

  // --- capability attenuation: every child att capability must be covered
  // --- by some parent att capability. The pool is the UNION of att across
  // --- all verified proofs at this layer (matches the reference
  // --- implementation's rights-amplification behavior: a child may combine
  // --- capabilities granted by different proofs). A layer with no proofs is
  // --- a root and grants its own att without attenuation.
  if (parsed.payload.prf.length > 0) {
    for (const childCap of parsed.payload.att) {
      const covered = verifiedProofAtt.some((parentCap) =>
        capabilityCovers(parentCap, childCap)
      );
      if (!covered) {
        errors.push(
          `${UCAN_ERRORS.ATTENUATION_VIOLATION}: depth-${depth} capability ` +
            `{with:${childCap.with},can:${childCap.can}} not covered by any ` +
            `proof att`
        );
      }
    }
  }

  return parsed;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

const FORMAT: FormatId = "ucan";

export interface UcanVerifier {
  id: FormatId;
  detect(input: unknown): boolean;
  verify(input: unknown, opts?: VerifyOptions): Promise<Verdict>;
  normalize(input: unknown): NormalizedReceipt;
}

/**
 * Cheap shape check: looks like a compact JWT whose header carries a UCAN
 * version (`ucv`) or whose payload carries UCAN claims (`att`/`prf`).
 * Never throws.
 */
export function detect(input: unknown): boolean {
  if (typeof input !== "string") return false;
  try {
    const parts = input.split(".");
    if (parts.length !== 3) return false;
    const header = JSON.parse(
      Buffer.from(b64uDecode(parts[0])).toString("utf8")
    ) as Record<string, unknown>;
    const payload = JSON.parse(
      Buffer.from(b64uDecode(parts[1])).toString("utf8")
    ) as Record<string, unknown>;
    if (typeof header !== "object" || header === null) return false;
    if (typeof payload !== "object" || payload === null) return false;
    const hasUcv = typeof header["ucv"] === "string";
    const hasAtt = Array.isArray(payload["att"]);
    const hasPrf = Array.isArray(payload["prf"]);
    return hasUcv || hasAtt || hasPrf;
  } catch {
    return false;
  }
}

export async function verify(
  input: unknown,
  opts: VerifyOptions = {}
): Promise<Verdict> {
  const errors: string[] = [];
  const warnings: string[] = [];
  const full: Required<Pick<VerifyOptions, "at" | "maxChainDepth">> &
    Pick<VerifyOptions, "trustedIssuers"> = {
    at: opts.at ?? new Date(),
    maxChainDepth: opts.maxChainDepth ?? 5,
    trustedIssuers: opts.trustedIssuers,
  };

  if (typeof input !== "string") {
    return {
      valid: false,
      format: FORMAT,
      receipt: null,
      errors: [`${UCAN_ERRORS.UNKNOWN_FORMAT}: UCAN input must be a string`],
      warnings,
    };
  }

  let parsed: ParsedUcan | null = null;
  try {
    parsed = verifyLayer(input, full, 1, null, errors, warnings);
  } catch (e) {
    errors.push(
      `${UCAN_ERRORS.UNKNOWN_FORMAT}: ${e instanceof Error ? e.message : String(e)}`
    );
  }

  const valid = errors.length === 0 && parsed !== null;
  return {
    valid,
    format: FORMAT,
    receipt: valid && parsed ? normalize(parsed.encoded) : null,
    errors,
    warnings,
  };
}

/**
 * Map a parsed UCAN to the shared NormalizedReceipt shape.
 * Assumes the input parsed cleanly (verify() or detect() should gate first);
 * throws UNKNOWN_FORMAT on malformed input.
 */
export function normalize(input: unknown): NormalizedReceipt {
  const parsed = parseUcan(input as string);
  const pubkey = ed25519PubkeyFromDid(parsed.payload.iss);
  const lossy: string[] = [
    "UCAN has no revocation registry; status always unknown",
    "fct (facts) not mapped",
    "no advisory text scope",
    "att capabilities beyond with/can strings not preserved",
  ];
  const notBefore =
    parsed.payload.nbf !== undefined
      ? new Date(parsed.payload.nbf * 1000).toISOString()
      : "1970-01-01T00:00:00.000Z";
  if (parsed.payload.nbf === undefined) lossy.push("no nbf claim");
  if (parsed.payload.prf.length === 0) lossy.push("no proofs (root UCAN)");

  return {
    format: FORMAT,
    receiptId: sha256hex(parsed.encoded),
    issuer: parsed.payload.iss,
    issuerKey: {
      kty: "OKP",
      crv: "Ed25519",
      x: b64uEncode(pubkey),
    },
    agent: parsed.payload.aud,
    scope: {
      kind: "capability",
      actions: parsed.payload.att.map((c) => c.can),
      resources: parsed.payload.att.map((c) => c.with),
      constraints: {},
      text: null,
      enforced: true,
    },
    boundaries: [],
    notBefore,
    notAfter: new Date(parsed.payload.exp * 1000).toISOString(),
    instructionsHash: null,
    parentId:
      parsed.payload.prf.length > 0 ? sha256hex(parsed.payload.prf[0]) : null,
    revocation: { required: false, pointer: null, status: "unknown" },
    raw: { header: parsed.header, payload: parsed.payload },
    lossy,
  };
}

const ucanVerifier: UcanVerifier = {
  id: FORMAT,
  detect,
  verify,
  normalize,
};

export default ucanVerifier;
