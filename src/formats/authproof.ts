// authproof JWS-profile verifier (draft-nelson-agent-delegation-receipts-11,
// sections 4, 5, 6, 8). Implements FormatVerifier for 'authproof-jws'.
// The COSE profile (section 7) is detected but explicitly not implemented.

import {
  base64urlDecode,
  base64urlEncode,
  ecJwkThumbprint,
  es256Verify,
  jcsCanonicalize,
  sha256Hex,
} from '../crypto.js';
import type {
  FormatId,
  FormatVerifier,
  NormalizedReceipt,
  ScopeExpression,
  Verdict,
  VerifyOptions,
} from '../model.js';

// Body fields defined by draft -11 sections 4.2 (required) and 4.3 (optional).
// Unknown fields are dropped before canonicalization per section 4.1.
const KNOWN_BODY_FIELDS = new Set([
  'delegationId',
  'issuedAt',
  'scope',
  'boundaries',
  'timeWindow',
  'operatorInstructions',
  'instructionsHash',
  'signerPublicKey',
  'agentId',
  'metadata',
  'toolSchemaHash',
  'trustedSources',
  'toolOutputHash',
  'revocationRequired',
  'oneTimeUse',
  'parentReceiptId',
  'authorityStateCommitment',
  'reauthPolicy',
  'scopeSchema',
  'nonce',
]);

const ISO8601_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/;
const HEX64 = /^[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;

function isIso8601Utc(s: unknown): s is string {
  return typeof s === 'string' && ISO8601_UTC.test(s) && !Number.isNaN(Date.parse(s));
}

interface ScopeSchemaEntry {
  operation: string;
  resource: string;
  constraints?: Record<string, unknown>;
}

interface ScopeSchema {
  version: string;
  allowedActions: ScopeSchemaEntry[];
  deniedActions: ScopeSchemaEntry[];
}

interface ReceiptBody {
  delegationId: string;
  issuedAt: string;
  scope: string;
  boundaries: string;
  timeWindow: { start: string; end: string };
  operatorInstructions: string;
  instructionsHash: string;
  signerPublicKey: { kty: 'EC'; crv: 'P-256'; x: string; y: string };
  agentId: string | null;
  parentReceiptId: string | null;
  revocationRequired: boolean;
  oneTimeUse: boolean;
  scopeSchema: ScopeSchema | null;
}

interface ParsedInput {
  kind: 'compact' | 'detached';
  headerB64: string;
  header: Record<string, unknown>;
  payloadBytes: Uint8Array;
  signature: Uint8Array;
  signingInput: Uint8Array;
  compactBytes: Uint8Array;
  receiptId: string;
  orchestratorSignature: string | null;
  raw: unknown;
}

function fail(code: string, detail?: string): never {
  throw new Error(detail ? `${code}: ${detail}` : code);
}

function ascii(s: string): Uint8Array {
  return Buffer.from(s, 'ascii');
}

// ---------------------------------------------------------------------------
// Input parsing
// ---------------------------------------------------------------------------

function parseHeader(headerB64: string): Record<string, unknown> {
  let header: unknown;
  try {
    header = JSON.parse(Buffer.from(base64urlDecode(headerB64)).toString('utf8'));
  } catch {
    fail('HEADER_NOT_JSON');
  }
  if (typeof header !== 'object' || header === null || Array.isArray(header)) {
    fail('HEADER_NOT_OBJECT');
  }
  return header as Record<string, unknown>;
}

function parseInput(input: unknown): ParsedInput {
  // Form 1: compact JWS string (three non-empty segments).
  if (typeof input === 'string') {
    const parts = input.split('.');
    if (parts.length !== 3 || parts.some((p) => p.length === 0 || !BASE64URL.test(p))) {
      fail('INPUT_NOT_COMPACT_JWS');
    }
    const [headerB64, payloadB64, sigB64] = parts;
    const header = parseHeader(headerB64);
    const payloadBytes = base64urlDecode(payloadB64);
    const signature = base64urlDecode(sigB64);
    const compactBytes = ascii(input);
    return {
      kind: 'compact',
      headerB64,
      header,
      payloadBytes,
      signature,
      signingInput: ascii(`${headerB64}.${payloadB64}`),
      compactBytes,
      receiptId: sha256Hex(compactBytes),
      orchestratorSignature: null,
      raw: input,
    };
  }

  // Form 2: object forms. { detached: "headerB64..sigB64", payload } per the
  // RFC 7797 detached profile, or { compact: "h.p.s" } when an attached
  // orchestratorSignature must travel alongside a compact receipt.
  if (typeof input === 'object' && input !== null) {
    const obj = input as Record<string, unknown>;
    const orch =
      typeof obj.orchestratorSignature === 'string' ? obj.orchestratorSignature : null;

    if (typeof obj.detached === 'string') {
      const parts = obj.detached.split('.');
      if (
        parts.length !== 3 ||
        parts[0].length === 0 ||
        parts[1] !== '' ||
        parts[2].length === 0 ||
        !BASE64URL.test(parts[0]) ||
        !BASE64URL.test(parts[2])
      ) {
        fail('INPUT_NOT_DETACHED_JWS');
      }
      const [headerB64, , sigB64] = parts;
      const header = parseHeader(headerB64);
      let payloadBytes: Uint8Array;
      if (typeof obj.payload === 'string') {
        payloadBytes = Buffer.from(obj.payload, 'utf8');
      } else if (obj.payload instanceof Uint8Array) {
        payloadBytes = obj.payload;
      } else {
        fail('DETACHED_PAYLOAD_INVALID');
      }
      // Section 6.6: receiptId over the compact form the receipt would have.
      const compactForm = `${headerB64}.${base64urlEncode(payloadBytes!)}.${sigB64}`;
      const compactBytes = ascii(compactForm);
      return {
        kind: 'detached',
        headerB64,
        header,
        payloadBytes: payloadBytes!,
        signature: base64urlDecode(sigB64),
        signingInput: Buffer.concat([ascii(`${headerB64}.`), payloadBytes!]),
        compactBytes,
        receiptId: sha256Hex(compactBytes),
        orchestratorSignature: orch,
        raw: input,
      };
    }

    if (typeof obj.compact === 'string') {
      const parsed = parseInput(obj.compact);
      parsed.orchestratorSignature = orch;
      parsed.raw = input;
      return parsed;
    }
  }

  fail('UNRECOGNIZED_INPUT');
}

// ---------------------------------------------------------------------------
// Header validation (draft -11 section 6.1, 6.5)
// ---------------------------------------------------------------------------

function validateHeader(
  parsed: ParsedInput,
  errors: string[],
  warnings: string[],
): void {
  const { header } = parsed;
  const alg = header.alg;
  if (alg === 'none') {
    errors.push('ALG_NONE_PROHIBITED');
  } else if (alg === undefined) {
    errors.push('ALG_MISSING');
  } else if (alg !== 'ES256') {
    errors.push(`ALG_UNSUPPORTED:${String(alg)}`);
  }

  if (header.typ === undefined) {
    warnings.push('TYP_MISSING');
  } else if (header.typ !== 'drp-receipt') {
    warnings.push(`TYP_UNEXPECTED:${String(header.typ)}`);
  }

  // RFC 7515 section 4.1.11: every "crit" parameter must be understood.
  if (header.crit !== undefined) {
    if (!Array.isArray(header.crit)) {
      errors.push('CRIT_MALFORMED');
    } else {
      for (const name of header.crit) {
        if (name !== 'b64') errors.push(`CRIT_UNRECOGNIZED:${String(name)}`);
      }
    }
  }

  if (parsed.kind === 'compact' && header.b64 === false) {
    errors.push('B64_FALSE_IN_COMPACT');
  }
  if (parsed.kind === 'detached') {
    const crit = header.crit;
    if (
      header.b64 !== false ||
      !Array.isArray(crit) ||
      !crit.includes('b64')
    ) {
      errors.push('DETACHED_HEADER_INVALID');
    }
  }
}

// ---------------------------------------------------------------------------
// Body validation (draft -11 sections 4.1, 4.2, 4.5)
// ---------------------------------------------------------------------------

function validateScopeEntry(e: unknown): ScopeSchemaEntry | null {
  if (typeof e !== 'object' || e === null) return null;
  const o = e as Record<string, unknown>;
  if (typeof o.operation !== 'string' || typeof o.resource !== 'string') return null;
  const entry: ScopeSchemaEntry = { operation: o.operation, resource: o.resource };
  if (o.constraints !== undefined) {
    if (typeof o.constraints !== 'object' || o.constraints === null || Array.isArray(o.constraints)) {
      return null;
    }
    entry.constraints = o.constraints as Record<string, unknown>;
  }
  return entry;
}

function validateScopeSchema(v: unknown): ScopeSchema | null {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  if (!Array.isArray(o.allowedActions)) return null;
  const allowed: ScopeSchemaEntry[] = [];
  for (const e of o.allowedActions) {
    const entry = validateScopeEntry(e);
    if (!entry) return null;
    allowed.push(entry);
  }
  const denied: ScopeSchemaEntry[] = [];
  if (o.deniedActions !== undefined) {
    if (!Array.isArray(o.deniedActions)) return null;
    for (const e of o.deniedActions) {
      const entry = validateScopeEntry(e);
      if (!entry) return null;
      denied.push(entry);
    }
  }
  const version = o.version === undefined ? '1.0' : o.version;
  if (typeof version !== 'string') return null;
  return { version, allowedActions: allowed, deniedActions: denied };
}

// Normalization of operatorInstructions per draft -11 section 4.2:
// trim, lowercase, collapse whitespace, remove commas, remove sentence-final
// periods, remove straight and curly quotes, sort detected key-value pairs.
// The key-value detection syntax is a reference interpretation: the draft
// mandates sorting "detected" pairs but does not define the detection syntax.
export function normalizeInstructions(s: string): string {
  let t = s.trim().toLowerCase().replace(/\s+/g, ' ').replace(/,/g, '').replace(/\.+$/, '');
  t = t.replace(/['\u2018\u2019\u201c\u201d"]/g, '');
  const pairRe = /([A-Za-z_][\w-]*)\s*[:=]\s*("[^"]*"|'[^']*'|[^\s]+)/g;
  const pairs: Array<{ key: string; text: string; index: number }> = [];
  let m: RegExpExecArray | null;
  while ((m = pairRe.exec(t)) !== null) {
    pairs.push({ key: m[1], text: m[0], index: m.index });
  }
  if (pairs.length > 1) {
    const sorted = [...pairs].sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
    let out = '';
    let pos = 0;
    for (let i = 0; i < pairs.length; i++) {
      out += t.slice(pos, pairs[i].index) + sorted[i].text;
      pos = pairs[i].index + pairs[i].text.length;
    }
    out += t.slice(pos);
    t = out;
  }
  return t;
}

function validateBody(payloadBytes: Uint8Array): {
  body: ReceiptBody;
  lossy: string[];
  warnings: string[];
} {
  const errors: string[] = [];
  const warnings: string[] = [];
  const lossy: string[] = [];

  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(payloadBytes).toString('utf8'));
  } catch {
    fail('PAYLOAD_NOT_JSON');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    fail('PAYLOAD_NOT_OBJECT');
  }
  const obj = parsed as Record<string, unknown>;

  // Iman Schrock's pinned case 2 (-12 direction): authorization fields are
  // closed. An unknown top-level body field is never silently allowed —
  // extensions belong inside `metadata` (case 1). Fail fast with a dedicated
  // code rather than the generic canonicalization error.
  const unknownFields = Object.keys(obj).filter((k) => !KNOWN_BODY_FIELDS.has(k));
  if (unknownFields.length > 0) {
    fail('UNKNOWN_BODY_FIELD', unknownFields.sort().join(','));
  }
  const known: Record<string, unknown> = {};
  for (const k of Object.keys(obj)) {
    if (KNOWN_BODY_FIELDS.has(k)) known[k] = obj[k];
  }
  let canonical: string;
  try {
    canonical = jcsCanonicalize(known);
  } catch {
    fail('PAYLOAD_NOT_JCS_CANONICAL');
  }
  const canonicalBytes = Buffer.from(canonical, 'utf8');
  if (
    canonicalBytes.length !== payloadBytes.length ||
    !Buffer.from(payloadBytes).equals(canonicalBytes)
  ) {
    fail('PAYLOAD_NOT_JCS_CANONICAL');
  }

  const req = (name: string, pred: (v: unknown) => boolean, code: string): void => {
    if (!pred(known[name])) errors.push(code);
  };
  const isNonEmptyString = (v: unknown): v is string => typeof v === 'string' && v.length > 0;

  req('delegationId', isNonEmptyString, 'DELEGATION_ID_INVALID');
  req('issuedAt', isIso8601Utc, 'ISSUED_AT_INVALID');
  req('scope', (v) => typeof v === 'string', 'SCOPE_INVALID');
  req('boundaries', (v) => typeof v === 'string', 'BOUNDARIES_INVALID');
  req(
    'timeWindow',
    (v): v is { start: string; end: string } =>
      typeof v === 'object' &&
      v !== null &&
      isIso8601Utc((v as Record<string, unknown>).start) &&
      isIso8601Utc((v as Record<string, unknown>).end),
    'TIME_WINDOW_INVALID',
  );
  req('operatorInstructions', (v) => typeof v === 'string', 'OPERATOR_INSTRUCTIONS_INVALID');
  req('instructionsHash', (v) => typeof v === 'string' && HEX64.test(v), 'INSTRUCTIONS_HASH_INVALID');

  const jwk = known.signerPublicKey as Record<string, unknown> | undefined;
  let signerPublicKey: ReceiptBody['signerPublicKey'] | null = null;
  if (
    typeof jwk === 'object' &&
    jwk !== null &&
    jwk.kty === 'EC' &&
    jwk.crv === 'P-256' &&
    typeof jwk.x === 'string' &&
    jwk.x.length > 0 &&
    BASE64URL.test(jwk.x) &&
    typeof jwk.y === 'string' &&
    jwk.y.length > 0 &&
    BASE64URL.test(jwk.y)
  ) {
    signerPublicKey = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
    const extra = Object.keys(jwk).filter((k) => !['kty', 'crv', 'x', 'y'].includes(k));
    if (extra.length > 0) warnings.push(`SIGNER_JWK_EXTRA_MEMBERS:${extra.sort().join(',')}`);
  } else {
    errors.push('SIGNER_PUBLIC_KEY_INVALID');
  }

  let agentId: string | null = null;
  if (known.agentId !== undefined) {
    if (typeof known.agentId === 'string') agentId = known.agentId;
    else warnings.push('AGENT_ID_IGNORED');
  }

  let parentReceiptId: string | null = null;
  if (known.parentReceiptId !== undefined) {
    if (typeof known.parentReceiptId === 'string') parentReceiptId = known.parentReceiptId;
    else errors.push('PARENT_RECEIPT_ID_INVALID');
  }

  let scopeSchema: ScopeSchema | null = null;
  if (known.scopeSchema !== undefined) {
    const s = validateScopeSchema(known.scopeSchema);
    if (!s) errors.push('SCOPE_SCHEMA_INVALID');
    else scopeSchema = s;
  }

  if (errors.length > 0) {
    fail(errors.join('; '));
  }

  const body: ReceiptBody = {
    delegationId: known.delegationId as string,
    issuedAt: known.issuedAt as string,
    scope: known.scope as string,
    boundaries: known.boundaries as string,
    timeWindow: known.timeWindow as { start: string; end: string },
    operatorInstructions: known.operatorInstructions as string,
    instructionsHash: known.instructionsHash as string,
    signerPublicKey: signerPublicKey!,
    agentId,
    parentReceiptId,
    revocationRequired: known.revocationRequired === true,
    oneTimeUse: known.oneTimeUse === true,
    scopeSchema,
  };

  // Warning-only consistency check: the instructionsHash is SHA-256 over the
  // normalized instructions. A mismatch cannot survive signature verification
  // when the issuer computed it honestly, so this flags issuer-side drift.
  const recomputed = sha256Hex(Buffer.from(normalizeInstructions(body.operatorInstructions), 'utf8'));
  if (recomputed !== body.instructionsHash) {
    warnings.push('INSTRUCTIONS_HASH_MISMATCH');
  }

  return { body, lossy, warnings };
}

// ---------------------------------------------------------------------------
// Normalization to the shared model
// ---------------------------------------------------------------------------

function mapScope(body: ReceiptBody, lossy: string[]): ScopeExpression {
  const schema = body.scopeSchema;
  if (!schema) {
    // Draft -11 section 8.4: text scope is advisory, never enforced.
    return {
      kind: 'text',
      actions: [],
      resources: [],
      constraints: {},
      text: body.scope,
      enforced: false,
    };
  }
  const actions = schema.allowedActions.map((e) => e.operation);
  const resources = schema.allowedActions.map((e) => e.resource);
  const constraints: Record<string, unknown> = {};
  for (const e of schema.allowedActions) {
    if (e.constraints !== undefined) {
      constraints[`${e.operation}::${e.resource}`] = e.constraints;
    }
  }
  // The shared model has no denied-actions slot; each denial is preserved as
  // a machine-readable lossy note so chain attenuation checks can recover it.
  for (const e of schema.deniedActions) {
    lossy.push(`DENIED:${e.operation}::${e.resource}`);
  }
  return { kind: 'structured', actions, resources, constraints, text: null, enforced: true };
}

function buildNormalized(
  parsed: ParsedInput,
  body: ReceiptBody,
  lossy: string[],
): NormalizedReceipt {
  const scope = mapScope(body, lossy);

  const boundaries: string[] = body.boundaries
    .split(/[\n;]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  if (/[\n;]/.test(body.boundaries)) {
    lossy.push('BOUNDARIES_SPLIT_ON_NEWLINES_AND_SEMICOLONS');
  }

  return {
    format: 'authproof-jws',
    receiptId: parsed.receiptId,
    // The issuer is identified by the RFC 7638 thumbprint of the signing key.
    issuer: ecJwkThumbprint(body.signerPublicKey),
    issuerKey: {
      kty: body.signerPublicKey.kty,
      crv: body.signerPublicKey.crv,
      x: body.signerPublicKey.x,
      y: body.signerPublicKey.y,
    },
    agent: body.agentId,
    scope,
    boundaries,
    notBefore: body.timeWindow.start,
    notAfter: body.timeWindow.end,
    instructionsHash: body.instructionsHash,
    parentId: body.parentReceiptId,
    // Revocation distribution is out of scope for this library (draft -11
    // section 14); without a registry, status is always unknown.
    revocation: { required: body.revocationRequired, pointer: null, status: 'unknown' },
    raw: parsed.raw,
    lossy,
  };
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

function verifySignature(parsed: ParsedInput, body: ReceiptBody, errors: string[]): void {
  const sig = parsed.signature;
  if (sig.length !== 64) {
    // Section 6.3: DER-encoded signatures are the pre-11 format and must be
    // rejected; they are never valid -11 JWS.
    if (sig.length > 0 && sig[0] === 0x30) {
      errors.push('DER_SIGNATURE_REJECTED');
    } else {
      errors.push('SIGNATURE_MALFORMED');
    }
    return;
  }
  const ok = es256Verify(
    { x: body.signerPublicKey.x, y: body.signerPublicKey.y },
    parsed.signingInput,
    sig,
  );
  if (!ok) errors.push('SIGNATURE_INVALID');
}

// Verifies an attached orchestratorSignature: a compact JWS whose payload is
// the exact ASCII binding string
// "orchestrator-delegation:<parentReceiptId>:<receiptId>" (draft -11 section
// 4.4), signed by the parent receipt's key. Exported for verifyChain.
export function verifyOrchestratorSignature(
  parent: NormalizedReceipt,
  child: NormalizedReceipt,
  orchJws: string,
): boolean {
  try {
    if (child.parentId === null || child.parentId !== parent.receiptId) return false;
    const parts = orchJws.split('.');
    if (parts.length !== 3 || parts.some((p) => p.length === 0)) return false;
    const header = JSON.parse(Buffer.from(base64urlDecode(parts[0])).toString('utf8')) as {
      alg?: unknown;
    };
    if (header.alg !== 'ES256') return false;
    const sig = base64urlDecode(parts[2]);
    if (sig.length !== 64) return false;
    const payloadText = Buffer.from(base64urlDecode(parts[1])).toString('utf8');
    const expected = `orchestrator-delegation:${child.parentId}:${child.receiptId}`;
    if (payloadText !== expected) return false;
    return es256Verify(
      { x: parent.issuerKey.x, y: parent.issuerKey.y as string },
      ascii(`${parts[0]}.${parts[1]}`),
      sig,
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// FormatVerifier implementation
// ---------------------------------------------------------------------------

function detect(input: unknown): boolean {
  try {
    if (typeof input === 'string') {
      const parts = input.split('.');
      if (parts.length !== 3 || parts.some((p) => p.length === 0)) return false;
      const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
      return typeof header === 'object' && header !== null && !Array.isArray(header)
        ? (header as { alg?: unknown }).alg === 'ES256'
        : false;
    }
    if (typeof input === 'object' && input !== null) {
      const obj = input as Record<string, unknown>;
      if (typeof obj.detached === 'string') {
        const parts = obj.detached.split('.');
        if (parts.length !== 3 || parts[0].length === 0 || parts[1] !== '' || parts[2].length === 0) {
          return false;
        }
        if (!(typeof obj.payload === 'string' || obj.payload instanceof Uint8Array)) return false;
        const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
        return (
          typeof header === 'object' &&
          header !== null &&
          (header as { alg?: unknown }).alg === 'ES256'
        );
      }
      if (typeof obj.compact === 'string') {
        return detect(obj.compact);
      }
    }
    return false;
  } catch {
    return false;
  }
}

export function normalizeAuthproof(input: unknown): NormalizedReceipt {
  const parsed = parseInput(input); // throws Error on unparseable input
  const { body, lossy, warnings } = validateBody(parsed.payloadBytes); // throws Error on invalid body
  return buildNormalized(parsed, body, [...lossy, ...warnings]);
}

interface VerifyExtension {
  parentReceipt?: unknown;
}

async function verifyAuthproof(input: unknown, opts: VerifyOptions): Promise<Verdict> {
  const errors: string[] = [];
  const warnings: string[] = [];
  const at = opts.at ?? new Date();

  let parsed: ParsedInput;
  try {
    parsed = parseInput(input);
  } catch (e) {
    return {
      valid: false,
      format: 'authproof-jws',
      receipt: null,
      errors: [(e as Error).message],
      warnings,
    };
  }

  validateHeader(parsed, errors, warnings);

  let body: ReceiptBody | null = null;
  let lossy: string[] = [];
  try {
    const validated = validateBody(parsed.payloadBytes);
    body = validated.body;
    lossy = [...validated.lossy, ...validated.warnings];
    warnings.push(...validated.warnings);
  } catch (e) {
    for (const code of String((e as Error).message).split('; ')) {
      if (code) errors.push(code);
    }
  }

  let receipt: NormalizedReceipt | null = null;
  if (body) {
    verifySignature(parsed, body, errors);
    receipt = buildNormalized(parsed, body, lossy);

    // Time window: start <= at < end.
    const startMs = Date.parse(body.timeWindow.start);
    const endMs = Date.parse(body.timeWindow.end);
    const atMs = at.getTime();
    if (!(startMs <= atMs && atMs < endMs)) {
      errors.push('TIME_WINDOW');
    }

    // Revocation: this library ships no registry (distribution is out of
    // scope per draft -11 section 14), so fail closed when a check is asked
    // for on a receipt that requires one (section 9.4).
    if (body.revocationRequired && opts.checkRevocation) {
      errors.push('REVOCATION_CHECK_REQUIRED');
    } else if (body.revocationRequired) {
      warnings.push('REVOCATION_REQUIRED_BUT_UNCHECKED');
    }

    // Issuer trust.
    if (opts.trustedIssuers !== undefined && opts.trustedIssuers.length > 0) {
      if (!opts.trustedIssuers.includes(receipt.issuer)) {
        errors.push('ISSUER_NOT_TRUSTED');
      }
    }

    // Sub-receipt: the orchestrator signature binds parent and child keys.
    // In a single verify() call the parent key is unavailable, so the check
    // is deferred to verifyChain (warning). Callers may supply the parent
    // receipt input via opts.parentReceipt to resolve it here.
    if (body.parentReceiptId !== null) {
      const parentInput = (opts as VerifyExtension).parentReceipt;
      if (parentInput !== undefined) {
        try {
          const parentReceipt = normalizeAuthproof(parentInput);
          if (parentReceipt.receiptId !== body.parentReceiptId) {
            errors.push('PARENT_LINK_MISMATCH');
          } else if (parsed.orchestratorSignature === null) {
            errors.push('ORCHESTRATOR_SIG_MISSING');
          } else if (
            !verifyOrchestratorSignature(parentReceipt, receipt, parsed.orchestratorSignature)
          ) {
            errors.push('ORCHESTRATOR_SIG_INVALID');
          }
        } catch (e) {
          errors.push(`PARENT_RECEIPT_INVALID:${(e as Error).message}`);
        }
      } else {
        warnings.push('ORCHESTRATOR_SIG_DEFERRED_TO_CHAIN');
      }
    }

    // Draft -11 section 9.5 / Iman Schrock's pinned case 3: one-time-use
    // receipts require a durable, shared consumption store, and consumption
    // is attempted only after every other check has passed. This verifier
    // ships no consumption store, so fail closed: a receipt demanding
    // single consumption must never verify as authorizing here.
    if (body.oneTimeUse) {
      errors.push('CONSUMPTION_STORE_REQUIRED');
    }
  }

  return { valid: errors.length === 0, format: 'authproof-jws', receipt, errors, warnings };
}

export const authproofJws: FormatVerifier = {
  id: 'authproof-jws',
  detect,
  verify: (input, opts) => verifyAuthproof(input, opts),
  normalize: (input) => normalizeAuthproof(input),
};

// COSE profile (draft -11 section 7): recognized so it is never mistaken for
// an unknown or JWS input, but explicitly not implemented. verify() reports
// the gap instead of faking a result.
export const authproofCose: FormatVerifier = {
  id: 'authproof-cose',
  detect(input: unknown): boolean {
    // COSE_Sign1 is CBOR tag 18 (0xD2) wrapping a 4-element array (0x84).
    return (
      input instanceof Uint8Array && input.length >= 2 && input[0] === 0xd2 && input[1] === 0x84
    );
  },
  async verify(): Promise<Verdict> {
    return {
      valid: false,
      format: 'authproof-cose',
      receipt: null,
      errors: ['COSE_NOT_IMPLEMENTED'],
      warnings: [],
    };
  },
  normalize(): NormalizedReceipt {
    throw new Error('COSE_NOT_IMPLEMENTED');
  },
};

export type { FormatId };
