#!/usr/bin/env node
// ---------------------------------------------------------------------------
// Conformance-vector minter for the JWS receipt profile of
// draft-nelson-agent-delegation-receipts-11 (sections 4, 5, 6, 8, 9).
//
// EVERY vector is minted with real ES256 signatures from throwaway P-256
// keys generated fresh on each run. These keys are single-purpose test
// material: they MUST NOT be used for anything real, and nothing here
// hand-writes a signature or hash.
//
// Expected receipt fields (receiptId, issuer thumbprint, ...) are derived
// through the reference implementation's own crypto (normalize()), so each
// vectors.json is self-consistent with src/.
//
// Run:  npx tsx test-vectors/generate-vectors.mjs
// ---------------------------------------------------------------------------

import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { generateKeyPairSync, sign } from 'node:crypto';
import {
  base64urlEncode,
  jcsCanonicalize,
  sha256Hex,
  ecJwkThumbprint,
  normalizeInstructions,
  normalize,
} from '../src/index.ts';

const HERE = dirname(fileURLToPath(import.meta.url));

// Fixed, pinned timestamps. Verification "now" is always AT, so vectors
// never rot.
const ISSUED = '2026-10-09T12:00:00.000Z';
const W0 = '2026-10-09T12:00:00.000Z';
const W1 = '2026-10-09T13:00:00.000Z';
const AT = '2026-10-09T12:30:00.000Z';
const INSTR = "Read today's calendar events and draft a summary for the 2pm standup.";

// ---------------------------------------------------------------------------
// Minting helpers (mirror the draft's issuance rules)
// ---------------------------------------------------------------------------

function genKey() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { priv: privateKey, pub: publicKey.export({ format: 'jwk' }) };
}

function baseBody(pub, overrides = {}) {
  return {
    delegationId: 'tv-base',
    issuedAt: ISSUED,
    scope: 'read calendar events and draft meeting summaries',
    boundaries: 'never send email without explicit confirmation',
    timeWindow: { start: W0, end: W1 },
    operatorInstructions: INSTR,
    instructionsHash: sha256Hex(Buffer.from(normalizeInstructions(INSTR), 'utf8')),
    signerPublicKey: pub,
    ...overrides,
  };
}

const HDR = { alg: 'ES256', typ: 'drp-receipt' };

function b64uJson(v) {
  return base64urlEncode(Buffer.from(JSON.stringify(v), 'utf8'));
}

function makeCompact(bodyObj, priv, header = HDR, opts = {}) {
  const headerB64 = b64uJson(header);
  const payloadBytes = opts.rawPayload ?? Buffer.from(jcsCanonicalize(bodyObj), 'utf8');
  const payloadB64 = base64urlEncode(payloadBytes);
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, 'ascii');
  const sig = opts.der
    ? sign('sha256', signingInput, priv)
    : sign('sha256', signingInput, { key: priv, dsaEncoding: 'ieee-p1363' });
  return `${headerB64}.${payloadB64}.${base64urlEncode(sig)}`;
}

function makeDetached(bodyObj, priv, header = { alg: 'ES256', b64: false, crit: ['b64'] }) {
  const headerB64 = b64uJson(header);
  const payloadBytes = Buffer.from(jcsCanonicalize(bodyObj), 'utf8');
  const signingInput = Buffer.concat([Buffer.from(`${headerB64}.`, 'ascii'), payloadBytes]);
  const sig = sign('sha256', signingInput, { key: priv, dsaEncoding: 'ieee-p1363' });
  return {
    detached: `${headerB64}..${base64urlEncode(sig)}`,
    payload_b64: payloadBytes.toString('base64'),
  };
}

function makeOrchestratorSig(parentPriv, parentId, childId) {
  const binding = `orchestrator-delegation:${parentId}:${childId}`;
  const headerB64 = b64uJson({ alg: 'ES256' });
  const payloadB64 = base64urlEncode(Buffer.from(binding, 'utf8'));
  const sig = sign('sha256', Buffer.from(`${headerB64}.${payloadB64}`, 'ascii'), {
    key: parentPriv,
    dsaEncoding: 'ieee-p1363',
  });
  return `${headerB64}.${payloadB64}.${base64urlEncode(sig)}`;
}

// Decode a vectors.json-style input back into the library's input shape.
function decodeInput(inp) {
  if (typeof inp === 'string') return inp;
  const out = {};
  if (inp.compact) out.compact = inp.compact;
  if (inp.detached) out.detached = inp.detached;
  if (inp.payload_b64) out.payload = Buffer.from(inp.payload_b64, 'base64');
  if (inp.orchestratorSignature) out.orchestratorSignature = inp.orchestratorSignature;
  return out;
}

// Expected receipt spot-checks, derived via the reference implementation.
function receiptSpotChecks(inp) {
  const n = normalize(decodeInput(inp));
  return {
    receiptId: n.receiptId,
    issuer: n.issuer,
    parentId: n.parentId,
    scopeKind: n.scope.kind,
    agent: n.agent,
    revocationRequired: n.revocation.required,
  };
}

function scope3() {
  return {
    version: '1.0',
    allowedActions: [
      { operation: 'read', resource: 'calendar/events' },
      { operation: 'write', resource: 'calendar/drafts' },
      { operation: 'delete', resource: 'calendar/archive' },
    ],
    deniedActions: [{ operation: 'delete', resource: 'calendar/events' }],
  };
}

// ---------------------------------------------------------------------------
// Vector builders
// ---------------------------------------------------------------------------

const vectors = [];
function V(v) {
  vectors.push(v);
  return v;
}
const OPTS = { at: AT, checkRevocation: false };

// --- Valid single receipts ------------------------------------------------

{
  const k = genKey();
  const compact = makeCompact({ ...baseBody(k.pub), delegationId: 'tv-valid-compact-01' }, k.priv);
  V({
    id: 'valid-compact-text-scope',
    category: 'valid',
    description:
      'Minimal valid compact JWS receipt (ES256, JCS payload, text scope). Draft 6.3.',
    profile: 'jws-compact',
    mode: 'receipt',
    draftSection: '6.3',
    input: compact,
    options: { ...OPTS },
    expect: {
      valid: true,
      format: 'authproof-jws',
      errors: [],
      warnings: [],
      receipt: receiptSpotChecks(compact),
    },
  });
}

{
  const k = genKey();
  const bodyObj = {
    ...baseBody(k.pub),
    delegationId: 'tv-valid-compact-02',
    agentId: 'calendar-agent-01',
    metadata: { session: 'tv-002' },
    trustedSources: ['user', 'system_prompt'],
    scopeSchema: {
      version: '1.0',
      allowedActions: [
        { operation: 'read', resource: 'calendar/events' },
        { operation: 'write', resource: 'calendar/drafts', constraints: { maxEvents: 10 } },
      ],
      deniedActions: [{ operation: 'delete', resource: 'calendar/events' }],
    },
  };
  const compact = makeCompact(bodyObj, k.priv);
  V({
    id: 'valid-compact-structured-scope',
    category: 'valid',
    description:
      'Valid compact receipt with enforced structured scopeSchema (constraints + deniedActions), agentId, metadata, trustedSources. Draft 4.3, 4.5, 8.1.',
    profile: 'jws-compact',
    mode: 'receipt',
    draftSection: '4.5',
    input: compact,
    options: { ...OPTS },
    expect: {
      valid: true,
      format: 'authproof-jws',
      errors: [],
      warnings: [],
      receipt: receiptSpotChecks(compact),
    },
  });
}

{
  const k = genKey();
  const compact = makeCompact(
    { ...baseBody(k.pub), delegationId: 'tv-valid-compact-03' },
    k.priv,
    { alg: 'ES256' },
  );
  V({
    id: 'valid-compact-typ-missing',
    category: 'valid',
    description:
      'Valid compact receipt whose header omits "typ" (SHOULD, not MUST): still valid, TYP_MISSING warning. Draft 6.1.',
    profile: 'jws-compact',
    mode: 'receipt',
    draftSection: '6.1',
    input: compact,
    options: { ...OPTS },
    expect: {
      valid: true,
      format: 'authproof-jws',
      errors: [],
      warnings: ['TYP_MISSING'],
      receipt: receiptSpotChecks(compact),
    },
  });
}

{
  const k = genKey();
  const compact = makeCompact(
    { ...baseBody(k.pub), delegationId: 'tv-valid-compact-04' },
    k.priv,
    { alg: 'ES256', typ: 'drp-receipt', kid: 'throwaway-key-1' },
  );
  V({
    id: 'valid-compact-with-kid',
    category: 'valid',
    description:
      'Valid compact receipt carrying an optional "kid" header parameter. Draft 6.1.',
    profile: 'jws-compact',
    mode: 'receipt',
    draftSection: '6.1',
    input: compact,
    options: { ...OPTS },
    expect: {
      valid: true,
      format: 'authproof-jws',
      errors: [],
      warnings: [],
      receipt: receiptSpotChecks(compact),
    },
  });
}

{
  const k = genKey();
  const bodyObj = {
    ...baseBody(k.pub),
    delegationId: 'tv-valid-compact-05',
    instructionsHash: '0'.repeat(64), // well-formed hex64, but wrong digest
  };
  const compact = makeCompact(bodyObj, k.priv);
  V({
    id: 'valid-compact-instructions-hash-mismatch-warning',
    category: 'valid',
    description:
      'Signature is over the stated body, but the committed instructionsHash does not match the normalized instructions: valid signature, INSTRUCTIONS_HASH_MISMATCH warning (issuer-side drift flag). Draft 4.2.',
    profile: 'jws-compact',
    mode: 'receipt',
    draftSection: '4.2',
    input: compact,
    options: { ...OPTS },
    expect: {
      valid: true,
      format: 'authproof-jws',
      errors: [],
      warnings: ['INSTRUCTIONS_HASH_MISMATCH'],
      receipt: receiptSpotChecks(compact),
    },
  });
}

{
  const k = genKey();
  const bodyObj = {
    ...baseBody(k.pub),
    delegationId: 'tv-valid-compact-06',
    revocationRequired: true,
  };
  const compact = makeCompact(bodyObj, k.priv);
  V({
    id: 'valid-compact-revocation-required-unchecked',
    category: 'valid',
    description:
      'Receipt with revocationRequired:true verified without a registry check (checkRevocation=false): valid, with REVOCATION_REQUIRED_BUT_UNCHECKED warning. Draft 9.4.',
    profile: 'jws-compact',
    mode: 'receipt',
    draftSection: '9.4',
    input: compact,
    options: { ...OPTS, checkRevocation: false },
    expect: {
      valid: true,
      format: 'authproof-jws',
      errors: [],
      warnings: ['REVOCATION_REQUIRED_BUT_UNCHECKED'],
      receipt: receiptSpotChecks(compact),
    },
  });
}

{
  const k = genKey();
  const det = makeDetached({ ...baseBody(k.pub), delegationId: 'tv-valid-detached-01' }, k.priv);
  V({
    id: 'valid-detached',
    category: 'valid',
    description:
      'Valid RFC 7797 detached JWS: header carries b64:false with crit:["b64"], signing input is ASCII(headerB64 || "." || raw JCS payload), transmission form is header..signature with the payload supplied out of band. Draft 6.4.',
    profile: 'jws-detached',
    mode: 'receipt',
    draftSection: '6.4',
    input: det,
    options: { ...OPTS },
    expect: {
      valid: true,
      format: 'authproof-jws',
      errors: [],
      warnings: ['TYP_MISSING'], // detached test header omits "typ" (SHOULD, not MUST)
      receipt: receiptSpotChecks(det),
    },
  });
}

// --- Signature failures ----------------------------------------------------

{
  const k = genKey();
  const other = genKey();
  const compact = makeCompact({ ...baseBody(k.pub), delegationId: 'tv-sig-01' }, other.priv);
  V({
    id: 'invalid-signature-wrong-key',
    category: 'signature',
    description:
      'Payload and header well-formed, but the signature was made by a different P-256 key: SIGNATURE_INVALID. Draft 6.3, 10 (check 1).',
    profile: 'jws-compact',
    mode: 'receipt',
    draftSection: '6.3',
    input: compact,
    options: { ...OPTS },
    expect: { valid: false, format: 'authproof-jws', errors: ['SIGNATURE_INVALID'], warnings: [] },
  });
}

{
  const k = genKey();
  const compact = makeCompact({ ...baseBody(k.pub), delegationId: 'tv-sig-02' }, k.priv, HDR, {
    der: true,
  });
  V({
    id: 'der-signature-rejected',
    category: 'signature',
    description:
      'Genuine ECDSA signature but DER-encoded (the pre-11 format): verifiers MUST reject it; DER_SIGNATURE_REJECTED. Draft 6.3.',
    profile: 'jws-compact',
    mode: 'receipt',
    draftSection: '6.3',
    input: compact,
    options: { ...OPTS },
    expect: {
      valid: false,
      format: 'authproof-jws',
      errors: ['DER_SIGNATURE_REJECTED'],
      warnings: [],
    },
  });
}

{
  const k = genKey();
  const good = makeCompact({ ...baseBody(k.pub), delegationId: 'tv-sig-03' }, k.priv);
  const parts = good.split('.');
  parts[2] = base64urlEncode(Buffer.alloc(32)); // 32 zero bytes: not 64, not DER
  const compact = parts.join('.');
  V({
    id: 'signature-malformed',
    category: 'signature',
    description:
      'Signature segment decodes to 32 bytes (neither the 64-byte raw R||S nor DER): SIGNATURE_MALFORMED. Draft 6.3.',
    profile: 'jws-compact',
    mode: 'receipt',
    draftSection: '6.3',
    input: compact,
    options: { ...OPTS },
    expect: {
      valid: false,
      format: 'authproof-jws',
      errors: ['SIGNATURE_MALFORMED'],
      warnings: [],
    },
  });
}

{
  const k = genKey();
  const compact = makeCompact(
    { ...baseBody(k.pub), delegationId: 'tv-sig-04' },
    k.priv,
    { alg: 'none', typ: 'drp-receipt' },
  );
  V({
    id: 'alg-none-prohibited',
    category: 'signature',
    description:
      'INTEROP NOTE: "alg":"none" is PROHIBITED by draft 6.5 and the reference verifier defines an ALG_NONE_PROHIBITED code, but its format detector only claims ES256 JWS inputs, so through the public API this input is rejected one layer earlier as UNKNOWN_FORMAT. The normative requirement is the denial; the exact error code is implementation-defined.',
    profile: 'jws-compact',
    mode: 'receipt',
    draftSection: '6.5',
    input: compact,
    options: { ...OPTS },
    expect: {
      valid: false,
      format: 'unknown',
      errors: ['UNKNOWN_FORMAT'],
      warnings: [],
    },
  });
}

{
  const k = genKey();
  const compact = makeCompact(
    { ...baseBody(k.pub), delegationId: 'tv-sig-05' },
    k.priv,
    { alg: 'RS256', typ: 'drp-receipt' },
  );
  V({
    id: 'alg-unsupported',
    category: 'signature',
    description:
      'INTEROP NOTE: header names an algorithm outside this verifier\'s registry (RS256). As with alg:none, the reference verifier\'s detector only claims ES256 inputs, so the public API rejects this as UNKNOWN_FORMAT rather than with its internal ALG_UNSUPPORTED code. The normative requirement (draft 6.5) is denial of non-ES256 algs; the exact code is implementation-defined.',
    profile: 'jws-compact',
    mode: 'receipt',
    draftSection: '6.5',
    input: compact,
    options: { ...OPTS },
    expect: {
      valid: false,
      format: 'unknown',
      errors: ['UNKNOWN_FORMAT'],
      warnings: [],
    },
  });
}

// --- Payload / body failures -----------------------------------------------

{
  const k = genKey();
  const good = makeCompact({ ...baseBody(k.pub), delegationId: 'tv-body-01' }, k.priv);
  const [h, p, s] = good.split('.');
  const tamperedBody = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
  tamperedBody.scope = 'read calendar events, delete everything, and exfiltrate';
  const p2 = base64urlEncode(Buffer.from(jcsCanonicalize(tamperedBody), 'utf8'));
  V({
    id: 'tampered-payload',
    category: 'body',
    description:
      'Scope text altered after signing (payload still canonical JSON): the signature no longer covers the payload; SIGNATURE_INVALID. Draft 5, 10 (check 1).',
    profile: 'jws-compact',
    mode: 'receipt',
    draftSection: '5',
    input: `${h}.${p2}.${s}`,
    options: { ...OPTS },
    expect: { valid: false, format: 'authproof-jws', errors: ['SIGNATURE_INVALID'], warnings: [] },
  });
}

{
  const k = genKey();
  const bodyObj = { ...baseBody(k.pub), delegationId: 'tv-body-02' };
  // Valid JSON but NOT JCS: keys in reverse insertion order.
  const rawPayload = Buffer.from(
    JSON.stringify(Object.fromEntries(Object.entries(bodyObj).reverse())),
    'utf8',
  );
  const compact = makeCompact(bodyObj, k.priv, HDR, { rawPayload });
  V({
    id: 'payload-not-canonical',
    category: 'body',
    description:
      'Payload is valid JSON but not RFC 8785 canonical (keys unsorted), signed anyway: PAYLOAD_NOT_JCS_CANONICAL. Draft 5.',
    profile: 'jws-compact',
    mode: 'receipt',
    draftSection: '5',
    input: compact,
    options: { ...OPTS },
    expect: {
      valid: false,
      format: 'authproof-jws',
      errors: ['PAYLOAD_NOT_JCS_CANONICAL'],
      warnings: [],
    },
  });
}

{
  const k = genKey();
  const good = makeCompact({ ...baseBody(k.pub), delegationId: 'tv-body-03' }, k.priv);
  const [h, , s] = good.split('.');
  const notJson = base64urlEncode(Buffer.from('this is not json {', 'utf8'));
  V({
    id: 'payload-not-json',
    category: 'body',
    description: 'Payload segment is not JSON at all: PAYLOAD_NOT_JSON. Draft 6.2.',
    profile: 'jws-compact',
    mode: 'receipt',
    draftSection: '6.2',
    input: `${h}.${notJson}.${s}`,
    options: { ...OPTS },
    expect: { valid: false, format: 'authproof-jws', errors: ['PAYLOAD_NOT_JSON'], warnings: [] },
  });
}

{
  const k = genKey();
  const { delegationId: _d, ...rest } = baseBody(k.pub);
  void _d;
  const compact = makeCompact(rest, k.priv);
  V({
    id: 'missing-delegation-id',
    category: 'body',
    description: 'Required field delegationId absent: DELEGATION_ID_INVALID. Draft 4.2.',
    profile: 'jws-compact',
    mode: 'receipt',
    draftSection: '4.2',
    input: compact,
    options: { ...OPTS },
    expect: {
      valid: false,
      format: 'authproof-jws',
      errors: ['DELEGATION_ID_INVALID'],
      warnings: [],
    },
  });
}

{
  const k = genKey();
  const compact = makeCompact(
    { ...baseBody(k.pub), delegationId: 'tv-body-04', instructionsHash: 'not-a-sha256-digest' },
    k.priv,
  );
  V({
    id: 'bad-instructions-hash-format',
    category: 'body',
    description:
      'instructionsHash is not 64 lowercase hex characters: INSTRUCTIONS_HASH_INVALID. Draft 4.2.',
    profile: 'jws-compact',
    mode: 'receipt',
    draftSection: '4.2',
    input: compact,
    options: { ...OPTS },
    expect: {
      valid: false,
      format: 'authproof-jws',
      errors: ['INSTRUCTIONS_HASH_INVALID'],
      warnings: [],
    },
  });
}

{
  const k = genKey();
  const compact = makeCompact(
    {
      ...baseBody(k.pub),
      delegationId: 'tv-body-05',
      timeWindow: { start: W0, end: 'sometime-later' },
    },
    k.priv,
  );
  V({
    id: 'bad-time-window',
    category: 'body',
    description: 'timeWindow.end is not an ISO 8601 UTC timestamp: TIME_WINDOW_INVALID. Draft 4.2.',
    profile: 'jws-compact',
    mode: 'receipt',
    draftSection: '4.2',
    input: compact,
    options: { ...OPTS },
    expect: {
      valid: false,
      format: 'authproof-jws',
      errors: ['TIME_WINDOW_INVALID'],
      warnings: [],
    },
  });
}

{
  const k = genKey();
  const compact = makeCompact(
    {
      ...baseBody(k.pub),
      delegationId: 'tv-body-06',
      signerPublicKey: { ...k.pub, crv: 'P-384' },
    },
    k.priv,
  );
  V({
    id: 'bad-signer-key',
    category: 'body',
    description:
      'signerPublicKey carries crv P-384, mismatching the ES256 profile: SIGNER_PUBLIC_KEY_INVALID. Draft 4.2, 6.5.',
    profile: 'jws-compact',
    mode: 'receipt',
    draftSection: '4.2',
    input: compact,
    options: { ...OPTS },
    expect: {
      valid: false,
      format: 'authproof-jws',
      errors: ['SIGNER_PUBLIC_KEY_INVALID'],
      warnings: [],
    },
  });
}

{
  const k = genKey();
  const compact = makeCompact(
    {
      ...baseBody(k.pub),
      delegationId: 'tv-body-07',
      scopeSchema: { version: '1.0', allowedActions: 'everything' },
    },
    k.priv,
  );
  V({
    id: 'bad-scope-schema',
    category: 'body',
    description: 'scopeSchema.allowedActions is not an array: SCOPE_SCHEMA_INVALID. Draft 4.5.',
    profile: 'jws-compact',
    mode: 'receipt',
    draftSection: '4.5',
    input: compact,
    options: { ...OPTS },
    expect: {
      valid: false,
      format: 'authproof-jws',
      errors: ['SCOPE_SCHEMA_INVALID'],
      warnings: [],
    },
  });
}

{
  const k = genKey();
  // Draft 4.1 says verifiers MUST ignore unknown fields, but ALSO that they
  // MUST NOT appear in the canonicalized signing input — so the reference
  // verifier requires the payload to be byte-identical to JCS(known fields
  // only). A payload that still carries an unknown field fails here.
  const compact = makeCompact(
    { ...baseBody(k.pub), delegationId: 'tv-body-08', vendorNote: 'hello' },
    k.priv,
  );
  V({
    id: 'unknown-field-in-payload-rejected',
    category: 'body',
    description:
      'INTEROP NOTE: payload carries an unknown field. Draft 4.1 tells signers to strip unknown fields before canonicalization and tells verifiers to ignore them; the reference verifier enforces the signer rule strictly and rejects the payload as non-canonical (PAYLOAD_NOT_JCS_CANONICAL) rather than ignoring the field. Independent implementations should decide which reading they follow and document it.',
    profile: 'jws-compact',
    mode: 'receipt',
    draftSection: '4.1',
    input: compact,
    options: { ...OPTS },
    expect: {
      valid: false,
      format: 'authproof-jws',
      errors: ['PAYLOAD_NOT_JCS_CANONICAL'],
      warnings: [],
    },
  });
}

// --- Header failures ---------------------------------------------------------

{
  const k = genKey();
  const compact = makeCompact(
    { ...baseBody(k.pub), delegationId: 'tv-hdr-01' },
    k.priv,
    { alg: 'ES256', typ: 'drp-receipt', b64: false },
  );
  V({
    id: 'compact-b64-false',
    category: 'header',
    description:
      'Compact serialization carrying b64:false (the unencoded-payload option) is invalid outside the detached form: B64_FALSE_IN_COMPACT. Draft 6.3, 6.4.',
    profile: 'jws-compact',
    mode: 'receipt',
    draftSection: '6.4',
    input: compact,
    options: { ...OPTS },
    expect: {
      valid: false,
      format: 'authproof-jws',
      errors: ['B64_FALSE_IN_COMPACT'],
      warnings: [],
    },
  });
}

{
  const k = genKey();
  const det = makeDetached(
    { ...baseBody(k.pub), delegationId: 'tv-hdr-02' },
    k.priv,
    { alg: 'ES256', typ: 'drp-receipt' }, // missing b64:false + crit:["b64"]
  );
  V({
    id: 'detached-header-invalid',
    category: 'header',
    description:
      'Detached form whose protected header lacks b64:false with crit:["b64"]: DETACHED_HEADER_INVALID. Draft 6.4.',
    profile: 'jws-detached',
    mode: 'receipt',
    draftSection: '6.4',
    input: det,
    options: { ...OPTS },
    expect: {
      valid: false,
      format: 'authproof-jws',
      errors: ['DETACHED_HEADER_INVALID'],
      warnings: [],
    },
  });
}

{
  const k = genKey();
  const compact = makeCompact(
    { ...baseBody(k.pub), delegationId: 'tv-hdr-03' },
    k.priv,
    { alg: 'ES256', typ: 'drp-receipt', crit: ['x-custom'] },
  );
  V({
    id: 'crit-unrecognized',
    category: 'header',
    description:
      'Header "crit" lists a parameter this verifier does not understand: CRIT_UNRECOGNIZED. RFC 7515 4.1.11, draft 6.1.',
    profile: 'jws-compact',
    mode: 'receipt',
    draftSection: '6.1',
    input: compact,
    options: { ...OPTS },
    expect: {
      valid: false,
      format: 'authproof-jws',
      errors: ['CRIT_UNRECOGNIZED'],
      warnings: [],
    },
  });
}

// --- Time window -------------------------------------------------------------

{
  const k = genKey();
  const compact = makeCompact(
    {
      ...baseBody(k.pub),
      delegationId: 'tv-time-01',
      timeWindow: { start: '2026-10-09T10:00:00.000Z', end: '2026-10-09T12:00:00.000Z' },
    },
    k.priv,
  );
  V({
    id: 'expired',
    category: 'time',
    description:
      'Verification time (12:30Z) is after the window end (12:00Z): TIME_WINDOW. Draft 4.2, 10 (check 3).',
    profile: 'jws-compact',
    mode: 'receipt',
    draftSection: '4.2',
    input: compact,
    options: { ...OPTS },
    expect: { valid: false, format: 'authproof-jws', errors: ['TIME_WINDOW'], warnings: [] },
  });
}

{
  const k = genKey();
  const compact = makeCompact(
    {
      ...baseBody(k.pub),
      delegationId: 'tv-time-02',
      timeWindow: { start: '2026-10-09T13:00:00.000Z', end: '2026-10-09T14:00:00.000Z' },
    },
    k.priv,
  );
  V({
    id: 'not-yet-valid',
    category: 'time',
    description:
      'Verification time (12:30Z) is before the window start (13:00Z): TIME_WINDOW. Draft 4.2, 10 (check 3).',
    profile: 'jws-compact',
    mode: 'receipt',
    draftSection: '4.2',
    input: compact,
    options: { ...OPTS },
    expect: { valid: false, format: 'authproof-jws', errors: ['TIME_WINDOW'], warnings: [] },
  });
}

// --- Revocation / policy -----------------------------------------------------

{
  const k = genKey();
  const compact = makeCompact(
    { ...baseBody(k.pub), delegationId: 'tv-rev-01', revocationRequired: true },
    k.priv,
  );
  V({
    id: 'revocation-check-required',
    category: 'revocation',
    description:
      'Receipt with revocationRequired:true and a registry check requested (checkRevocation=true): the reference implementation ships no registry (distribution out of scope, draft 14), so it fails closed with REVOCATION_CHECK_REQUIRED. Draft 9.4.',
    profile: 'jws-compact',
    mode: 'receipt',
    draftSection: '9.4',
    input: compact,
    options: { ...OPTS, checkRevocation: true },
    expect: {
      valid: false,
      format: 'authproof-jws',
      errors: ['REVOCATION_CHECK_REQUIRED'],
      warnings: [],
    },
  });
}

{
  const k = genKey();
  const compact = makeCompact({ ...baseBody(k.pub), delegationId: 'tv-pol-01' }, k.priv);
  V({
    id: 'issuer-not-trusted',
    category: 'policy',
    description:
      'Caller pins a trusted-issuer set that does not contain the receipt issuer thumbprint: ISSUER_NOT_TRUSTED. Draft 10.',
    profile: 'jws-compact',
    mode: 'receipt',
    draftSection: '10',
    input: compact,
    options: { ...OPTS, trustedIssuers: ['not-the-issuer-thumbprint'] },
    expect: {
      valid: false,
      format: 'authproof-jws',
      errors: ['ISSUER_NOT_TRUSTED'],
      warnings: [],
    },
  });
}

{
  V({
    id: 'input-not-jws',
    category: 'input',
    description:
      'Input is not a three-segment JWS at all: detectFormat reports "unknown" and verifyReceipt denies with UNKNOWN_FORMAT.',
    profile: 'n/a',
    mode: 'receipt',
    draftSection: '6.3',
    input: 'abc.def',
    options: { ...OPTS },
    expect: { valid: false, format: 'unknown', errors: ['UNKNOWN_FORMAT'], warnings: [] },
  });
}

// --- Delegation chains -------------------------------------------------------

function buildHopChain() {
  const root = genKey();
  const child = genKey();
  const rootCompact = makeCompact(
    { ...baseBody(root.pub), delegationId: 'tv-chain-root', scopeSchema: scope3() },
    root.priv,
  );
  const rootId = normalize(rootCompact).receiptId;
  const childBody = {
    ...baseBody(child.pub),
    delegationId: 'tv-chain-child',
    timeWindow: { start: '2026-10-09T12:15:00.000Z', end: '2026-10-09T12:45:00.000Z' },
    scopeSchema: {
      version: '1.0',
      allowedActions: [
        { operation: 'read', resource: 'calendar/events' },
        { operation: 'write', resource: 'calendar/drafts' },
      ],
      deniedActions: [{ operation: 'delete', resource: 'calendar/events' }],
    },
    parentReceiptId: rootId,
  };
  const childCompact = makeCompact(childBody, child.priv);
  const childId = normalize(childCompact).receiptId;
  const orch = makeOrchestratorSig(root.priv, rootId, childId);
  return { root, child, rootCompact, rootId, childBody, childCompact, childId, orch };
}

{
  const c = buildHopChain();
  const chain = [c.rootCompact, { compact: c.childCompact, orchestratorSignature: c.orch }];
  V({
    id: 'chain-valid-2hop',
    category: 'chain',
    description:
      'Valid 2-hop delegation chain: root signature, child signature, orchestratorSignature over the exact binding string "orchestrator-delegation:<parentId>:<childId>" verified against the parent key, child window contained in parent window, child scope a strict proper subset of the parent scope (2 < 3 allowed actions, parent denial preserved). Draft 4.4, 8.5, 8.7, 10 (check 14).',
    profile: 'jws-compact',
    mode: 'chain',
    draftSection: '8.7',
    chain,
    options: { ...OPTS },
    expect: {
      valid: true,
      format: 'authproof-jws',
      errors: [],
      warnings: ['CHAIN_OK', 'ORCHESTRATOR_SIG_OK'],
      receipt: { receiptId: c.childId, parentId: c.rootId, scopeKind: 'structured' },
    },
  });
}

{
  // Root 4 actions -> mid 3 actions -> leaf 2 actions.
  const root = genKey();
  const mid = genKey();
  const leaf = genKey();
  const rootScope = {
    version: '1.0',
    allowedActions: [
      { operation: 'read', resource: 'calendar/events' },
      { operation: 'write', resource: 'calendar/drafts' },
      { operation: 'delete', resource: 'calendar/archive' },
      { operation: 'read', resource: 'contacts/list' },
    ],
    deniedActions: [{ operation: 'delete', resource: 'calendar/events' }],
  };
  const rootCompact = makeCompact(
    { ...baseBody(root.pub), delegationId: 'tv-chain3-root', scopeSchema: rootScope },
    root.priv,
  );
  const rootId = normalize(rootCompact).receiptId;
  const midBody = {
    ...baseBody(mid.pub),
    delegationId: 'tv-chain3-mid',
    timeWindow: { start: '2026-10-09T12:10:00.000Z', end: '2026-10-09T12:50:00.000Z' },
    scopeSchema: {
      version: '1.0',
      allowedActions: [
        { operation: 'read', resource: 'calendar/events' },
        { operation: 'write', resource: 'calendar/drafts' },
        { operation: 'delete', resource: 'calendar/archive' },
      ],
      deniedActions: [{ operation: 'delete', resource: 'calendar/events' }],
    },
    parentReceiptId: rootId,
  };
  const midCompact = makeCompact(midBody, mid.priv);
  const midId = normalize(midCompact).receiptId;
  const leafBody = {
    ...baseBody(leaf.pub),
    delegationId: 'tv-chain3-leaf',
    timeWindow: { start: '2026-10-09T12:20:00.000Z', end: '2026-10-09T12:40:00.000Z' },
    scopeSchema: {
      version: '1.0',
      allowedActions: [
        { operation: 'read', resource: 'calendar/events' },
        { operation: 'write', resource: 'calendar/drafts' },
      ],
      deniedActions: [{ operation: 'delete', resource: 'calendar/events' }],
    },
    parentReceiptId: midId,
  };
  const leafCompact = makeCompact(leafBody, leaf.priv);
  const leafId = normalize(leafCompact).receiptId;
  const chain = [
    rootCompact,
    { compact: midCompact, orchestratorSignature: makeOrchestratorSig(root.priv, rootId, midId) },
    { compact: leafCompact, orchestratorSignature: makeOrchestratorSig(mid.priv, midId, leafId) },
  ];
  V({
    id: 'chain-valid-3hop',
    category: 'chain',
    description:
      'Valid 3-hop chain (root at depth 0, leaf at depth 2, under the default maxDepth 3): every hop narrows scope and window, every orchestratorSignature verifies. Draft 8.6, 8.7.',
    profile: 'jws-compact',
    mode: 'chain',
    draftSection: '8.6',
    chain,
    options: { ...OPTS },
    expect: {
      valid: true,
      format: 'authproof-jws',
      errors: [],
      warnings: ['CHAIN_OK'],
      receipt: { receiptId: leafId, parentId: midId, scopeKind: 'structured' },
    },
  });
}

{
  const c = buildHopChain();
  const det = makeDetached(c.childBody, c.child.priv);
  // Section 6.6: the detached receiptId is computed over the reconstructed
  // compact form, whose header differs from the compact child's header, so
  // the orchestrator binding must use the DETACHED child's receiptId.
  const detChildId = normalize(decodeInput(det)).receiptId;
  const detOrch = makeOrchestratorSig(c.root.priv, c.rootId, detChildId);
  const chain = [
    c.rootCompact,
    { detached: det.detached, payload_b64: det.payload_b64, orchestratorSignature: detOrch },
  ];
  V({
    id: 'chain-valid-2hop-detached-child',
    category: 'chain',
    description:
      'Valid 2-hop chain where the child travels in detached form (RFC 7797): chain checks run identically, receiptId follows the section 6.6 compact-reconstruction rule. Draft 6.4, 6.6, 8.7.',
    profile: 'jws-detached',
    mode: 'chain',
    draftSection: '6.4',
    chain,
    options: { ...OPTS },
    expect: {
      valid: true,
      format: 'authproof-jws',
      errors: [],
      warnings: ['CHAIN_OK'],
      receipt: { parentId: c.rootId, scopeKind: 'structured' },
    },
  });
}

{
  const c = buildHopChain();
  // Child grants delete::calendar/events, which the parent never held (and denied).
  const wideBody = {
    ...c.childBody,
    delegationId: 'tv-chain-wide',
    scopeSchema: {
      version: '1.0',
      allowedActions: [
        { operation: 'read', resource: 'calendar/events' },
        { operation: 'write', resource: 'calendar/drafts' },
        { operation: 'delete', resource: 'calendar/archive' },
        { operation: 'delete', resource: 'calendar/events' },
      ],
      deniedActions: [{ operation: 'delete', resource: 'calendar/events' }],
    },
  };
  const wideCompact = makeCompact(wideBody, c.child.priv);
  const wideId = normalize(wideCompact).receiptId;
  const chain = [
    c.rootCompact,
    {
      compact: wideCompact,
      orchestratorSignature: makeOrchestratorSig(c.root.priv, c.rootId, wideId),
    },
  ];
  V({
    id: 'chain-attenuation-wider-scope',
    category: 'chain',
    description:
      'Scope attenuation violation: the child grants delete::calendar/events, a key the parent never held (literal operation::resource comparison, wildcards not expanded): CHAIN_HOP_1_SCOPE_ATTENUATION_VIOLATED. Draft 8.5.',
    profile: 'jws-compact',
    mode: 'chain',
    draftSection: '8.5',
    chain,
    options: { ...OPTS },
    expect: {
      valid: false,
      format: 'authproof-jws',
      errors: ['CHAIN_HOP_1_SCOPE_ATTENUATION_VIOLATED'],
      warnings: [],
    },
  });
}

{
  const c = buildHopChain();
  // Child carries the parent's full 3-action scope: not a strict proper subset.
  const equalBody = {
    ...c.childBody,
    delegationId: 'tv-chain-equal',
    scopeSchema: scope3(),
  };
  const equalCompact = makeCompact(equalBody, c.child.priv);
  const equalId = normalize(equalCompact).receiptId;
  const chain = [
    c.rootCompact,
    {
      compact: equalCompact,
      orchestratorSignature: makeOrchestratorSig(c.root.priv, c.rootId, equalId),
    },
  ];
  V({
    id: 'chain-attenuation-equal-scope',
    category: 'chain',
    description:
      'Scope attenuation violation: the child keeps the parent\'s full allowedActions set (equal scope is rejected; delegation MUST narrow): CHAIN_HOP_1_SCOPE_ATTENUATION_VIOLATED. Draft 8.5.',
    profile: 'jws-compact',
    mode: 'chain',
    draftSection: '8.5',
    chain,
    options: { ...OPTS },
    expect: {
      valid: false,
      format: 'authproof-jws',
      errors: ['CHAIN_HOP_1_SCOPE_ATTENUATION_VIOLATED'],
      warnings: [],
    },
  });
}

{
  const c = buildHopChain();
  // Child narrows allowed actions but drops the parent's denial.
  const dropBody = {
    ...c.childBody,
    delegationId: 'tv-chain-dropdeny',
    scopeSchema: {
      version: '1.0',
      allowedActions: [
        { operation: 'read', resource: 'calendar/events' },
        { operation: 'write', resource: 'calendar/drafts' },
      ],
      deniedActions: [],
    },
  };
  const dropCompact = makeCompact(dropBody, c.child.priv);
  const dropId = normalize(dropCompact).receiptId;
  const chain = [
    c.rootCompact,
    {
      compact: dropCompact,
      orchestratorSignature: makeOrchestratorSig(c.root.priv, c.rootId, dropId),
    },
  ];
  V({
    id: 'chain-attenuation-dropped-denial',
    category: 'chain',
    description:
      'Scope attenuation violation: the child narrows allowedActions but drops the parent\'s deniedActions entry (delete::calendar/events): CHAIN_HOP_1_SCOPE_ATTENUATION_VIOLATED. Draft 8.5.',
    profile: 'jws-compact',
    mode: 'chain',
    draftSection: '8.5',
    chain,
    options: { ...OPTS },
    expect: {
      valid: false,
      format: 'authproof-jws',
      errors: ['CHAIN_HOP_1_SCOPE_ATTENUATION_VIOLATED'],
      warnings: [],
    },
  });
}

{
  const c = buildHopChain();
  // Child window extends past the parent window end: individually valid at AT, fails chain containment.
  const lateBody = {
    ...c.childBody,
    delegationId: 'tv-chain-late',
    timeWindow: { start: '2026-10-09T12:15:00.000Z', end: '2026-10-09T14:00:00.000Z' },
  };
  const lateCompact = makeCompact(lateBody, c.child.priv);
  const lateId = normalize(lateCompact).receiptId;
  const chain = [
    c.rootCompact,
    {
      compact: lateCompact,
      orchestratorSignature: makeOrchestratorSig(c.root.priv, c.rootId, lateId),
    },
  ];
  V({
    id: 'chain-window-violation',
    category: 'chain',
    description:
      'Child timeWindow (ending 14:00Z) is not contained in the parent window (ending 13:00Z): CHAIN_HOP_1_WINDOW_CONTAINMENT_VIOLATED. Draft 4.2, 8.7.',
    profile: 'jws-compact',
    mode: 'chain',
    draftSection: '4.2',
    chain,
    options: { ...OPTS },
    expect: {
      valid: false,
      format: 'authproof-jws',
      errors: ['CHAIN_HOP_1_WINDOW_CONTAINMENT_VIOLATED'],
      warnings: [],
    },
  });
}

{
  const c = buildHopChain();
  const wrongParentId = 'f'.repeat(64);
  const misBody = { ...c.childBody, delegationId: 'tv-chain-mislink', parentReceiptId: wrongParentId };
  const misCompact = makeCompact(misBody, c.child.priv);
  const misId = normalize(misCompact).receiptId;
  const chain = [
    c.rootCompact,
    {
      compact: misCompact,
      orchestratorSignature: makeOrchestratorSig(c.root.priv, wrongParentId, misId),
    },
  ];
  V({
    id: 'chain-parent-link-mismatch',
    category: 'chain',
    description:
      'Child parentReceiptId does not match the presented parent\'s receiptId: CHAIN_HOP_1_PARENT_LINK_MISMATCH (and the orchestrator binding consequently fails: CHAIN_HOP_1_ORCHESTRATOR_SIG_INVALID). Draft 8.7.',
    profile: 'jws-compact',
    mode: 'chain',
    draftSection: '8.7',
    chain,
    options: { ...OPTS },
    expect: {
      valid: false,
      format: 'authproof-jws',
      errors: ['CHAIN_HOP_1_PARENT_LINK_MISMATCH', 'CHAIN_HOP_1_ORCHESTRATOR_SIG_INVALID'],
      warnings: [],
    },
  });
}

{
  const c = buildHopChain();
  const chain = [c.rootCompact, { compact: c.childCompact }]; // no orchestratorSignature
  V({
    id: 'chain-orchestrator-sig-missing',
    category: 'chain',
    description:
      'Sub-receipt presented without its attached orchestratorSignature: CHAIN_HOP_1_ORCHESTRATOR_SIG_MISSING. Draft 4.4, 8.7.',
    profile: 'jws-compact',
    mode: 'chain',
    draftSection: '4.4',
    chain,
    options: { ...OPTS },
    expect: {
      valid: false,
      format: 'authproof-jws',
      errors: ['CHAIN_HOP_1_ORCHESTRATOR_SIG_MISSING'],
      warnings: [],
    },
  });
}

{
  const c = buildHopChain();
  const attacker = genKey();
  const forged = makeOrchestratorSig(attacker.priv, c.rootId, c.childId);
  const chain = [
    c.rootCompact,
    { compact: c.childCompact, orchestratorSignature: forged },
  ];
  V({
    id: 'chain-orchestrator-sig-forged',
    category: 'chain',
    description:
      'orchestratorSignature over the correct binding string but signed by an attacker key instead of the parent key: CHAIN_HOP_1_ORCHESTRATOR_SIG_INVALID. Draft 4.4.',
    profile: 'jws-compact',
    mode: 'chain',
    draftSection: '4.4',
    chain,
    options: { ...OPTS },
    expect: {
      valid: false,
      format: 'authproof-jws',
      errors: ['CHAIN_HOP_1_ORCHESTRATOR_SIG_INVALID'],
      warnings: [],
    },
  });
}

{
  // Reuse the 3-hop construction via fresh keys for a depth test.
  const root = genKey();
  const mid = genKey();
  const leaf = genKey();
  const rootCompact = makeCompact(
    { ...baseBody(root.pub), delegationId: 'tv-chainD-root', scopeSchema: scope3() },
    root.priv,
  );
  const rootId = normalize(rootCompact).receiptId;
  const midBody = {
    ...baseBody(mid.pub),
    delegationId: 'tv-chainD-mid',
    timeWindow: { start: '2026-10-09T12:10:00.000Z', end: '2026-10-09T12:50:00.000Z' },
    scopeSchema: {
      version: '1.0',
      allowedActions: [
        { operation: 'read', resource: 'calendar/events' },
        { operation: 'write', resource: 'calendar/drafts' },
      ],
      deniedActions: [{ operation: 'delete', resource: 'calendar/events' }],
    },
    parentReceiptId: rootId,
  };
  const midCompact = makeCompact(midBody, mid.priv);
  const midId = normalize(midCompact).receiptId;
  const leafBody = {
    ...baseBody(leaf.pub),
    delegationId: 'tv-chainD-leaf',
    timeWindow: { start: '2026-10-09T12:20:00.000Z', end: '2026-10-09T12:40:00.000Z' },
    scopeSchema: {
      version: '1.0',
      allowedActions: [{ operation: 'read', resource: 'calendar/events' }],
      deniedActions: [{ operation: 'delete', resource: 'calendar/events' }],
    },
    parentReceiptId: midId,
  };
  const leafCompact = makeCompact(leafBody, leaf.priv);
  const leafId = normalize(leafCompact).receiptId;
  const chain = [
    rootCompact,
    { compact: midCompact, orchestratorSignature: makeOrchestratorSig(root.priv, rootId, midId) },
    { compact: leafCompact, orchestratorSignature: makeOrchestratorSig(mid.priv, midId, leafId) },
  ];
  V({
    id: 'chain-depth-exceeded',
    category: 'chain',
    description:
      'Valid 3-hop chain presented with maxChainDepth=2: the leaf sits at depth 2, which is rejected: CHAIN_HOP_2_CHAIN_DEPTH_EXCEEDED. Draft 8.6.',
    profile: 'jws-compact',
    mode: 'chain',
    draftSection: '8.6',
    chain,
    options: { ...OPTS, maxChainDepth: 2 },
    expect: {
      valid: false,
      format: 'authproof-jws',
      errors: ['CHAIN_HOP_2_CHAIN_DEPTH_EXCEEDED'],
      warnings: [],
    },
  });
}

{
  const c = buildHopChain();
  const attacker = genKey();
  const badChild = makeCompact(c.childBody, attacker.priv); // signed by the wrong key
  const chain = [
    c.rootCompact,
    { compact: badChild, orchestratorSignature: c.orch }, // orch no longer matches child id either
  ];
  V({
    id: 'chain-hop-invalid-signature',
    category: 'chain',
    description:
      'Child hop carries a signature from the wrong key: the hop fails individual verification and the chain reports CHAIN_HOP_1_INVALID. Draft 8.7, 10 (check 14).',
    profile: 'jws-compact',
    mode: 'chain',
    draftSection: '8.7',
    chain,
    options: { ...OPTS },
    expect: {
      valid: false,
      format: 'authproof-jws',
      errors: ['CHAIN_HOP_1_INVALID'],
      warnings: [],
    },
  });
}

{
  V({
    id: 'chain-empty',
    category: 'chain',
    description: 'verifyChain called with an empty input list: EMPTY_CHAIN.',
    profile: 'n/a',
    mode: 'chain',
    draftSection: '8.7',
    chain: [],
    options: { ...OPTS },
    expect: { valid: false, format: 'unknown', errors: ['EMPTY_CHAIN'], warnings: [] },
  });
}

// ---------------------------------------------------------------------------
// Write vectors.json
// ---------------------------------------------------------------------------

const suite = {
  suite: 'draft-nelson-agent-delegation-receipts-11 JWS conformance vectors',
  version: '1.0.0',
  generated: new Date().toISOString(),
  keyMaterial:
    'THROWAWAY KEYS ONLY. All signatures were minted with single-purpose P-256 keys ' +
    'generated fresh at vector-generation time. Private keys are discarded and never ' +
    'published. These keys MUST NOT be used for anything real.',
  verificationTime: `All vectors pin verification time to ${AT}; vectors never expire.`,
  vectors,
};

writeFileSync(join(HERE, 'vectors.json'), JSON.stringify(suite, null, 2) + '\n');

const byCat = {};
for (const v of vectors) byCat[v.category] = (byCat[v.category] ?? 0) + 1;
console.log(`Wrote ${vectors.length} vectors:`, JSON.stringify(byCat));
