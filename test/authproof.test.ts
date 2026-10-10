// Tests for the authproof JWS-profile verifier (src/formats/authproof.ts).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import {
  base64urlDecode,
  base64urlEncode,
  ecJwkThumbprint,
  jcsCanonicalize,
  sha256Hex,
} from '../src/crypto.js';
import {
  authproofCose,
  authproofJws,
  normalizeInstructions,
} from '../src/formats/authproof.js';
import { detectFormat, normalize, verifyReceipt } from '../src/index.js';

const AT = new Date('2026-10-09T12:30:00.000Z');

interface TestKey {
  priv: KeyObject;
  pubJwk: { kty: string; crv: string; x: string; y: string };
}

function genKey(): TestKey {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const pubJwk = publicKey.export({ format: 'jwk' }) as TestKey['pubJwk'];
  return { priv: privateKey, pubJwk };
}

function baseBody(pubJwk: TestKey['pubJwk'], overrides: Record<string, unknown> = {}) {
  const instructions = 'Do the test thing, carefully.';
  return {
    delegationId: 'auth-test-001',
    issuedAt: '2026-10-09T12:00:00.000Z',
    scope: 'read test data and write test reports',
    boundaries: 'never delete test data; never exfiltrate',
    timeWindow: { start: '2026-10-09T12:00:00.000Z', end: '2026-10-09T13:00:00.000Z' },
    operatorInstructions: instructions,
    instructionsHash: sha256Hex(Buffer.from(normalizeInstructions(instructions), 'utf8')),
    signerPublicKey: pubJwk,
    ...overrides,
  };
}

function b64uJson(v: unknown): string {
  return base64urlEncode(Buffer.from(JSON.stringify(v), 'utf8'));
}

function makeCompact(
  body: Record<string, unknown>,
  priv: KeyObject,
  header: Record<string, unknown> = { alg: 'ES256', typ: 'drp-receipt' },
  opts: { der?: boolean; payloadBytes?: Uint8Array } = {},
): string {
  const headerB64 = b64uJson(header);
  const payloadBytes = opts.payloadBytes ?? Buffer.from(jcsCanonicalize(body), 'utf8');
  const payloadB64 = base64urlEncode(payloadBytes);
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, 'ascii');
  const sig = opts.der
    ? sign('sha256', signingInput, priv)
    : sign('sha256', signingInput, { key: priv, dsaEncoding: 'ieee-p1363' });
  return `${headerB64}.${payloadB64}.${base64urlEncode(sig)}`;
}

function makeDetached(
  body: Record<string, unknown>,
  priv: KeyObject,
  tamper?: (bytes: Uint8Array) => Uint8Array,
): { detached: string; payload: Uint8Array } {
  const header = { alg: 'ES256', b64: false, crit: ['b64'] };
  const headerB64 = b64uJson(header);
  let payloadBytes = Buffer.from(jcsCanonicalize(body), 'utf8');
  const signingInput = Buffer.concat([Buffer.from(`${headerB64}.`, 'ascii'), payloadBytes]);
  const sig = sign('sha256', signingInput, { key: priv, dsaEncoding: 'ieee-p1363' });
  const detached = `${headerB64}..${base64urlEncode(sig)}`;
  if (tamper) payloadBytes = Buffer.from(tamper(payloadBytes));
  return { detached, payload: payloadBytes };
}

// ---------------------------------------------------------------------------
// Positive paths
// ---------------------------------------------------------------------------

test('valid compact receipt verifies; normalized fields map correctly', async () => {
  const k = genKey();
  const compact = makeCompact(baseBody(k.pubJwk), k.priv);
  const verdict = await verifyReceipt(compact, { at: AT });
  assert.equal(verdict.valid, true);
  assert.deepEqual(verdict.errors, []);
  assert.equal(verdict.format, 'authproof-jws');
  const r = verdict.receipt!;
  assert.equal(r.receiptId, sha256Hex(Buffer.from(compact, 'ascii')));
  assert.equal(r.issuer, ecJwkThumbprint(k.pubJwk));
  assert.deepEqual(r.issuerKey, { kty: 'EC', crv: 'P-256', x: k.pubJwk.x, y: k.pubJwk.y });
  assert.equal(r.agent, null);
  assert.equal(r.notBefore, '2026-10-09T12:00:00.000Z');
  assert.equal(r.notAfter, '2026-10-09T13:00:00.000Z');
  assert.equal(r.parentId, null);
  assert.equal(r.revocation.required, false);
  assert.equal(r.revocation.status, 'unknown');
  // Text scope maps to advisory (section 8.4).
  assert.equal(r.scope.kind, 'text');
  assert.equal(r.scope.enforced, false);
  assert.equal(r.scope.text, 'read test data and write test reports');
  // Boundaries split on semicolons with a lossy note.
  assert.deepEqual(r.boundaries, ['never delete test data', 'never exfiltrate']);
  assert.ok(r.lossy.includes('BOUNDARIES_SPLIT_ON_NEWLINES_AND_SEMICOLONS'));
});

test('structured scopeSchema maps to an enforced structured ScopeExpression', async () => {
  const k = genKey();
  const body = baseBody(k.pubJwk, {
    scopeSchema: {
      version: '1.0',
      allowedActions: [
        { operation: 'read', resource: 'calendar/events' },
        { operation: 'write', resource: 'calendar/drafts', constraints: { maxEvents: 10 } },
      ],
      deniedActions: [{ operation: 'delete', resource: 'calendar/events' }],
    },
  });
  const verdict = await verifyReceipt(makeCompact(body, k.priv), { at: AT });
  assert.equal(verdict.valid, true);
  const r = verdict.receipt!;
  assert.equal(r.scope.kind, 'structured');
  assert.equal(r.scope.enforced, true);
  assert.equal(r.scope.text, null);
  assert.deepEqual(r.scope.actions, ['read', 'write']);
  assert.deepEqual(r.scope.resources, ['calendar/events', 'calendar/drafts']);
  assert.deepEqual(r.scope.constraints, { 'write::calendar/drafts': { maxEvents: 10 } });
  // Denials survive as machine-readable lossy notes for chain attenuation.
  assert.ok(r.lossy.includes('DENIED:delete::calendar/events'));
});

test('valid detached receipt verifies', async () => {
  const k = genKey();
  const { detached, payload } = makeDetached(baseBody(k.pubJwk), k.priv);
  const verdict = await verifyReceipt({ detached, payload }, { at: AT });
  assert.equal(verdict.valid, true);
  assert.deepEqual(verdict.errors, []);
  // Section 6.6: receiptId over the reconstructed compact form.
  const headerB64 = detached.split('.')[0];
  const expectedCompact = `${headerB64}.${base64urlEncode(payload)}.${detached.split('.')[2]}`;
  assert.equal(verdict.receipt!.receiptId, sha256Hex(Buffer.from(expectedCompact, 'ascii')));
});

test('missing typ header yields a warning, not an error', async () => {
  const k = genKey();
  const compact = makeCompact(baseBody(k.pubJwk), k.priv, { alg: 'ES256' });
  const verdict = await verifyReceipt(compact, { at: AT });
  assert.equal(verdict.valid, true);
  assert.ok(verdict.warnings.includes('TYP_MISSING'));
});

test('sub-receipt without a parent gets ORCHESTRATOR_SIG_DEFERRED_TO_CHAIN', async () => {
  const k = genKey();
  const body = baseBody(k.pubJwk, { parentReceiptId: 'abc123' });
  const verdict = await verifyReceipt(makeCompact(body, k.priv), { at: AT });
  assert.equal(verdict.valid, true);
  assert.ok(verdict.warnings.includes('ORCHESTRATOR_SIG_DEFERRED_TO_CHAIN'));
  assert.equal(verdict.receipt!.parentId, 'abc123');
});

// ---------------------------------------------------------------------------
// Negative paths
// ---------------------------------------------------------------------------

test('tampered payload byte fails signature verification', async () => {
  const k = genKey();
  const compact = makeCompact(baseBody(k.pubJwk), k.priv);
  const [h, p, s] = compact.split('.');
  // Flip one JSON byte while keeping the payload canonical, so only the
  // signature check can catch it.
  const tamperedJson = Buffer.from(p, 'base64url').toString('utf8').replace('test data', 'test datX');
  const tampered = `${h}.${base64urlEncode(Buffer.from(tamperedJson, 'utf8'))}.${s}`;
  const verdict = await verifyReceipt(tampered, { at: AT });
  assert.equal(verdict.valid, false);
  assert.ok(verdict.errors.includes('SIGNATURE_INVALID'), JSON.stringify(verdict.errors));
});

test('alg=none is rejected and not detected as authproof-jws', async () => {
  const k = genKey();
  const none = makeCompact(baseBody(k.pubJwk), k.priv, { alg: 'none', typ: 'drp-receipt' });
  assert.equal(detectFormat(none), 'unknown');
  const viaApi = await verifyReceipt(none, { at: AT });
  assert.equal(viaApi.valid, false);
  assert.deepEqual(viaApi.errors, ['UNKNOWN_FORMAT']);
  const direct = await authproofJws.verify(none, { at: AT });
  assert.equal(direct.valid, false);
  assert.ok(direct.errors.includes('ALG_NONE_PROHIBITED'));
});

test('DER-encoded signature is rejected per section 6.3', async () => {
  const k = genKey();
  const compact = makeCompact(baseBody(k.pubJwk), k.priv, undefined, { der: true });
  const sigLen = base64urlDecode(compact.split('.')[2]).length;
  assert.ok(sigLen !== 64, 'test setup: signature must be DER');
  const verdict = await verifyReceipt(compact, { at: AT });
  assert.equal(verdict.valid, false);
  assert.ok(verdict.errors.includes('DER_SIGNATURE_REJECTED'));
});

test('expired time window fails with TIME_WINDOW', async () => {
  const k = genKey();
  const compact = makeCompact(baseBody(k.pubJwk), k.priv);
  const verdict = await verifyReceipt(compact, { at: new Date('2026-10-09T14:00:00.000Z') });
  assert.equal(verdict.valid, false);
  assert.ok(verdict.errors.includes('TIME_WINDOW'));
});

test('signature from the wrong key fails with SIGNATURE_INVALID', async () => {
  const a = genKey();
  const b = genKey();
  const compact = makeCompact(baseBody(a.pubJwk), b.priv); // body names A, signed by B
  const verdict = await verifyReceipt(compact, { at: AT });
  assert.equal(verdict.valid, false);
  assert.ok(verdict.errors.includes('SIGNATURE_INVALID'));
});

test('non-JCS payload fails even with a valid signature over those bytes', async () => {
  const k = genKey();
  const body = baseBody(k.pubJwk);
  // Insertion-order JSON is not JCS (keys unsorted); sign it anyway.
  const nonCanonical = Buffer.from(JSON.stringify(body), 'utf8');
  assert.notEqual(nonCanonical.toString('utf8'), jcsCanonicalize(body));
  const compact = makeCompact(body, k.priv, undefined, { payloadBytes: nonCanonical });
  const verdict = await verifyReceipt(compact, { at: AT });
  assert.equal(verdict.valid, false);
  assert.ok(verdict.errors.includes('PAYLOAD_NOT_JCS_CANONICAL'));
});

test('detached form with an altered payload fails signature verification', async () => {
  const k = genKey();
  // Alter a byte inside a string value: the payload stays valid canonical
  // JSON, so only the signature check can catch the tampering.
  const tamper = (bytes: Uint8Array) => {
    const text = Buffer.from(bytes).toString('utf8').replace('test data', 'test datX');
    return Buffer.from(text, 'utf8');
  };
  const { detached, payload } = makeDetached(baseBody(k.pubJwk), k.priv, tamper);
  const verdict = await verifyReceipt({ detached, payload }, { at: AT });
  assert.equal(verdict.valid, false);
  assert.ok(verdict.errors.includes('SIGNATURE_INVALID'), JSON.stringify(verdict.errors));
});

test('malformed bodies report field errors', async () => {
  const k = genKey();
  const bad = baseBody(k.pubJwk, { instructionsHash: 'not-hex', timeWindow: { start: 'nope' } });
  const verdict = await verifyReceipt(makeCompact(bad as Record<string, unknown>, k.priv), {
    at: AT,
  });
  assert.equal(verdict.valid, false);
  assert.ok(verdict.errors.includes('INSTRUCTIONS_HASH_INVALID'));
  assert.ok(verdict.errors.includes('TIME_WINDOW_INVALID'));
});

test('revocationRequired with checkRevocation fails closed', async () => {
  const k = genKey();
  const compact = makeCompact(baseBody(k.pubJwk, { revocationRequired: true }), k.priv);
  const strict = await verifyReceipt(compact, { at: AT, checkRevocation: true });
  assert.equal(strict.valid, false);
  assert.ok(strict.errors.includes('REVOCATION_CHECK_REQUIRED'));
  const lax = await verifyReceipt(compact, { at: AT });
  assert.equal(lax.valid, true);
  assert.ok(lax.warnings.includes('REVOCATION_REQUIRED_BUT_UNCHECKED'));
});

test('untrusted issuer is rejected when trustedIssuers is set', async () => {
  const k = genKey();
  const compact = makeCompact(baseBody(k.pubJwk), k.priv);
  const verdict = await verifyReceipt(compact, { at: AT, trustedIssuers: ['someone-else'] });
  assert.equal(verdict.valid, false);
  assert.ok(verdict.errors.includes('ISSUER_NOT_TRUSTED'));
  const trusted = await verifyReceipt(compact, {
    at: AT,
    trustedIssuers: [ecJwkThumbprint(k.pubJwk)],
  });
  assert.equal(trusted.valid, true);
});

test('COSE input is detected but reported as not implemented, never faked', async () => {
  // Minimal COSE_Sign1 framing: CBOR tag 18 (0xD2) + 4-array (0x84).
  const cose = Uint8Array.from([0xd2, 0x84, 0x43, 0x01, 0x02, 0x03]);
  assert.equal(authproofCose.detect(cose), true);
  assert.equal(detectFormat(cose), 'authproof-cose');
  const verdict = await verifyReceipt(cose, { at: AT });
  assert.equal(verdict.valid, false);
  assert.deepEqual(verdict.errors, ['COSE_NOT_IMPLEMENTED']);
  assert.throws(() => normalize(cose), /COSE_NOT_IMPLEMENTED/);
});
