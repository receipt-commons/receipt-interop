// Tests for the registry and top-level entry points (src/api.ts).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { base64urlEncode, jcsCanonicalize, sha256Hex } from '../src/crypto.js';
import { normalizeInstructions } from '../src/formats/authproof.js';
import type { FormatVerifier } from '../src/model.js';
import {
  detectFormat,
  normalize,
  registerFormat,
  registeredFormats,
  resolveOptions,
  verifyReceipt,
} from '../src/index.js';

const AT = new Date('2026-10-09T12:30:00.000Z');

function makeReceipt(): string {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const pubJwk = publicKey.export({ format: 'jwk' });
  const instructions = 'API test instructions.';
  const body = {
    delegationId: 'auth-api-001',
    issuedAt: '2026-10-09T12:00:00.000Z',
    scope: 'api test scope',
    boundaries: 'no harm',
    timeWindow: { start: '2026-10-09T12:00:00.000Z', end: '2026-10-09T13:00:00.000Z' },
    operatorInstructions: instructions,
    instructionsHash: sha256Hex(Buffer.from(normalizeInstructions(instructions), 'utf8')),
    signerPublicKey: pubJwk,
  };
  const headerB64 = base64urlEncode(Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'drp-receipt' }), 'utf8'));
  const payloadB64 = base64urlEncode(Buffer.from(jcsCanonicalize(body), 'utf8'));
  const sig = sign('sha256', Buffer.from(`${headerB64}.${payloadB64}`, 'ascii'), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  return `${headerB64}.${payloadB64}.${base64urlEncode(sig)}`;
}

test('built-in formats are registered', () => {
  const formats = registeredFormats();
  assert.ok(formats.includes('authproof-jws'), JSON.stringify(formats));
  assert.ok(formats.includes('authproof-cose'), JSON.stringify(formats));
  assert.ok(formats.includes('ucan'), JSON.stringify(formats));
  assert.ok(formats.includes('agent-passport'), JSON.stringify(formats));
});

test('detectFormat routes inputs to the right format', () => {
  assert.equal(detectFormat(makeReceipt()), 'authproof-jws');
  assert.equal(detectFormat('garbage'), 'unknown');
  assert.equal(detectFormat(null), 'unknown');
  assert.equal(detectFormat(42), 'unknown');
  assert.equal(detectFormat({}), 'unknown');
  assert.equal(detectFormat(Uint8Array.from([0xd2, 0x84, 0x00])), 'authproof-cose');
});

test('custom verifiers can be registered', () => {
  const custom: FormatVerifier = {
    id: 'gleipnir',
    detect: (input) => input === 'gleipnir-receipt',
    verify: async () => ({
      valid: true,
      format: 'gleipnir',
      receipt: null,
      errors: [],
      warnings: [],
    }),
    normalize: () => {
      throw new Error('GLEIPNIR_NORMALIZE_UNIMPLEMENTED');
    },
  };
  registerFormat(custom);
  assert.equal(detectFormat('gleipnir-receipt'), 'gleipnir');
  assert.ok(registeredFormats().includes('gleipnir'));
});

test('normalize throws UNKNOWN_FORMAT on unparseable input', () => {
  assert.throws(() => normalize('garbage'), /UNKNOWN_FORMAT/);
  assert.throws(() => normalize(null), /UNKNOWN_FORMAT/);
});

test('verifyReceipt returns UNKNOWN_FORMAT for unknown input', async () => {
  const verdict = await verifyReceipt('garbage', { at: AT });
  assert.equal(verdict.valid, false);
  assert.equal(verdict.format, 'unknown');
  assert.equal(verdict.receipt, null);
  assert.deepEqual(verdict.errors, ['UNKNOWN_FORMAT']);
});

test('verifyReceipt applies defaults: at=now, checkRevocation=false, maxChainDepth=5', () => {
  const o = resolveOptions(undefined);
  assert.ok(o.at instanceof Date);
  assert.equal(o.checkRevocation, false);
  assert.equal(o.maxChainDepth, 5);
  const partial = resolveOptions({ maxChainDepth: 2 });
  assert.equal(partial.maxChainDepth, 2);
  assert.equal(partial.checkRevocation, false);
});

test('verifyReceipt on a valid receipt returns the normalized receipt', async () => {
  const verdict = await verifyReceipt(makeReceipt(), { at: AT });
  assert.equal(verdict.valid, true);
  assert.equal(verdict.format, 'authproof-jws');
  assert.ok(verdict.receipt !== null);
  assert.equal(verdict.receipt!.scope.kind, 'text');
});

test('detectors never throw on hostile input', () => {
  const hostile = [
    '',
    '.',
    '..',
    'a.b.c.d',
    '\0\0\0',
    { detached: 42, payload: null },
    { detached: 'x..y', payload: {} },
    Buffer.from([0xd2]),
  ];
  for (const h of hostile) {
    assert.doesNotThrow(() => detectFormat(h), `detectFormat threw on ${JSON.stringify(h)}`);
  }
});
