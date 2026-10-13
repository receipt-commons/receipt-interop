// Tests for the OPTIONAL EdDSA (Ed25519) JWS profile (draft -12 section 6.5).
// Run: npx tsx --test "test/**/*.test.ts"
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import {
  base64urlDecode,
  base64urlEncode,
  ed25519Verify,
  jcsCanonicalize,
  okpJwkThumbprint,
  sha256Hex,
} from '../src/crypto.js';
import { normalizeInstructions } from '../src/formats/authproof.js';
import { detectFormat, verifyChain, verifyReceipt } from '../src/index.js';

const AT = new Date('2026-10-09T12:30:00.000Z');

interface EdKey {
  priv: KeyObject;
  pubJwk: { kty: string; crv: string; x: string };
}

function genEdKey(): EdKey {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pubJwk = publicKey.export({ format: 'jwk' }) as EdKey['pubJwk'];
  assert.equal(pubJwk.kty, 'OKP');
  assert.equal(pubJwk.crv, 'Ed25519');
  return { priv: privateKey, pubJwk };
}

function baseBody(pubJwk: EdKey['pubJwk'], overrides: Record<string, unknown> = {}) {
  const instructions = 'Do the test thing, carefully.';
  return {
    delegationId: 'eddsa-test-001',
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

function makeEdCompact(
  body: Record<string, unknown>,
  priv: KeyObject,
  header: Record<string, unknown> = { alg: 'EdDSA', typ: 'drp-receipt' },
): string {
  const headerB64 = b64uJson(header);
  const payloadB64 = base64urlEncode(Buffer.from(jcsCanonicalize(body), 'utf8'));
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, 'ascii');
  const sig = sign(null, signingInput, priv);
  assert.equal(sig.length, 64);
  return `${headerB64}.${payloadB64}.${base64urlEncode(sig)}`;
}

// ---------------------------------------------------------------------------
// crypto-level
// ---------------------------------------------------------------------------

test('ed25519Verify round-trips a real signature and rejects the wrong key', () => {
  const k = genEdKey();
  const other = genEdKey();
  const msg = Buffer.from('test signing input', 'utf8');
  const sig = sign(null, msg, k.priv);
  assert.equal(ed25519Verify({ x: k.pubJwk.x }, msg, sig), true);
  assert.equal(ed25519Verify({ x: other.pubJwk.x }, msg, sig), false);
  const bad = Buffer.from(sig);
  bad[0] ^= 0x01;
  assert.equal(ed25519Verify({ x: k.pubJwk.x }, msg, bad), false);
  assert.equal(ed25519Verify({ x: k.pubJwk.x }, msg, new Uint8Array(32)), false);
});

test('okpJwkThumbprint is stable and differs across keys', () => {
  const a = genEdKey();
  const b = genEdKey();
  const t1 = okpJwkThumbprint(a.pubJwk);
  assert.equal(t1, okpJwkThumbprint(a.pubJwk));
  assert.notEqual(t1, okpJwkThumbprint(b.pubJwk));
  assert.match(t1, /^[A-Za-z0-9_-]+$/);
});

// ---------------------------------------------------------------------------
// verifier: positive and negative paths
// ---------------------------------------------------------------------------

test('valid EdDSA compact receipt verifies; issuer is the OKP thumbprint', async () => {
  const k = genEdKey();
  const compact = makeEdCompact(baseBody(k.pubJwk), k.priv);
  assert.equal(detectFormat(compact), 'authproof-jws');
  const verdict = await verifyReceipt(compact, { at: AT });
  assert.equal(verdict.valid, true);
  assert.deepEqual(verdict.errors, []);
  assert.equal(verdict.format, 'authproof-jws');
  const r = verdict.receipt!;
  assert.equal(r.issuer, okpJwkThumbprint(k.pubJwk));
  assert.deepEqual(r.issuerKey, { kty: 'OKP', crv: 'Ed25519', x: k.pubJwk.x });
  assert.ok(!('y' in r.issuerKey));
});

test('EdDSA receipt with a tampered signature fails SIGNATURE_INVALID', async () => {
  const k = genEdKey();
  const compact = makeEdCompact(baseBody(k.pubJwk), k.priv);
  const parts = compact.split('.');
  const sig = Buffer.from(base64urlDecode(parts[2]));
  sig[0] ^= 0x01;
  const tampered = `${parts[0]}.${parts[1]}.${base64urlEncode(sig)}`;
  const verdict = await verifyReceipt(tampered, { at: AT });
  assert.equal(verdict.valid, false);
  assert.ok(verdict.errors.includes('SIGNATURE_INVALID'));
});

test('EdDSA receipt signed by the wrong Ed25519 key fails', async () => {
  const k = genEdKey();
  const other = genEdKey();
  const compact = makeEdCompact(baseBody(k.pubJwk), other.priv);
  const verdict = await verifyReceipt(compact, { at: AT });
  assert.equal(verdict.valid, false);
  assert.ok(verdict.errors.includes('SIGNATURE_INVALID'));
});

test('alg/key mismatch is rejected, never verified', async () => {
  const ed = genEdKey();
  // EdDSA header but EC P-256 key in the body.
  const { generateKeyPairSync: gen } = await import('node:crypto');
  const { publicKey } = gen('ec', { namedCurve: 'P-256' });
  const ecJwk = publicKey.export({ format: 'jwk' }) as { kty: string; crv: string; x: string; y: string };
  const mismatched = makeEdCompact(baseBody(ecJwk as never), ed.priv, {
    alg: 'EdDSA',
    typ: 'drp-receipt',
  });
  const v1 = await verifyReceipt(mismatched, { at: AT });
  assert.equal(v1.valid, false);
  assert.ok(v1.errors.includes('ALG_KEY_MISMATCH'), JSON.stringify(v1.errors));

  // ES256 header but OKP Ed25519 key in the body.
  const headerB64 = b64uJson({ alg: 'ES256', typ: 'drp-receipt' });
  const payloadB64 = base64urlEncode(
    Buffer.from(jcsCanonicalize(baseBody(ed.pubJwk)), 'utf8'),
  );
  const sig = sign(null, Buffer.from(`${headerB64}.${payloadB64}`, 'ascii'), ed.priv);
  const v2 = await verifyReceipt(
    `${headerB64}.${payloadB64}.${base64urlEncode(sig)}`,
    { at: AT },
  );
  assert.equal(v2.valid, false);
  assert.ok(v2.errors.includes('ALG_KEY_MISMATCH'), JSON.stringify(v2.errors));
});

test('unknown algorithms are still rejected', async () => {
  const k = genEdKey();
  const compact = makeEdCompact(baseBody(k.pubJwk), k.priv, {
    alg: 'RS256',
    typ: 'drp-receipt',
  });
  assert.equal(detectFormat(compact), 'unknown');
});

// ---------------------------------------------------------------------------
// chains: orchestrator binding under Ed25519, signed by the child key
// ---------------------------------------------------------------------------

function makeOrchestratorSig(childPriv: KeyObject, parentId: string, childId: string): string {
  const binding = `orchestrator-delegation:${parentId}:${childId}`;
  const headerB64 = b64uJson({ alg: 'EdDSA' });
  const payloadB64 = base64urlEncode(Buffer.from(binding, 'utf8'));
  const sig = sign(null, Buffer.from(`${headerB64}.${payloadB64}`, 'ascii'), childPriv);
  return `${headerB64}.${payloadB64}.${base64urlEncode(sig)}`;
}

test('2-hop Ed25519 chain verifies with the child-signed orchestrator binding', async () => {
  const rootK = genEdKey();
  const childK = genEdKey();
  const rootCompact = makeEdCompact(
    baseBody(rootK.pubJwk, { delegationId: 'eddsa-chain-root' }),
    rootK.priv,
  );
  const rootId = (await verifyReceipt(rootCompact, { at: AT })).receipt!.receiptId;
  const childBody = baseBody(childK.pubJwk, {
    delegationId: 'eddsa-chain-child',
    parentReceiptId: rootId,
    scope: 'read test data',
  });
  const childCompact = makeEdCompact(childBody, childK.priv);
  const childId = (await verifyReceipt(childCompact, { at: AT })).receipt!.receiptId;
  const chain = [
    rootCompact,
    {
      compact: childCompact,
      orchestratorSignature: makeOrchestratorSig(childK.priv, rootId, childId),
    },
  ];
  const verdict = await verifyChain(chain, { at: AT });
  assert.equal(verdict.valid, true);
  assert.deepEqual(verdict.errors, []);
});

test('orchestrator binding signed by the parent key fails under -13 semantics', async () => {
  const rootK = genEdKey();
  const childK = genEdKey();
  const rootCompact = makeEdCompact(
    baseBody(rootK.pubJwk, { delegationId: 'eddsa-chain-root2' }),
    rootK.priv,
  );
  const rootId = (await verifyReceipt(rootCompact, { at: AT })).receipt!.receiptId;
  const childBody = baseBody(childK.pubJwk, {
    delegationId: 'eddsa-chain-child2',
    parentReceiptId: rootId,
    scope: 'read test data',
  });
  const childCompact = makeEdCompact(childBody, childK.priv);
  const childId = (await verifyReceipt(childCompact, { at: AT })).receipt!.receiptId;
  // Old (pre-13) behavior: parent signs the binding. Must now fail.
  const chain = [
    rootCompact,
    {
      compact: childCompact,
      orchestratorSignature: makeOrchestratorSig(rootK.priv, rootId, childId),
    },
  ];
  const verdict = await verifyChain(chain, { at: AT });
  assert.equal(verdict.valid, false);
  assert.ok(
    verdict.errors.some((e) => e.includes('ORCHESTRATOR_SIG_INVALID')),
    JSON.stringify(verdict.errors),
  );
});
