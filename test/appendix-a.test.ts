// Tests against the draft Appendix A worked example.
// Fixtures are extracted verbatim from draft-nelson-agent-delegation-receipts-11.md
// (see test/fixtures/appendix-a.json) so no hand transcription can drift.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { jcsCanonicalize, sha256Hex } from '../src/crypto.js';
import { normalizeInstructions } from '../src/formats/authproof.js';
import { verifyReceipt } from '../src/index.js';

const dir = dirname(fileURLToPath(import.meta.url));
const fx = JSON.parse(
  readFileSync(join(dir, 'fixtures', 'appendix-a.json'), 'utf8'),
) as { jcs: string; compact: string; detached: string; receiptId: string; d: string };

const AT = new Date('2026-10-09T12:30:00.000Z'); // inside the fixture time window

test('A.2: JCS of the A.1 receipt equals the published canonical bytes', () => {
  const body = JSON.parse(fx.jcs) as Record<string, unknown>;
  // Re-parse and re-canonicalize: any conforming JCS implementation must
  // reproduce the exact published bytes.
  assert.equal(jcsCanonicalize(body), fx.jcs);
});

test('A.3: payload segment decodes to exactly the A.2 bytes', () => {
  const payloadB64 = fx.compact.split('.')[1];
  const decoded = Buffer.from(payloadB64, 'base64url').toString('utf8');
  assert.equal(decoded, fx.jcs);
});

test('A.3: the published DER signature genuinely verifies with the published key', () => {
  // This is the draft's own claim ("a real signature over example inputs"):
  // verify it with node:crypto, independent of this library's verifier.
  const [headerB64, payloadB64, sigB64] = fx.compact.split('.');
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, 'ascii');
  const sigDer = Buffer.from(sigB64, 'base64url');
  assert.ok(sigDer.length !== 64, 'fixture signature is DER-encoded, not raw R||S');
  const body = JSON.parse(fx.jcs) as { signerPublicKey: { x: string; y: string } };
  const pub = createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x: body.signerPublicKey.x, y: body.signerPublicKey.y },
    format: 'jwk',
  });
  assert.equal(verify('sha256', signingInput, pub, sigDer), true);
});

test('A.3: receiptId recomputes to the published value per section 6.6', () => {
  assert.equal(sha256Hex(Buffer.from(fx.compact, 'ascii')), fx.receiptId);
});

test('A.1: instructionsHash matches the section 4.2 normalization', () => {
  const body = JSON.parse(fx.jcs) as { operatorInstructions: string; instructionsHash: string };
  const normalized = normalizeInstructions(body.operatorInstructions);
  assert.equal(createHash('sha256').update(normalized, 'utf8').digest('hex'), body.instructionsHash);
});

test('A.3: verify() rejects the fixture with DER_SIGNATURE_REJECTED per section 6.3', async () => {
  // Normative section 6.3 ("DER-encoded signatures MUST be rejected") wins
  // over the informative appendix: the fixture signature is genuine DER, so
  // the -11 verifier must refuse it.
  const verdict = await verifyReceipt(fx.compact, { at: AT });
  assert.equal(verdict.valid, false);
  assert.deepEqual(verdict.errors, ['DER_SIGNATURE_REJECTED']);
  assert.equal(verdict.format, 'authproof-jws');
});

test('A.4: detached fixture has the RFC 7797 header shape and a DER signature', () => {
  const [headerB64, payloadSeg, sigB64] = fx.detached.split('.');
  assert.equal(payloadSeg, '');
  const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8')) as Record<
    string,
    unknown
  >;
  assert.equal(header.alg, 'ES256');
  assert.equal(header.b64, false);
  assert.deepEqual(header.crit, ['b64']);
  const sig = Buffer.from(sigB64, 'base64url');
  assert.ok(sig.length !== 64 && sig[0] === 0x30, 'detached fixture signature is DER');
});
