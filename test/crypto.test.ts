// Unit tests for src/crypto.ts. Run: npx tsx --test "test/**/*.test.ts"
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import {
  base64urlDecode,
  base64urlEncode,
  ecJwkThumbprint,
  es256Verify,
  jcsCanonicalize,
  sha256Hex,
} from '../src/crypto.js';

test('base64url round-trips binary data with no padding', () => {
  const bytes = Uint8Array.from([0, 1, 2, 250, 251, 252, 253, 254, 255]);
  const enc = base64urlEncode(bytes);
  assert.ok(!enc.includes('=') && !enc.includes('+') && !enc.includes('/'));
  assert.deepEqual(Array.from(base64urlDecode(enc)), Array.from(bytes));
  assert.equal(base64urlEncode(new Uint8Array(0)), '');
  assert.deepEqual(Array.from(base64urlDecode('')), []);
});

test('base64urlDecode rejects invalid input', () => {
  assert.throws(() => base64urlDecode('ab+c'), /BASE64URL_INVALID/);
  assert.throws(() => base64urlDecode('ab=='), /BASE64URL_INVALID/);
  assert.throws(() => base64urlDecode('a b'), /BASE64URL_INVALID/);
});

test('sha256Hex matches the well-known "abc" vector', () => {
  assert.equal(
    sha256Hex('abc'),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  );
});

test('jcsCanonicalize sorts keys recursively and strips whitespace', () => {
  const input = { z: 1, a: { d: [3, 2], b: 'x' }, m: null };
  assert.equal(jcsCanonicalize(input), '{"a":{"b":"x","d":[3,2]},"m":null,"z":1}');
});

test('jcsCanonicalize sorts integer-like keys by UTF-16 code units, not numerically', () => {
  // RFC 8785: "10" < "2" because 0x31 < 0x32, even though 10 > 2 numerically.
  assert.equal(jcsCanonicalize({ '2': 'b', '10': 'a' }), '{"10":"a","2":"b"}');
});

test('jcsCanonicalize uses shortest-round-trip numbers and normalizes -0', () => {
  assert.equal(jcsCanonicalize({ n: -0 }), '{"n":0}');
  assert.equal(jcsCanonicalize({ n: 1e21 }), '{"n":1e+21}');
  assert.equal(jcsCanonicalize({ n: 0.30000000000000004 }), '{"n":0.30000000000000004}');
  assert.throws(() => jcsCanonicalize({ n: NaN }), /JCS_NON_FINITE_NUMBER/);
  assert.throws(() => jcsCanonicalize({ n: Infinity }), /JCS_NON_FINITE_NUMBER/);
});

test('jcsCanonicalize applies only the mandated string escapes', () => {
  assert.equal(jcsCanonicalize({ s: 'a"b\\c\nd\te\bf\fg\rh\x01i~' }), '{"s":"a\\"b\\\\c\\nd\\te\\bf\\fg\\rh\\u0001i~"}');
  // U+007F and non-ASCII are emitted literally, not escaped.
  assert.equal(jcsCanonicalize({ s: '\x7f\u00e9\ud83d\ude00' }), '{"s":"\x7f\u00e9\ud83d\ude00"}');
});

test('jcsCanonicalize rejects lone surrogates', () => {
  assert.throws(() => jcsCanonicalize({ s: '\ud800' }), /JCS_LONE_SURROGATE/);
  assert.throws(() => jcsCanonicalize({ s: 'x\udc00' }), /JCS_LONE_SURROGATE/);
  assert.throws(() => jcsCanonicalize({ s: '\ud800x' }), /JCS_LONE_SURROGATE/);
});

test('jcsCanonicalize rejects non-JSON values', () => {
  assert.throws(() => jcsCanonicalize({ f: () => 1 }), /JCS_UNREPRESENTABLE_VALUE/);
  assert.throws(() => jcsCanonicalize({ b: 10n }), /JCS_UNREPRESENTABLE_VALUE/);
  assert.throws(() => jcsCanonicalize(undefined), /JCS_UNREPRESENTABLE_VALUE/);
});

test('ecJwkThumbprint is deterministic, 43 chars, and key-sensitive', () => {
  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    x: 'k4eDoJ8mAwcQ8CkSSXmE5fldUVMG5yvA5JV8lWfgEZE',
    y: '0L9A-hFoNMj7UspxAWu1EKsnjdgEoNb08A9r-kYhCwU',
  };
  const t1 = ecJwkThumbprint(jwk);
  const t2 = ecJwkThumbprint({ ...jwk });
  assert.equal(t1, t2);
  assert.match(t1, /^[A-Za-z0-9_-]{43}$/);
  // Independent recomputation straight from RFC 7638 section 3.
  const canonical = '{"crv":"P-256","kty":"EC","x":"k4eDoJ8mAwcQ8CkSSXmE5fldUVMG5yvA5JV8lWfgEZE","y":"0L9A-hFoNMj7UspxAWu1EKsnjdgEoNb08A9r-kYhCwU"}';
  const expected = createHash('sha256').update(canonical, 'utf8').digest().toString('base64url');
  assert.equal(t1, expected);
  const other = ecJwkThumbprint({ ...jwk, x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' });
  assert.notEqual(t1, other);
});

test('es256Verify accepts a genuine raw R||S signature', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string; y: string };
  const msg = Buffer.from('signing input', 'ascii');
  const sig = sign('sha256', msg, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  assert.equal(sig.length, 64);
  assert.ok(es256Verify(jwk, msg, sig));
});

test('es256Verify rejects DER signatures, wrong keys, and tampered inputs', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const { publicKey: otherPub } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string; y: string };
  const otherJwk = otherPub.export({ format: 'jwk' }) as { x: string; y: string };
  const msg = Buffer.from('signing input', 'ascii');
  const raw = sign('sha256', msg, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  const der = sign('sha256', msg, privateKey); // default DER encoding
  assert.ok(der.length !== 64);
  assert.equal(es256Verify(jwk, msg, der), false); // DER rejected: not 64 raw bytes
  assert.equal(es256Verify(otherJwk, msg, raw), false); // wrong key
  assert.equal(es256Verify(jwk, Buffer.from('tampered', 'ascii'), raw), false);
  const flipped = Buffer.from(raw);
  flipped[0] ^= 0x01;
  assert.equal(es256Verify(jwk, msg, flipped), false);
  assert.equal(es256Verify({ x: 'bogus', y: 'bogus' }, msg, raw), false);
});

test('es256Verify agrees with a direct node:crypto call', () => {
  const { privateKey: k2, publicKey: p2 } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const j2 = p2.export({ format: 'jwk' }) as { x: string; y: string };
  const m = Buffer.from('cross-check', 'utf8');
  const s = sign('sha256', m, { key: k2, dsaEncoding: 'ieee-p1363' });
  assert.equal(es256Verify(j2, m, s), true);
});
