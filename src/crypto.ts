// Cryptographic utilities. Real primitives only: node:crypto for hashing and
// ECDSA, RFC 8785 canonicalization implemented to the letter, no homebrew crypto.

import { createHash, createPublicKey, verify } from 'node:crypto';

// base64url without padding (RFC 4648 section 5).
export function base64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

export function base64urlDecode(s: string): Uint8Array {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) {
    throw new Error('BASE64URL_INVALID');
  }
  return Buffer.from(s, 'base64url');
}

export function sha256Hex(data: Uint8Array | string): string {
  return createHash('sha256').update(data).digest('hex');
}

// JSON Canonicalization Scheme (RFC 8785):
// - object member names sorted by UTF-16 code units, recursively
// - no insignificant whitespace
// - shortest round-trip number form
// - only the mandated string escapes; lone surrogates are an error
export function jcsCanonicalize(value: unknown): string {
  return canonicalizeValue(value);
}

function canonicalizeValue(value: unknown): string {
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';
  if (typeof value === 'string') return canonicalizeString(value);
  if (typeof value === 'number') return canonicalizeNumber(value);
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalizeValue).join(',') + ']';
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const parts = keys.map(
      (k) =>
        canonicalizeString(k) +
        ':' +
        canonicalizeValue((value as Record<string, unknown>)[k]),
    );
    return '{' + parts.join(',') + '}';
  }
  throw new Error('JCS_UNREPRESENTABLE_VALUE');
}

function canonicalizeString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const cu = s.charCodeAt(i);
    if (cu >= 0xd800 && cu <= 0xdbff) {
      // high surrogate: must be followed by a low surrogate
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : -1;
      if (next >= 0xdc00 && next <= 0xdfff) {
        out += s[i] + s[i + 1]; // valid pair: emitted literally per RFC 8785
        i++;
      } else {
        throw new Error('JCS_LONE_SURROGATE');
      }
    } else if (cu >= 0xdc00 && cu <= 0xdfff) {
      throw new Error('JCS_LONE_SURROGATE');
    } else if (cu === 0x22) {
      out += '\\"';
    } else if (cu === 0x5c) {
      out += '\\\\';
    } else if (cu === 0x08) {
      out += '\\b';
    } else if (cu === 0x09) {
      out += '\\t';
    } else if (cu === 0x0a) {
      out += '\\n';
    } else if (cu === 0x0c) {
      out += '\\f';
    } else if (cu === 0x0d) {
      out += '\\r';
    } else if (cu < 0x20) {
      out += '\\u' + cu.toString(16).padStart(4, '0');
    } else {
      out += s[i];
    }
  }
  return out + '"';
}

function canonicalizeNumber(n: number): string {
  if (!Number.isFinite(n)) throw new Error('JCS_NON_FINITE_NUMBER');
  if (Object.is(n, -0)) return '0';
  // String(n) is the shortest round-trip form in ECMAScript (ES2022 6.1.6.1).
  return String(n);
}

// JWK SHA-256 thumbprint (RFC 7638). For EC keys the required members,
// lexicographically ordered, are exactly: crv, kty, x, y.
export function ecJwkThumbprint(jwk: {
  kty: string;
  crv: string;
  x: string;
  y: string;
}): string {
  const canonical = jcsCanonicalize({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  });
  const digest = createHash('sha256').update(canonical, 'utf8').digest();
  return base64urlEncode(digest);
}

// ES256 verification. Signature must be the raw 64-byte R||S concatenation
// (RFC 7518 section 3.4); DER-encoded signatures are rejected by returning
// false. Returns false (fail closed) on any malformed key or signature.
export function es256Verify(
  key: { x: string; y: string },
  signingInput: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (!(signature instanceof Uint8Array) || signature.length !== 64) return false;
  try {
    const pub = createPublicKey({
      key: { kty: 'EC', crv: 'P-256', x: key.x, y: key.y },
      format: 'jwk',
    });
    return verify('sha256', signingInput, { key: pub, dsaEncoding: 'ieee-p1363' }, signature);
  } catch {
    return false;
  }
}
