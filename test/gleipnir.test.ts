import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { gleipnirVerifier, detect, verify, normalize } from '../src/formats/gleipnir.js';
import { registeredFormats } from '../src/index.js';

describe('gleipnir (experimental skeleton)', () => {
  it('detect always returns false: no published wire format exists', () => {
    assert.equal(detect('anything'), false);
    assert.equal(detect({}), false);
    assert.equal(gleipnirVerifier.detect('mandate'), false);
  });

  it('verify always answers NOT_IMPLEMENTED with receipt null', async () => {
    const verdict = await verify({}, {});
    assert.equal(verdict.valid, false);
    assert.equal(verdict.format, 'gleipnir');
    assert.equal(verdict.receipt, null);
    assert.deepEqual(verdict.errors, ['GLEIPNIR_NOT_IMPLEMENTED']);
    assert.ok(verdict.warnings.some((w) => w.includes('experimental')));
  });

  it('normalize throws NOT_IMPLEMENTED', () => {
    assert.throws(() => normalize({}), /GLEIPNIR_NOT_IMPLEMENTED/);
  });

  it('is exported but NOT auto-registered in index.ts', () => {
    assert.ok(!registeredFormats().includes('gleipnir'));
  });
});
