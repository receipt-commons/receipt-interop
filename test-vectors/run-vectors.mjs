#!/usr/bin/env node
// ---------------------------------------------------------------------------
// Conformance-vector runner for the draft-nelson-agent-delegation-receipts-11
// JWS vector suite.
//
// Loads test-vectors/vectors.json, feeds every vector through the reference
// implementation (src/ via tsx), and asserts the expected outcome:
//   - detected format
//   - verdict.valid
//   - every expected error code appears (as a substring) in the actual errors
//   - every expected warning appears (as a substring) in the actual warnings
//   - expected receipt spot-checks (receiptId, issuer thumbprint, parentId,
//     scope kind, agent, revocationRequired)
//
// Exit 0 when every vector passes; exit 1 otherwise, with per-vector detail.
//
// Run:  npx tsx test-vectors/run-vectors.mjs
// ---------------------------------------------------------------------------

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import assert from 'node:assert/strict';
import { detectFormat, verifyReceipt, verifyChain } from '../src/index.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const suite = JSON.parse(readFileSync(join(HERE, 'vectors.json'), 'utf8'));

// vectors.json input encoding -> library input shape.
function decodeInput(inp) {
  if (typeof inp === 'string') return inp;
  const out = {};
  if (inp.compact) out.compact = inp.compact;
  if (inp.detached) out.detached = inp.detached;
  if (inp.payload_b64) out.payload = Buffer.from(inp.payload_b64, 'base64');
  if (inp.orchestratorSignature) out.orchestratorSignature = inp.orchestratorSignature;
  return out;
}

function toOpts(o) {
  const opts = { at: new Date(o.at) };
  if (o.checkRevocation !== undefined) opts.checkRevocation = o.checkRevocation;
  if (o.maxChainDepth !== undefined) opts.maxChainDepth = o.maxChainDepth;
  if (o.trustedIssuers !== undefined) opts.trustedIssuers = o.trustedIssuers;
  return opts;
}

const RECEIPT_FIELDS = {
  receiptId: (r) => r.receiptId,
  issuer: (r) => r.issuer,
  parentId: (r) => r.parentId,
  scopeKind: (r) => r.scope.kind,
  agent: (r) => r.agent,
  revocationRequired: (r) => r.revocation.required,
};

function checkExpect(v, verdict) {
  const e = v.expect;
  assert.equal(verdict.valid, e.valid, `${v.id}: expected valid=${e.valid}`);
  assert.equal(verdict.format, e.format, `${v.id}: expected format ${e.format}`);
  for (const code of e.errors ?? []) {
    assert.ok(
      verdict.errors.some((err) => err.includes(code)),
      `${v.id}: expected error containing "${code}"; got [${verdict.errors.join(' | ')}]`,
    );
  }
  for (const w of e.warnings ?? []) {
    assert.ok(
      verdict.warnings.some((warn) => warn.includes(w)),
      `${v.id}: expected warning containing "${w}"; got [${verdict.warnings.join(' | ')}]`,
    );
  }
  if (e.receipt) {
    assert.ok(verdict.receipt, `${v.id}: expected a receipt object, got null`);
    for (const [key, expected] of Object.entries(e.receipt)) {
      const actual = RECEIPT_FIELDS[key](verdict.receipt);
      assert.equal(actual, expected, `${v.id}: receipt.${key}`);
    }
  }
}

let passed = 0;
const failures = [];

for (const v of suite.vectors) {
  try {
    if (v.mode === 'chain') {
      const hops = (v.chain ?? []).map(decodeInput);
      const verdict = await verifyChain(hops, toOpts(v.options));
      checkExpect(v, verdict);
    } else {
      const input = decodeInput(v.input);
      assert.equal(
        detectFormat(input),
        v.expect.format,
        `${v.id}: detectFormat mismatch`,
      );
      const verdict = await verifyReceipt(input, toOpts(v.options));
      checkExpect(v, verdict);
    }
    passed++;
    console.log(`PASS ${v.id}`);
  } catch (err) {
    failures.push({ id: v.id, error: String(err?.message ?? err).split('\n')[0] });
    console.log(`FAIL ${v.id}: ${String(err?.message ?? err).split('\n')[0]}`);
  }
}

console.log('---');
console.log(`${suite.suite} v${suite.version}: ${passed}/${suite.vectors.length} vectors passed`);
if (failures.length > 0) {
  for (const f of failures) console.log(`  FAILED: ${f.id} — ${f.error}`);
  process.exit(1);
}
