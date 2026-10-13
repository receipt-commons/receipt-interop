#!/usr/bin/env node
// Self-consistency check: every interop corpus case verifies against this
// implementation with its documented expected outcome.
// Run: npx tsx test-vectors/verify-interop-corpus.mjs
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { verifyReceipt, verifyChain } from '../src/index.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const corpus = JSON.parse(readFileSync(join(HERE, '..', 'interop', 'corpus.json'), 'utf8'));
let pass = 0;
const failures = [];
for (const c of corpus.cases) {
  const opts = {
    ...(c.options?.at ? { at: new Date(c.options.at) } : {}),
    ...(c.options?.checkRevocation ? { checkRevocation: true } : {}),
  };
  const verdict =
    c.mode === 'chain' ? await verifyChain(c.chain, opts) : await verifyReceipt(c.input, opts);
  if (verdict.valid === c.expected.valid) {
    pass++;
    console.log('PASS', c.id);
  } else {
    failures.push(c.id);
    console.log('FAIL', c.id, '| expected', c.expected.valid, '| got', verdict.valid, JSON.stringify(verdict.errors));
  }
}
console.log(`\n${pass}/${corpus.cases.length} self-consistent`);
process.exit(failures.length ? 1 : 0);
