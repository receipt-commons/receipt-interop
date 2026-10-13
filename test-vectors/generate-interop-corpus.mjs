#!/usr/bin/env node
// ---------------------------------------------------------------------------
// Interop exchange corpus for draft-nelson-agent-delegation-receipts-12.
//
// Repackages a focused subset of the 45 JWS conformance vectors into a
// self-describing exchange format for independent implementers (see
// https://github.com/Commonguy25/authproof-sdk/issues/15).
//
// Categories follow the exchange offer: basic, expired, scope violation,
// revoked, sub-receipt chains. All inputs are ES256 JWS compact receipts,
// because draft -12 section 6.5 makes ES256 REQUIRED for conforming
// implementations (EdDSA is OPTIONAL).
//
// The `expected` block is normative only on `valid` (boolean). `errors` and
// `notes` carry this implementation's diagnostics as informative text; a
// foreign verifier SHOULD agree on valid/invalid and MAY use its own codes.
//
// Run:  npx tsx test-vectors/generate-interop-corpus.mjs
// Output: interop/corpus.json + interop/README.md
// ---------------------------------------------------------------------------

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const OUT = join(ROOT, 'interop');
mkdirSync(OUT, { recursive: true });

const all = JSON.parse(readFileSync(join(HERE, 'vectors.json'), 'utf8')).vectors;
const byId = new Map(all.map((v) => [v.id, v]));

// [interopId, sourceVectorId, plain-language expected outcome]
const SELECTION = [
  [
    'interop-01-basic-valid',
    'valid-compact-text-scope',
    'ACCEPT: minimal well-formed receipt, signature verifies, window covers verification time.',
  ],
  [
    'interop-02-structured-scope-valid',
    'valid-compact-structured-scope',
    'ACCEPT: receipt with an enforced structured scope; scope schema itself is valid.',
  ],
  [
    'interop-03-expired',
    'expired',
    'REJECT: verification time is after the receipt time window (notAfter passed).',
  ],
  [
    'interop-04-scope-violation',
    'chain-attenuation-wider-scope',
    'REJECT: child receipt grants an action class outside the parent scope (attenuation violation).',
  ],
  [
    'interop-05-revocation-required',
    'revocation-check-required',
    'REJECT (fail-closed): receipt requires revocation checking and the registry reports revoked/unavailable.',
  ],
  [
    'interop-06-chain-valid-2hop',
    'chain-valid-2hop',
    'ACCEPT: 2-hop delegation chain; every hop signature-verifies, scopes attenuate, windows nest.',
  ],
  [
    'interop-07-chain-valid-3hop',
    'chain-valid-3hop',
    'ACCEPT: 3-hop delegation chain within the default max depth.',
  ],
];

const cases = SELECTION.map(([interopId, srcId, outcome]) => {
  const src = byId.get(srcId);
  if (!src) throw new Error(`source vector missing: ${srcId}`);
  const c = {
    id: interopId,
    description: src.description,
    profile: src.profile,
    draftSection: src.draftSection,
    expectedOutcome: outcome,
    expected: {
      valid: src.expect.valid,
      // Informative: this implementation's diagnostics. Foreign verifiers
      // should agree on `valid`; codes are not normative across implementations.
      errors: src.expect.errors ?? [],
      warnings: src.expect.warnings ?? [],
    },
    options: src.options ?? {},
  };
  if (src.mode === 'chain') {
    c.mode = 'chain';
    c.chain = src.chain; // ordered root -> leaf
  } else {
    c.mode = 'receipt';
    c.input = src.input; // JWS compact serialization
  }
  return c;
});

const corpus = {
  format: 'agent-delegation-receipt-interop-corpus/1',
  draft: 'draft-nelson-agent-delegation-receipts-12',
  generated: new Date().toISOString().split('T')[0],
  generator: 'receipt-interop test-vectors (ES256, throwaway P-256 keys; test material only)',
  profile: 'JWS compact serialization, ES256 (REQUIRED per draft -12 section 6.5)',
  verificationTime: 'Each case carries its own `options.at`; verify as-of that instant.',
  cases,
};

writeFileSync(join(OUT, 'corpus.json'), JSON.stringify(corpus, null, 2) + '\n');

const readme = `# Interop exchange corpus

Exchange corpus for \`draft-nelson-agent-delegation-receipts-12\`, published for
independent implementers (see
[authproof-sdk#15](https://github.com/Commonguy25/authproof-sdk/issues/15)).

## Contents

\`corpus.json\` — 7 cases in the categories offered for exchange:

| case | meaning |
|---|---|
| interop-01-basic-valid | minimal well-formed receipt |
| interop-02-structured-scope-valid | enforced structured scope |
| interop-03-expired | verification after notAfter |
| interop-04-scope-violation | child exceeds parent scope |
| interop-05-revocation-required | revocation check fails closed |
| interop-06-chain-valid-2hop | valid 2-hop delegation chain |
| interop-07-chain-valid-3hop | valid 3-hop delegation chain |

Each case carries \`expected.valid\` (normative), plus this implementation's
\`errors\`/\`warnings\` as informative diagnostics — agree on valid/invalid,
use your own codes. Chain cases list receipts root-first under \`chain\`;
verify with the case's \`options.at\` as "now".

## Conformance note

Draft -12 section 6.5: **ES256 is REQUIRED** — every conforming
implementation MUST support it. EdDSA (Ed25519) is OPTIONAL. All cases here
are ES256; an implementation that verifies only Ed25519 is not conformant
and will fail this corpus.

## Keys

All signatures use throwaway P-256 keys generated for these vectors. Test
material only — never trust them for anything real.
`;

writeFileSync(join(OUT, 'README.md'), readme);
console.log(`wrote ${cases.length} interop cases -> ${OUT}/corpus.json`);
