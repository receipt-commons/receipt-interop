# Interop exchange corpus

Exchange corpus for `draft-nelson-agent-delegation-receipts-12`, published for
independent implementers (see
[authproof-sdk#15](https://github.com/Commonguy25/authproof-sdk/issues/15)).

## Contents

`corpus.json` — 7 cases in the categories offered for exchange:

| case | meaning |
|---|---|
| interop-01-basic-valid | minimal well-formed receipt |
| interop-02-structured-scope-valid | enforced structured scope |
| interop-03-expired | verification after notAfter |
| interop-04-scope-violation | child exceeds parent scope |
| interop-05-revocation-required | revocation check fails closed |
| interop-06-chain-valid-2hop | valid 2-hop delegation chain |
| interop-07-chain-valid-3hop | valid 3-hop delegation chain |

Each case carries `expected.valid` (normative), plus this implementation's
`errors`/`warnings` as informative diagnostics — agree on valid/invalid,
use your own codes. Chain cases list receipts root-first under `chain`;
verify with the case's `options.at` as "now".

## Conformance note

Draft -12 section 6.5: **ES256 is REQUIRED** — every conforming
implementation MUST support it. EdDSA (Ed25519) is OPTIONAL. All cases here
are ES256; an implementation that verifies only Ed25519 is not conformant
and will fail this corpus.

## Keys

All signatures use throwaway P-256 keys generated for these vectors. Test
material only — never trust them for anything real.
