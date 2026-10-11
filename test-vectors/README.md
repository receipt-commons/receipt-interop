# JWS Conformance Vector Suite — draft-nelson-agent-delegation-receipts-11

Language-agnostic test vectors for the **JWS receipt profile** (draft sections 4, 5, 6, 8, 9)
of `draft-nelson-agent-delegation-receipts-11`. Future independent implementers run this suite
against their own verifier to check conformance. The COSE profile (section 7) is out of scope
for this suite — the reference implementation does not implement it.

**Key material: THROWAWAY KEYS ONLY.** Every signature in `vectors.json` was minted with
single-purpose P-256 keys generated fresh at vector-generation time. Private keys are discarded
and never published. These keys MUST NOT be used for anything real.

## Files

| File | Purpose |
|---|---|
| `vectors.json` | The suite. 42 vectors, each fully self-describing. |
| `run-vectors.mjs` | Reference runner: loads `vectors.json`, feeds each vector through the reference implementation (`../src` via tsx), asserts the expected outcome. Exit 0 = all green. |
| `generate-vectors.mjs` | The minter. Regenerates `vectors.json` from scratch using the library's own crypto. Run: `npx tsx test-vectors/generate-vectors.mjs`. |
| `README.md` | This file. |

## Running

From `source/receipt-interop/`:

```sh
npx tsx test-vectors/run-vectors.mjs
```

Expected output ends with `42/42 vectors passed` and exit code 0.

## Vector format spec

Top-level `vectors.json`:

```json
{
  "suite": "draft-nelson-agent-delegation-receipts-11 JWS conformance vectors",
  "version": "1.0.0",
  "generated": "<ISO 8601 timestamp>",
  "keyMaterial": "THROWAWAY KEYS ONLY …",
  "verificationTime": "All vectors pin verification time to 2026-10-09T12:30:00.000Z; vectors never expire.",
  "vectors": [ … ]
}
```

Each vector:

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Stable identifier, e.g. `chain-attenuation-wider-scope`. |
| `category` | string | One of `valid`, `signature`, `body`, `header`, `time`, `revocation`, `policy`, `input`, `chain`. |
| `description` | string | What the vector tests and why. Vectors whose behavior documents a spec/implementation tension are marked `INTEROP NOTE`. |
| `profile` | string | `jws-compact`, `jws-detached`, or `n/a`. |
| `mode` | string | `receipt` (single `verifyReceipt`) or `chain` (`verifyChain`). |
| `draftSection` | string | Draft section under test, e.g. `8.5`. |
| `input` | string \| object | The receipt input. Compact form: the full `h.p.s` string. Detached form: `{ "detached": "<headerB64>..<sigB64>", "payload_b64": "<base64 of raw JCS payload bytes>" }`. A sub-receipt carrying its orchestrator signature: `{ "compact": "<h.p.s>", "orchestratorSignature": "<h.p.s>" }`. |
| `chain` | array | `mode: "chain"` only. Ordered hop inputs, root first, leaf last; each hop encoded like `input` above. |
| `options` | object | Verifier options: `at` (ISO 8601, always pinned to `2026-10-09T12:30:00.000Z` so vectors never rot), `checkRevocation` (bool), `maxChainDepth` (when relevant), `trustedIssuers` (when relevant). |
| `expect` | object | Expected outcome (see below). |

`expect`:

| Field | Type | Meaning |
|---|---|---|
| `valid` | bool | Expected verdict validity. |
| `format` | string | Expected detected format (`authproof-jws` or `unknown`). |
| `errors` | string[] | Every listed code MUST appear (as a substring) in the actual error list. The reference implementation prefixes chain errors with `CHAIN_HOP_<n>_`, e.g. `CHAIN_HOP_1_SCOPE_ATTENUATION_VIOLATED: …` — match on the code, not the full string. Error codes are implementation-defined; what the draft requires is the **denial**, not the spelling. |
| `warnings` | string[] | Every listed warning MUST appear (as a substring) in the actual warning list. Warnings never affect validity. |
| `receipt` | object | Spot-checks against the verified receipt: `receiptId` (draft 6.6: lowercase hex SHA-256 of the ASCII JWS Compact Serialization; for detached, over the reconstructed compact form), `issuer` (RFC 7638 JWK SHA-256 thumbprint of the signing key), `parentId`, `scopeKind` (`structured` \| `text`), `agent`, `revocationRequired`. Only present keys are checked. |

## How an independent implementation consumes the suite

1. Parse `vectors.json`. For each vector, decode `input` (or each entry of `chain`):
   - string → compact JWS `h.p.s`;
   - `{detached, payload_b64}` → detached JWS: the transmission form is `detached`, the payload bytes are `base64decode(payload_b64)`;
   - `{compact, orchestratorSignature}` → compact JWS with an attached second JWS.
2. Run your verifier at `options.at` (parse as UTC), with `checkRevocation`, `maxChainDepth`, `trustedIssuers` as given.
   - `mode: "receipt"` → single-receipt verification.
   - `mode: "chain"` → verify the array root-first with your delegation-chain logic (parent-link, window containment, attenuation, depth, orchestrator signature).
3. Assert: `valid` matches; each expected error/warning code is a substring of one actual error/warning; each `receipt` spot-check equals.
4. Normative weight: `valid` and the `receipt` spot-checks (`receiptId`, `issuer`, `scopeKind`, `parentId`) are the conformance-critical assertions. Error **codes** are informative — the reference implementation's codes are not normative, but the deny/permit decision is.

## Coverage (42 vectors)

| Category | Count | What's covered |
|---|---|---|
| `valid` | 8 | compact text-scope; compact structured scope (constraints, denials, agentId, metadata, trustedSources); missing `typ` (warning); `kid` header; instructionsHash-mismatch warning; revocationRequired-without-check (warning); detached RFC 7797 incl. 6.6 receiptId rule; metadata.displayLabel preserves decision (Iman case 1) |
| `signature` | 5 | wrong-key signature; **DER-encoded signature rejected** (genuine DER that verifies as DER); malformed (32-byte) signature; `alg:none` → denied; unsupported `alg` → denied |
| `body` | 11 | tampered payload; non-canonical (non-JCS) payload; non-JSON payload; missing `delegationId`; malformed `instructionsHash`; malformed `timeWindow`; mismatched `signerPublicKey` (P-384); malformed `scopeSchema`; unknown field in payload (rejected — see interop note); unknown authority field (Iman case 2); `oneTimeUse:true` fail-closed (Iman case 3) |
| `header` | 3 | `b64:false` in compact form; detached header missing `b64:false`/`crit:["b64"]`; unrecognized `crit` parameter |
| `time` | 2 | expired window; not-yet-valid window |
| `revocation` | 1 | `revocationRequired:true` + registry check requested → fail-closed denial |
| `policy` | 1 | issuer not in `trustedIssuers` |
| `input` | 1 | non-JWS input → unknown format |
| `chain` | 13 | valid 2-hop; valid 3-hop (depth rule); valid 2-hop with detached child; attenuation violations — child wider than parent, equal scope, dropped denial; window containment violation; parent-link mismatch; missing orchestrator signature; forged orchestrator signature; depth exceeded; invalid hop signature; empty chain |

## Known gaps (deliberate — the reference model does not support these)

- **Revocation registry:** the reference implementation ships no registry (distribution is out of scope per draft section 14), so there is no vector for a positively-revoked receipt or `ANCESTOR_REVOKED`. Revocation coverage is the fail-closed behavior: `revocationRequired:true` denies when a check is requested and warns when it isn't.
- **Per-action allow/deny:** `verifyReceipt` takes no action parameter, so scopeSchema allow/deny decisions against a concrete action are not exercised; the suite covers schema structure, structured-vs-advisory mapping, and chain attenuation instead.
- **`oneTimeUse`:** fail-closed per draft 9.5. The reference implementation ships no durable consumption store, so a receipt with `oneTimeUse: true` is denied with `CONSUMPTION_STORE_REQUIRED`; vector `iman-case-3-onetimeuse-fail-closed` pins this.
- **COSE profile:** recognized but explicitly not implemented by the reference (`COSE_NOT_IMPLEMENTED`); not covered here.
- **ED25519/ES384/ES512:** optional per the draft registry; no vectors mint them.

## Interop notes found while minting

1. **Unknown fields (draft 4.1, -12 direction per Iman Schrock).** Authorization fields are closed: a payload carrying an unknown top-level body field is rejected with `UNKNOWN_BODY_FIELD` — never silently allowed. Extensions belong inside `metadata`, whose contents are ignored by the verifier (vector `iman-case-1-metadata-display-label` pins that the decision is unchanged). Vectors `unknown-field-in-payload-rejected` and `iman-case-2-unknown-authority-field-rejected` pin the rejection, including for an authority constraint the verifier cannot interpret.
2. **Non-ES256 algorithms.** The reference verifier defines `ALG_NONE_PROHIBITED` / `ALG_UNSUPPORTED` codes, but its format detector only claims ES256 inputs, so through the public API `alg:none` and `alg:RS256` receipts are denied one layer earlier as `UNKNOWN_FORMAT`. Vectors `alg-none-prohibited` and `alg-unsupported` pin the denial; the exact code is implementation-defined.
