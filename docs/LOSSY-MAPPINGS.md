# Lossy mappings

Every verifier converts its native receipt into one `NormalizedReceipt`. The common model cannot hold everything, so mappings drop or reshape data. This file lists every known lossy mapping per format. Assume a mapping is lossy unless it says otherwise; never imply equivalence where loss is recorded here.

Legend: **kept** = carried into the normalized model without loss. **noted** = not carried, but recorded as a `lossy` note string on the receipt (machine-readable where noted). **dropped** = not carried and not noted.

## authproof-jws

Native spec: the authproof draft (-11), JWS profile.

| Native field | Normalized field | Fate |
|---|---|---|
| JWS compact ASCII bytes | `receiptId` = sha256hex of the compact bytes (draft §6.6) | kept |
| `payload.signerPublicKey` (EC P-256 JWK) | `issuer` = RFC 7638 thumbprint (base64url); `issuerKey` = the JWK | kept |
| `payload.agentId` | `agent` | kept |
| `payload.timeWindow.start` / `.end` | `notBefore` / `notAfter` (ISO strings as written in the payload) | kept |
| `payload.instructionsHash` | `instructionsHash` | kept |
| `payload.parentReceiptId` | `parentId` | kept |
| `payload.boundaries` (free text, newlines and semicolons allowed) | `boundaries[]` | **noted**: split into an array on newlines and semicolons (`BOUNDARIES_SPLIT_ON_NEWLINES_AND_SEMICOLONS`); splitting changes the original string shape |
| `payload.scopeSchema.allowedActions[]` (`operation`, `resource`, `constraints`) | `scope.kind='structured'`, `actions[]`, `resources[]`, `constraints` keyed `operation::resource` | kept for structure; per-entry constraints keyed by the joined pair, which is a reshaping |
| `payload.scopeSchema.deniedActions[]` | — | **noted**: no slot in the common model; each denial is recorded as `DENIED:<operation>::<resource>` so chain attenuation can recover it. Denials are second-class citizens in the normalized model. |
| `payload.scope` (plain text, no scopeSchema) | `scope.kind='text'`, `text`, `enforced=false` | **lossy**: per draft §8.4 text scope is advisory only; the normalized model cannot enforce it, and `checkAttenuation` skips text scopes (warning, not error) |
| `payload.revocationRequired` | `revocation.required` | kept; `revocation.status` is always `'unknown'`, `revocation.pointer` always null — **lossy**: no registry exists in this library, so a receipt that requires revocation can only fail closed when checked |
| unknown top-level payload fields | — | **dropped** per draft §4.1 (noted as `UNKNOWN_FIELDS_DROPPED:<fields>`) |
| JWS header (`alg`, `typ`) | — | dropped after validation (`alg` must be ES256; `typ` should be `drp-receipt`, warning only if absent) |
| orchestrator signature on sub-receipts | — | **noted**: single `verify()` records `ORCHESTRATOR_SIG_DEFERRED_TO_CHAIN`; only `verifyChain` with the `{compact, orchestratorSignature}` wrapper resolves it |
| COSE profile input | — | not a mapping: detected, answered `COSE_NOT_IMPLEMENTED` |

## ucan (0.x, embedded-JWT line)

Native spec: ucan-wg/ts-ucan (reference implementation, 0.8.1) and the ucan-wg spec fixtures.

| Native field | Normalized field | Fate |
|---|---|---|
| compact JWT ASCII bytes | `receiptId` = sha256hex of the compact bytes | kept |
| `payload.iss` (did:key DID) | `issuer` = the DID verbatim | kept |
| did:key ed25519 pubkey | `issuerKey` = `{kty:'OKP', crv:'Ed25519', x: base64url(pubkey)}` | kept |
| `payload.aud` | `agent` | kept |
| `payload.att[]` (`with`, `can`; aliases `wn`, `cap` accepted) | `scope.kind='capability'`, `actions[]` = cans, `resources[]` = withs, `enforced=true` | **noted**: capabilities beyond the with/can strings are not preserved (`att capabilities beyond with/can strings not preserved`) |
| `payload.nbf` / `payload.exp` (unix seconds) | `notBefore` / `notAfter` (ISO) | kept; **noted**: a missing `nbf` falls back to the epoch (`no nbf claim`) |
| `payload.prf` (embedded proof JWTs) | `parentId` = sha256hex of `prf[0]`; null when `prf` is empty | **noted**: only the first proof feeds `parentId` (`no proofs (root UCAN)`); the remaining proofs are preserved in `raw` but not in the chain model. `verifyChain` expects a flat root-to-leaf array; native multi-proof (rights-amplification) structure does not round-trip through the normalized chain. |
| `payload.fct` (facts) | — | **dropped** (`fct (facts) not mapped`) |
| revocation | `revocation = {required:false, pointer:null, status:'unknown'}` | **lossy**: the UCAN material defines no standard revocation mechanism; status is always unknown |
| header (`alg`, `typ`, `ucv`) | — | dropped after validation (`alg` must be EdDSA; `ucv` version warns only) |
| no advisory text scope exists natively | — | noted: nothing to map |

## agent-passport (Action Receipts v1.1)

Native spec: `docs/SPEC-v1.1.md`, `docs/CANONICAL-SPEC.md`, `src/core/*` at commit c31d94a of agent-passport-system/agent-passport-system.

| Native field | Normalized field | Fate |
|---|---|---|
| `receipt_id` | `receiptId` | kept |
| executor key (delegation_chain tail → leaf delegation `delegatedTo` → fallback) | `issuer` = raw public-key hex (lowercase); `issuerKey` = `{kty:'OKP', crv:'Ed25519', x: base64url(pubkey)}` | kept; **noted**: identity in this format is key material, and the delegation chain fingerprints are not modeled (`delegation_chain fingerprints are not modeled; only the executing agent's key is normalized as issuer`) |
| `agent_id` | `agent` | kept |
| `action.scope_used` / `action.target` | `scope.kind='structured'`, `actions=[scope_used]`, `resources=[target]`, `enforced=true` | **noted**: only the leaf action's scope is normalized; per-hop narrowing is verified at `verify()` time and does not survive normalization (`per-hop scope narrowing is verified at verify() time; the normalized scope carries only the leaf action's scope_used`) |
| `action.type`, `action.method`, `action.spend` | `scope.constraints` (`actionType`, `method`, `spend`) | **noted**: flattened into constraints; spend currency-unit semantics are not modeled (`action.type/method/spend flattened into scope.constraints; spend currency-unit semantics are not modeled`) |
| `action.result` (status, summary) | — | **noted**: no normalized field (`action.result (status/summary) has no normalized field; preserved in raw`) |
| delegation bounds (`spendLimit`, `spendLimitUnit`, `maxDepth`, `currentDepth`, `scopeInterpretation`) | — | **noted**: not modeled (`delegation bounds (...) are not modeled; preserved in raw`); verified at verify time, lost on normalize |
| leaf delegation `notBefore` / `expiresAt` | `notBefore` / `notAfter` | kept when a chain is supplied; **noted**: with no delegation chain supplied, both fall back to the receipt `timestamp` |
| `delegation_id` | `parentId` | kept |
| `previousReceiptHash` | — | **noted** when present (`previousReceiptHash append-only linkage is not represented in the normalized parent model; preserved in raw`); the digest algorithm is not pinned by their spec, so nothing is verified about it |
| `witnessSignature`, `witnessAttestation`, `finality`, `authorizationRef` | — | **noted** when present (each as `optional <field> (notary/maturation field) is not modeled; preserved in raw`) |
| `tombstoned` / `tombstoneReason` | — | preserved in `raw` only |
| revocation | `revocation.pointer` / `.status` from supplied evidence, else `{required:false, pointer:null, status:'unknown'}` | **lossy**: offline only; their cascade implementation lives gateway-side, not in the OSS SDK, so an offline verifier cannot perform their registry check (`REVOCATION_UNCHECKED_OFFLINE`). Bad revocation signatures are ignored with a warning (fail-safe: never revoke on forged evidence). |
| `instructionsHash` | null | native field does not exist; null is honest, not lossy |

## gleipnir

No published mandate format exists (checked 2026-10-09; the company is pre-product). There is no mapping to document. The module in `src/formats/gleipnir.ts` is a documented skeleton: it detects nothing and verifies nothing. When Gleipnir publishes a real format, the mapping belongs here.
