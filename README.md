# receipt-interop

A neutral verification layer for AI-agent delegation receipts.

When one AI agent acts on another's behalf, there should be a receipt: who authorized it, what it was allowed to do, and when. Several formats exist for those receipts, and none of them is the standard. This library reads and cryptographically verifies the main ones, then hands you each receipt in the same shape so your code only has to deal with one model.

It verifies receipts. It does not enforce anything. If a malicious operator skips the check, no library can stop them. This is audit and attribution, not access control.

## Supported formats

- `authproof-jws` — the authproof draft JWS profile: compact and detached JWS receipts signed with ES256 (P-256), JSON Canonicalization Scheme payloads, structured scopes, optional orchestrator signatures on sub-receipts.
- `ucan` — UCAN 0.x (the embedded-JWT line, as implemented by ucan-wg/ts-ucan): Ed25519-signed capability tokens with audience-chained proofs.
- `agent-passport` — Action Receipts v1.1 from the agent-passport-system repo: Ed25519 receipts over their canonical JSON, with delegation chains, per-hop scope narrowing, and spend limits.

Gleipnir mandate support exists as an experimental skeleton and is not wired up. See Limitations.

## Quickstart

The package is not published to npm yet. To work from this repo:

```bash
cd source/receipt-interop
npm install
npm run build
```

Then, from a project that depends on it:

```ts
import { detectFormat, verifyReceipt } from 'receipt-interop';

const input = 'eyJhbGciOiJFUzI1NiIs...'; // a receipt in any supported format

const verdict = await verifyReceipt(input, {
  trustedIssuers: ['did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH'],
});

if (verdict.valid) {
  console.log('format:', verdict.format);
  console.log('issuer:', verdict.receipt!.issuer);
} else {
  console.error('rejected:', verdict.errors);
}
```

`detectFormat(input)` returns the format id (`'authproof-jws'`, `'ucan'`, `'agent-passport'`, or `'unknown'`) without touching cryptography. `normalize(input)` returns the NormalizedReceipt without verifying signatures; it throws on unrecognized input.

## Issuer convention

`NormalizedReceipt.issuer` carries the format's native identity string, and `trustedIssuers` is matched against that same string. There is no cross-format issuer translation.

| Format | `issuer` holds | `trustedIssuers` example |
|---|---|---|
| `authproof-jws` | RFC 7638 JWK thumbprint (base64url) of `signerPublicKey` | `trustedIssuers: ['8b8J3uQ...']` |
| `ucan` | the `iss` DID, e.g. `did:key:z6MkpTHR8VN...` | `trustedIssuers: ['did:key:z6MkpTHR8VN...']` |
| `agent-passport` | the executing agent's raw public key hex | `trustedIssuers: ['a1b2c3...']` (hex matched case-insensitively) |

If you need to compare issuers across formats, that is your job: the same key material appears as a DID in UCAN, a JWK thumbprint in authproof, and raw hex in agent-passport, and the library does not canonicalize between them.

## API reference

### detectFormat(input: unknown): FormatId | 'unknown'

Runs each registered verifier's `detect()` in registration order and returns the first id that claims the input. Never throws on hostile input. Returns `'unknown'` when nothing matches.

### verifyReceipt(input: unknown, opts?: VerifyOptions): Promise<Verdict>

Full verification for a single receipt: format detection, structural validation, signature check against the format's real cryptography (ES256 raw R||S for authproof, Ed25519 for UCAN and agent-passport), time-window check, and the optional issuer trust gate. Returns a `Verdict`:

```ts
{
  valid: boolean;                    // false if any check failed
  format: FormatId;                  // detected format, or 'unknown'
  receipt: NormalizedReceipt | null; // present when normalization succeeded
  errors: string[];                  // machine-readable failure codes
  warnings: string[];                // non-fatal notes, including every lossy mapping
}
```

### normalize(input: unknown): NormalizedReceipt

Structural normalization only. No signature verification. Throws `UNKNOWN_FORMAT` when no verifier recognizes the input. Use this when you need the common model for a receipt you verified elsewhere.

### verifyChain(inputs: unknown[], opts?: VerifyOptions): Promise<Verdict>

Verifies a delegation chain, root first and leaf last. Every hop is individually signature-verified, then chain rules run: parent-link integrity, depth limit, child time window inside parent window, and scope attenuation (child scope must be a strict narrowing of the parent). The returned verdict describes the leaf; chain detail lands in `warnings`. For authproof chains, sub-receipts carry their orchestrator signature in a `{ compact, orchestratorSignature }` wrapper and the chain resolves it against the parent key.

### VerifyOptions

```ts
{
  at?: Date;               // "now" for time-window checks; defaults to the current time
  checkRevocation?: boolean; // default false; see Limitations on revocation
  trustedIssuers?: string[]; // issuer allowlist, compared per the issuer convention above
  maxChainDepth?: number;    // adapter chain cap; default 5
}
```

### Extending

Custom formats register through `registerFormat(verifier)`, and `registeredFormats()` lists what is currently registered. A verifier is `{ id, detect, verify, normalize }`.

## Limitations

Plain and complete.

- **Revocation is offline and unknown by default.** None of the formats has a registry this library can query. Every receipt normalizes to `revocation.status: 'unknown'` unless the caller supplies signed revocation evidence (agent-passport supports caller-supplied evidence). Setting `checkRevocation: true` on an authproof receipt whose `revocationRequired` flag is set fails closed. There is no plan to bundle a registry: distribution is the issuer's problem.
- **UCAN 1.0 is out of scope.** The adapter covers the 0.x embedded-JWT line only. UCAN 1.0's IPLD-CID proofs need IPFS to resolve, which this library will not do; such input fails with a chain-break error, not a guess.
- **The COSE profile is not implemented.** authproof COSE_Sign1 input is detected and answered with `COSE_NOT_IMPLEMENTED`. It is never silently treated as verified.
- **Verification is not enforcement.** This library answers "is this receipt genuine?" It cannot answer "did the operator actually check it?" Treat the output as audit and attribution.
- **The normalized model is lossy.** Per-format native fields that do not fit the common model are dropped or noted; see `docs/LOSSY-MAPPINGS.md` and the `lossy` notes on every receipt. Never treat two normalized receipts as carrying identical meaning to their native originals.
- **Gleipnir support is experimental.** There is a module sketch and nothing more; it is exported but not registered, detects nothing, and verifies nothing. See `src/formats/gleipnir.ts`.
- **Attenuation semantics differ by format.** authproof chains use literal `operation::resource` narrowing per the draft; UCAN uses the reference default capability semantics (union across proofs); agent-passport uses the repo's `scopeCovers` narrowing rule. Cross-format chains are not supported: every hop in `verifyChain` is checked within its own format's rules.
- **Known draft contradiction.** The authproof draft's section 6.3 requires rejecting DER-encoded signatures, while its Appendix A publishes DER-encoded signatures. The library follows the normative text and rejects them. Details in `hidden_files/phase2-pr-summary.md`.
