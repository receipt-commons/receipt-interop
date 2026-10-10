# Agent-passport vectors run + issue #216 findings — verification report

Date: 2026-10-10. Vectors: `action-receipt-vectors-v1.1.json` at
agent-passport-system commit `949d77dd32024391192556e248ec9a25d863f8fe`
(22 cases: 12 delegation, 10 receipt). SDK reference commit `c31d94a`.
All work local; nothing posted to GitHub.

## 1. Vector run against the adapter (three layers)

### L1 — raw wire records through `verify()` as-is
All 9 camelCase receipt records → `AP_UNKNOWN_FORMAT` (`receipt.receipt_id
must be a string`). The 1 snake_case record (`receipt-snake-case-spelling`)
parses, then fails `AP_BAD_SIGNATURE` — matching their recorded `invalid`
(their own vector documents that re-spelling without re-signing breaks the
signature, since key names are inside the canonical bytes).

Practical impact of finding #1: **the adapter cannot read a single receipt
their TS SDK actually emits.** Every live v1.1 receipt is camelCase.

### L2 — canonicalization agreement
The adapter's `apsCanonicalize` reproduces their `signature_preimage_text`
**byte-for-byte on all 4 published preimages** (2 delegations, 2 receipts).
Canonical JSON is in full agreement; the wire-spelling split is purely a
member-naming issue, not a crypto or canonicalization issue.

### L3 — semantic re-mint (22 cases re-minted in the adapter's wire shape
with the vector keys, `at` pinned to their `verification_instant`
2026-10-10T12:00:00.000Z; receipts signed with the vector private keys)

**18/24 agree** on valid/invalid (the 2 extra rows are the
wider-than-parent records run as children — see below).

| Case | Theirs (function) | Adapter | Notes |
|---|---|---|---|
| valid-root-delegation | valid | valid | agree |
| valid-child-delegation | valid | valid | agree |
| delegation-expired | invalid | invalid (AP_EXPIRED) | agree |
| delegation-expires-at-verification-instant | valid | valid | agree — both use strict `<`/`>` (boundary valid) |
| delegation-not-yet-valid | invalid | invalid (AP_NOT_YET_VALID) | agree |
| delegation-not-before-at-verification-instant | valid | valid | agree |
| delegation-signed-by-other-key | invalid | invalid (AP_BAD_SIGNATURE) | agree |
| delegation-depth-exceeded | invalid | invalid (AP_DEPTH_EXCEEDED) | agree |
| delegation-grandchild-beyond-depth | invalid | invalid (AP_DEPTH_EXCEEDED) | agree |
| delegation-scope-wider-than-parent (lone) | valid | valid | agree at record level |
| delegation-spend-wider-than-parent (lone) | valid | valid | agree at record level |
| **delegation-without-max-depth-at-depth-64** | **valid** | **invalid (AP_DEPTH_EXCEEDED)** | **genuine divergence — finding #2** |
| delegation-scope-wider-than-parent (as child) | valid | invalid (AP_NARROWING_VIOLATION) | documented scope difference (below) |
| delegation-spend-wider-than-parent (as child) | valid | invalid (AP_NARROWING_VIOLATION) | documented scope difference (below) |
| valid-receipt-under-root | valid | valid | agree |
| valid-receipt-under-child | valid | valid | agree |
| receipt-tampered-spend | invalid | invalid (AP_BAD_SIGNATURE) | agree |
| receipt-signed-by-other-key | invalid | invalid (AP_BAD_SIGNATURE) | agree |
| receipt-version-1.0 | invalid | invalid (AP_UNSUPPORTED_VERSION) | agree |
| receipt-snake-case-spelling | invalid | invalid (AP_BAD_SIGNATURE) | agree (fails at sig, not parse) |
| receipt-scope-not-delegated | valid | invalid (AP_SCOPE_VIOLATION) | documented scope difference |
| receipt-spend-over-budget | valid | invalid (AP_OVER_BUDGET) | documented scope difference |
| receipt-under-expired-delegation | valid | invalid (AP_EXPIRED) | documented scope difference |
| receipt-chain-not-validated | valid | valid | agree — **neither** validates the `delegationChain` fingerprint list |

**On the "documented scope differences":** their vectors record what ONE
function returned (`verifyReceipt` = signature + version only;
`verifyDelegation` = one record alone, parent never consulted). Their own
`how_to_read` says "A `valid: true` here is one function's result. No case
establishes that an action was authorized." The adapter's `verify()` is a
full-chain verifier (chain binding, scope narrowing, spend, windows), so it
refuses things their per-record functions accept. Both sides are behaving
as documented; these are not bugs. Worth stating plainly in any joint
conformance doc: their vectors pin per-function behavior, the adapter pins
end-to-end verification behavior.

## 2. Finding #3 (revocation) — CONFIRMED and FIXED

Reproduced with throwaway Ed25519 keys before the fix:

- Revocation for an **unrelated delegation**, validly signed by an unrelated
  key → `revocation.status` was `"active"` (should be `"unknown"`).
- Revocation **naming the chain's delegation** but signed by a
  **non-delegator key** → `"active"` (should be `"unknown"`).
- Controls: genuine revocation (in-chain + delegator-signed) → correctly
  `AP_REVOKED`/invalid; no evidence → correctly `"unknown"` with
  `REVOCATION_UNCHECKED_OFFLINE`.

Root cause: `evidenceSeen = true` was set for **any** validly-signed
revocation record, before the in-chain and delegator-signature checks.

Fix (`src/formats/agent-passport.ts`): `evidenceSeen` is now set only
after the record passes both gates — (a) it names a delegation in the
chain, and (b) it is signed by that delegation's delegator key. Irrelevant
records are ignored with a warning and leave the status at `"unknown"`.
Post-fix repro: scenarios A and B → `"unknown"`; genuine revocation still
revokes; no-evidence behavior unchanged.

Test changes (`test/agent-passport.test.ts`): the old test
"honors supplied revocation evidence (clean chain => active)" asserted the
buggy behavior and was replaced by two regression tests, one per
maintainer scenario. Suite: **116/116 pass** (was 115; +1 net test),
`npm run build` clean.

Note: with the fix, `revocation.status === "active"` is effectively
unreachable via supplied revocation *records* (genuine ones always revoke
the named delegation, failing the verdict). The branch is kept for a
future signed non-revocation attestation, if the spec ever defines one.

## 3. Finding #1 (camelCase vs snake_case) — assessment, no parser change

Confirmed from their vectors + PR #217 errata:
- Their TS SDK at `c31d94a` emits **and signs camelCase** for receipts
  (`receiptId`, `agentId`, `delegationId`, `action.scopeUsed`,
  `delegationChain`) and delegations.
- Their SPEC-v1.1 doc shows **snake_case** (`receipt_id`, …).
- The adapter's parser requires snake_case receipts (camelCase delegations
  — matching their TS `Delegation` type). So the adapter verifies the
  *document's* shape, not the *shipped SDK's* shape.
- The v1.1 family is **frozen/legacy** per the vectors file's own status
  line ("Legacy, pre-draft, frozen. Not on the draft-pidlisnyi-aps path"),
  so the SDK's camelCase output is the final word on what exists.

**Options:**
- **A. Accept both spellings; verify the signature over the exact received
  bytes.** Security is unchanged: key names are inside the canonical
  bytes, so a forged re-spelling still fails (their
  `receipt-snake-case-spelling` vector keeps failing under A). Reject
  records that mix both spellings as ambiguous. Record the observed
  spelling in the normalized output's lossy log. `detect()` accepts both.
- **B. Stay snake_case-only.** Defensible as "we implement the document,"
  but it leaves the adapter unable to verify the only v1.1 receipts that
  exist in the wild — a hollow interop story.
- **C. Strict default + opt-in compat flag** (e.g.
  `VerifyOptions.acceptCamelCaseReceipts`). Middle path; adds API surface
  for a frozen legacy family.

**Recommendation: Option A.** The adapter's job is to verify what exists,
and what exists is camelCase; the signature covers the spelling, so
nothing is weakened. The doc-vs-SDK divergence is their errata's problem,
and the adapter can note which spelling it saw. If Ryan + aeoess agree the
frozen family should be read strictly per the doc, fall back to B — but
then say so explicitly in the README's limitations.

## 4. Finding #2 (maxDepth) — confirmed, no change

Their vectors file (`what_each_function_checks.max_depth`) and PR #217
errata both state it: `createDelegation` **writes** `maxDepth: 1` when the
caller omits it, but `verifyDelegation` applies **no ceiling** when
`maxDepth` is absent ("the writer default and the reader behaviour are not
equivalent"). The adapter defaults read-time to 1 (`d.maxDepth ?? 1`),
following SPEC-v1.1 §3.4 and their reference code — but not their
`verifyDelegation`. L3 proves the divergence:
`delegation-without-max-depth-at-depth-64` → theirs valid, adapter
`AP_DEPTH_EXCEEDED`.

Three-way split worth flagging to aeoess: the doc says default 1, the TS
verifier enforces nothing when absent, their **Python SDK reads absent as
0** (per PR #217). The adapter sides with the doc. No code change made;
this is a spec-ambiguity item for the joint conformance discussion (and a
candidate for the draft's -12 unknown-fields/depth-default notes).

## Working-tree state (commit-ready)

- `src/formats/agent-passport.ts` — revocation evidence gating fix only.
- `test/agent-passport.test.ts` — 1 test replaced with 2 regression tests.
- `npm test`: 116/116 pass. `npm run build`: clean.
- This report: `test-vectors/agent-passport-vectors-report.md`.
- Not committed, not pushed, nothing posted to GitHub.
