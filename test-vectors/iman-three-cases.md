# Iman Schrock's three pinned unknown-field cases — implemented

**Status:** implemented in receipt-interop (commit pending review), all green.
**Source:** Iman Schrock's reply on the oauth@ietf.org thread, Oct 10, 2026, answering Ryan's unknown-fields question for the -12 revision.

Iman's framing, adopted verbatim: keep authorization fields closed, put optional extensions inside `metadata` (which draft -11 Section 4.3 already makes extensible). The three pinned cases below are implemented as first-class verifier behavior with unit tests and conformance vectors.

---

## Case 1 — `metadata.displayLabel` preserves the decision

**Behavior:** Unknown fields inside `metadata` are ignored by the verifier; the verification decision is identical with or without them. `metadata` is part of the signed payload (JCS-canonicalized with everything else), so a `displayLabel` is authenticated but never interpreted.

**Evidence:**
- Unit test: `metadata.displayLabel preserves the verification decision (Iman case 1)` — valid receipt, `valid: true`, zero errors.
- Vector: `iman-case-1-metadata-display-label` (draft section 4.3) — PASS.

## Case 2 — an uninterpretable authority constraint must not produce an allow

**Behavior:** Authorization fields are closed. An unknown top-level body field — e.g. `authorityConstraint: "m-of-2"`, even with a valid signature over the payload bytes — fails verification with **`UNKNOWN_BODY_FIELD`** (the offending field names are appended after a colon, e.g. `UNKNOWN_BODY_FIELD: authorityConstraint`). It never produces an allow and never silently drops the field.

**Evidence:**
- Unit test: `unknown top-level field fails with UNKNOWN_BODY_FIELD, never an allow (Iman case 2)` — `valid: false`.
- Vectors: `unknown-field-in-payload-rejected` and `iman-case-2-unknown-authority-field-rejected` (draft section 4.1) — PASS.

Note: this replaces the library's earlier behavior of rejecting unknown fields via the generic `PAYLOAD_NOT_JCS_CANONICAL` code. The rejection itself is unchanged; the code is now dedicated and quotable for the -12 draft text.

## Case 3 — `oneTimeUse: true` fails closed without a durable consumption store

**Behavior:** Per draft -11 Section 9.5, a receipt with `"oneTimeUse": true` authorizes at most one action globally, and enforcement requires a durable, shared consumption store. This verifier ships no consumption store, so the receipt is denied with **`CONSUMPTION_STORE_REQUIRED`** (fail closed). The check runs after every other check has passed, per Section 9.5's ordering rule — a consumption slot is never the reason a receipt fails for another cause, and a receipt that fails elsewhere is not additionally punished for `oneTimeUse`. `oneTimeUse: false` or absent verifies normally.

**Evidence:**
- Unit tests: `oneTimeUse:true fails closed with CONSUMPTION_STORE_REQUIRED (Iman case 3)` — `valid: false`; `oneTimeUse:false verifies normally` — `valid: true`.
- Vector: `iman-case-3-onetimeuse-fail-closed` (draft section 9.5) — PASS.

---

## Totals

- Unit tests: 4 new (1 per case, plus the `oneTimeUse:false` control) — full suite **120/120 pass** (was 116).
- Conformance vectors: 3 new + 1 updated — suite **45/45 pass** (was 42).
- `npm run build` (strict tsc): clean.
- Changed files: `src/formats/authproof.ts`, `test/authproof.test.ts`, `test-vectors/generate-vectors.mjs`, `test-vectors/vectors.json` (regenerated), `test-vectors/README.md`, `README.md`.

## What Ryan can tell Iman, verbatim if he likes

"All three cases are implemented in receipt-interop: metadata extensions are ignored with the decision unchanged; unknown top-level fields fail closed with UNKNOWN_BODY_FIELD; oneTimeUse:true fails closed with CONSUMPTION_STORE_REQUIRED since the verifier has no durable consumption store. 45/45 conformance vectors green, including one vector per case."
