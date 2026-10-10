// Gleipnir mandate support — EXPERIMENTAL, design-only.
//
// Gleipnir (https://getgleipnir.com) is a pre-product startup in Vienna
// building "verifiable mandates for AI agents": a signed permission from a
// company officer that tells a counterparty which agent is approved, for
// what kind of action, up to what amount, and until when. As of October
// 2026 they have published no wire format or spec — only a product
// description and an interactive mockup on their site.
//
// Because there is no published format, this module does NOT invent one.
// detect() always returns false and verify() always answers NOT_IMPLEMENTED.
// The shape below sketches what an integration would need once Gleipnir
// publishes a real format, inferred from their public description:
//
//   - issuer: the company officer's signing key (identity: key material)
//   - agent: the agent's id, with the agent proving possession of its own key
//   - scope: action type + spend ceiling + expiry, e.g. "place purchase
//     orders, limit EUR 50,000 per order, expires 31 Dec 2026"
//   - approval authority: whether the signer was allowed to sign (their core
//     problem; maps to a company-register rule, not something a receipt
//     verifier can check offline)
//   - receipt: both sides keep a signed record of the check ("can you prove
//     it later" — closest to this library's NormalizedReceipt)
//
// This verifier is exported but deliberately NOT auto-registered in index.ts.
// Register it only if you are experimenting against a Gleipnir draft format:
//   import { gleipnirVerifier } from 'receipt-interop';
//   import { registerFormat } from 'receipt-interop';
//   registerFormat(gleipnirVerifier);
//
// Do not present any wire format as Gleipnir's; none exists yet.

import type { FormatVerifier, NormalizedReceipt, VerifyOptions, Verdict } from '../model.js';

export const GLEIPNIR_ERRORS = {
  NOT_IMPLEMENTED: 'GLEIPNIR_NOT_IMPLEMENTED',
} as const;

export const GLEIPNIR_WARNINGS = [
  'gleipnir support is experimental: no published mandate format exists as of 2026-10-09; this verifier is a placeholder only',
] as const;

export function detect(_input: unknown): boolean {
  // No published wire format to recognize.
  return false;
}

export async function verify(_input: unknown, _opts: VerifyOptions): Promise<Verdict> {
  return {
    valid: false,
    format: 'gleipnir',
    receipt: null,
    errors: [GLEIPNIR_ERRORS.NOT_IMPLEMENTED],
    warnings: [...GLEIPNIR_WARNINGS],
  };
}

export function normalize(_input: unknown): NormalizedReceipt {
  throw new Error(GLEIPNIR_ERRORS.NOT_IMPLEMENTED);
}

export const gleipnirVerifier: FormatVerifier = {
  id: 'gleipnir',
  detect,
  verify,
  normalize,
};
