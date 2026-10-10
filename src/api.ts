// Verifier registry and top-level entry points.
// Format modules (including the sibling ucan.ts and agent-passport.ts tracks)
// register themselves via registerFormat; index.ts registers the built-ins.

import type {
  FormatId,
  FormatVerifier,
  NormalizedReceipt,
  Verdict,
  VerifyOptions,
} from './model.js';
import { verifyOrchestratorSignature } from './formats/authproof.js';

const registry = new Map<FormatId, FormatVerifier>();

export function registerFormat(v: FormatVerifier): void {
  registry.set(v.id, v);
}

export function registeredFormats(): FormatId[] {
  return [...registry.keys()];
}

export function detectFormat(input: unknown): FormatId | 'unknown' {
  for (const v of registry.values()) {
    try {
      if (v.detect(input)) return v.id;
    } catch {
      // A detector must never throw on foreign input; treat as non-match.
    }
  }
  return 'unknown';
}

// Structural normalization only: no signature verification is performed.
export function normalize(input: unknown): NormalizedReceipt {
  const id = detectFormat(input);
  const v = registry.get(id as FormatId);
  if (!v) throw new Error('UNKNOWN_FORMAT');
  return v.normalize(input);
}

const DEFAULT_OPTS: Required<Pick<VerifyOptions, 'checkRevocation' | 'maxChainDepth'>> = {
  checkRevocation: false,
  maxChainDepth: 5,
};

export function resolveOptions(opts?: VerifyOptions): VerifyOptions & {
  at: Date;
  checkRevocation: boolean;
  maxChainDepth: number;
} {
  return {
    at: opts?.at ?? new Date(),
    checkRevocation: opts?.checkRevocation ?? DEFAULT_OPTS.checkRevocation,
    trustedIssuers: opts?.trustedIssuers,
    maxChainDepth: opts?.maxChainDepth ?? DEFAULT_OPTS.maxChainDepth,
  };
}

export async function verifyReceipt(input: unknown, opts?: VerifyOptions): Promise<Verdict> {
  const id = detectFormat(input);
  const v = registry.get(id as FormatId);
  if (!v) {
    return { valid: false, format: 'unknown', receipt: null, errors: ['UNKNOWN_FORMAT'], warnings: [] };
  }
  return v.verify(input, resolveOptions(opts));
}

// Verifies a delegation chain: inputs[0] is the root, inputs[n-1] the leaf.
// Each hop is signature-verified, then chain rules are applied:
// parent-link integrity, depth limit, child-in-parent window containment,
// and scope attenuation (child scope a strict proper subset of parent).
// The returned verdict describes the leaf; chain detail goes in warnings.
export async function verifyChain(inputs: unknown[], opts?: VerifyOptions): Promise<Verdict> {
  const o = resolveOptions(opts);
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!Array.isArray(inputs) || inputs.length === 0) {
    return { valid: false, format: 'unknown', receipt: null, errors: ['EMPTY_CHAIN'], warnings };
  }

  const hops: Verdict[] = [];
  for (let i = 0; i < inputs.length; i++) {
    const verdict = await verifyReceipt(inputs[i], o);
    hops.push(verdict);
    if (!verdict.valid) {
      errors.push(`CHAIN_HOP_${i}_INVALID: ${verdict.errors.join('; ')}`);
    }
  }

  const receipts = hops.map((h) => h.receipt);
  const leaf = hops[hops.length - 1];
  const leafReceipt = leaf.receipt;

  if (errors.length === 0) {
    for (let i = 1; i < receipts.length; i++) {
      const parent = receipts[i - 1]!;
      const child = receipts[i]!;
      const tag = `CHAIN_HOP_${i}`;

      // Depth: the root is depth 0; a receipt at index i sits at depth i.
      if (i >= o.maxChainDepth) {
        errors.push(`${tag}_CHAIN_DEPTH_EXCEEDED: depth ${i} >= maxChainDepth ${o.maxChainDepth}`);
        continue;
      }

      // Parent-link integrity.
      if (child.parentId === null) {
        errors.push(`${tag}_PARENT_LINK_MISSING: hop ${i} carries no parentReceiptId`);
      } else if (child.parentId !== parent.receiptId) {
        errors.push(
          `${tag}_PARENT_LINK_MISMATCH: child parentId ${child.parentId} != parent receiptId ${parent.receiptId}`,
        );
      }

      // Window containment: child window inside parent window.
      const pStart = Date.parse(parent.notBefore);
      const pEnd = Date.parse(parent.notAfter);
      const cStart = Date.parse(child.notBefore);
      const cEnd = Date.parse(child.notAfter);
      if (!(cStart >= pStart && cEnd <= pEnd)) {
        errors.push(
          `${tag}_WINDOW_CONTAINMENT_VIOLATED: child [${child.notBefore}, ${child.notAfter}] not within parent [${parent.notBefore}, ${parent.notAfter}]`,
        );
      }

      // Scope attenuation: child scope a strict proper subset of parent scope.
      const att = checkAttenuation(parent, child);
      if (att.violations.length > 0) {
        errors.push(`${tag}_SCOPE_ATTENUATION_VIOLATED: ${att.violations.join('; ')}`);
      } else if (att.unchecked) {
        warnings.push(`${tag}_SCOPE_ATTENUATION_UNCHECKED: text-only scope cannot be machine-checked`);
      }

      // Orchestrator signature: resolves the ORCHESTRATOR_SIG_DEFERRED_TO_CHAIN
      // warning from single-hop verification. The parent key is now available.
      const orch = (inputs[i] as { orchestratorSignature?: unknown } | null)?.orchestratorSignature;
      if (typeof orch === 'string' && child.format === 'authproof-jws') {
        const ok = verifyOrchestratorSignature(parent, child, orch);
        if (!ok) errors.push(`${tag}_ORCHESTRATOR_SIG_INVALID`);
        else warnings.push(`${tag}_ORCHESTRATOR_SIG_OK`);
      } else if (child.parentId !== null && child.format === 'authproof-jws') {
        errors.push(`${tag}_ORCHESTRATOR_SIG_MISSING: sub-receipt carries no orchestratorSignature`);
      }
    }
    if (receipts[0]!.parentId !== null) {
      warnings.push('CHAIN_ROOT_HAS_PARENT: first hop carries parentReceiptId; chain may be partial');
    }
    warnings.push(`CHAIN_OK: ${receipts.length} hop(s), max depth ${hops.length - 1}`);
  }

  return {
    valid: errors.length === 0,
    format: leaf.format,
    receipt: leafReceipt,
    errors,
    warnings,
  };
}

interface AttenuationResult {
  violations: string[];
  unchecked: boolean;
}

// Draft -11 section 8.5: comparison on literal "operation::resource" keys.
// Both receipts must carry structured scopes; otherwise the check cannot run.
export function checkAttenuation(
  parent: NormalizedReceipt,
  child: NormalizedReceipt,
): AttenuationResult {
  const violations: string[] = [];
  if (parent.scope.kind !== 'structured' || child.scope.kind !== 'structured') {
    return { violations, unchecked: true };
  }
  const parentAllowed = allowedKeys(parent);
  const childAllowed = allowedKeys(child);
  for (const k of childAllowed) {
    if (!parentAllowed.has(k)) violations.push(`child grants unheld key ${k}`);
  }
  if (childAllowed.size >= parentAllowed.size) {
    violations.push(
      `child allowedActions (${childAllowed.size}) not strictly fewer than parent (${parentAllowed.size})`,
    );
  }
  const parentDenied = deniedKeys(parent);
  const childDenied = deniedKeys(child);
  for (const k of parentDenied) {
    if (!childDenied.has(k)) violations.push(`child dropped parent denial ${k}`);
  }
  return { violations, unchecked: false };
}

// The normalized model does not carry deniedActions verbatim, so denial sets
// are recovered from the authproof mapping's lossy notes (each denied entry is
// recorded as "DENIED:<operation>::<resource>"). Formats that do not emit
// those notes simply contribute an empty denial set.
function allowedKeys(r: NormalizedReceipt): Set<string> {
  const s = new Set<string>();
  for (let i = 0; i < r.scope.actions.length; i++) {
    const res = r.scope.resources[i] ?? '';
    s.add(`${r.scope.actions[i]}::${res}`);
  }
  return s;
}

function deniedKeys(r: NormalizedReceipt): Set<string> {
  const s = new Set<string>();
  for (const note of r.lossy) {
    const m = /^DENIED:([^:]+)::(.+)$/.exec(note);
    if (m) s.add(`${m[1]}::${m[2]}`);
  }
  return s;
}
