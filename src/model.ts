// Shared model for the receipt-interop adapter.
// These interfaces are the contract every format verifier implements,
// including the sibling tracks (src/formats/ucan.ts, src/formats/agent-passport.ts).

export type FormatId =
  | 'authproof-jws'
  | 'authproof-cose'
  | 'ucan'
  | 'agent-passport'
  | 'gleipnir'
  | 'unknown';

export interface ScopeExpression {
  kind: 'structured' | 'text' | 'capability';
  actions: string[];
  resources: string[];
  constraints: Record<string, unknown>;
  text: string | null;
  enforced: boolean;
}

export interface NormalizedReceipt {
  format: FormatId;
  receiptId: string;
  issuer: string;
  issuerKey: { kty: string; crv: string; x: string; y?: string };
  agent: string | null;
  scope: ScopeExpression;
  boundaries: string[];
  notBefore: string;
  notAfter: string;
  instructionsHash: string | null;
  parentId: string | null;
  revocation: {
    required: boolean;
    pointer: string | null;
    status: 'unknown' | 'active' | 'revoked';
  };
  raw: unknown;
  lossy: string[];
}

export interface VerifyOptions {
  at?: Date;
  checkRevocation?: boolean;
  trustedIssuers?: string[];
  maxChainDepth?: number;
}

export interface Verdict {
  valid: boolean;
  format: FormatId;
  receipt: NormalizedReceipt | null;
  errors: string[];
  warnings: string[];
}

export interface FormatVerifier {
  id: FormatId;
  detect(input: unknown): boolean;
  verify(input: unknown, opts: VerifyOptions): Promise<Verdict>;
  normalize(input: unknown): NormalizedReceipt;
}
