// receipt-interop: neutral verification adapter for AI agent delegation receipts.
//
// Built-in formats are registered on import. Sibling format tracks
// (src/formats/ucan.ts, src/formats/agent-passport.ts) export their
// FormatVerifier as the default export and are registered below.

export * from './model.js';
export {
  base64urlDecode,
  base64urlEncode,
  ecJwkThumbprint,
  ed25519Verify,
  es256Verify,
  jcsCanonicalize,
  okpJwkThumbprint,
  sha256Hex,
} from './crypto.js';
export {
  checkAttenuation,
  detectFormat,
  normalize,
  registerFormat,
  registeredFormats,
  resolveOptions,
  verifyChain,
  verifyReceipt,
} from './api.js';
export {
  authproofCose,
  authproofJws,
  normalizeAuthproof,
  normalizeInstructions,
  verifyOrchestratorSignature,
} from './formats/authproof.js';

import { registerFormat } from './api.js';
import { authproofCose, authproofJws } from './formats/authproof.js';
import ucanVerifier from './formats/ucan.js';
import agentPassportVerifier from './formats/agent-passport.js';

// Gleipnir is deliberately NOT registered here. It is experimental and has
// no published mandate format, so its verifier can detect and verify
// nothing. It is exported from './formats/gleipnir.js' (see that module)
// and you may registerFormat() it yourself only while experimenting.
export { gleipnirVerifier } from './formats/gleipnir.js';

registerFormat(authproofJws);
registerFormat(authproofCose);
registerFormat(ucanVerifier);
registerFormat(agentPassportVerifier);
