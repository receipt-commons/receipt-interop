// Tests for verifyChain: delegation chains with real P-256 keys.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { base64urlEncode, jcsCanonicalize, sha256Hex } from '../src/crypto.js';
import { normalizeInstructions } from '../src/formats/authproof.js';
import { normalize, verifyChain } from '../src/index.js';

const AT = new Date('2026-10-09T12:30:00.000Z');

interface TestKey {
  priv: KeyObject;
  pubJwk: { kty: string; crv: string; x: string; y: string };
}

function genKey(): TestKey {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { priv: privateKey, pubJwk: publicKey.export({ format: 'jwk' }) as TestKey['pubJwk'] };
}

let chainCounter = 0;

function body(pubJwk: TestKey['pubJwk'], overrides: Record<string, unknown> = {}) {
  const instructions = 'Chain test instructions.';
  return {
    delegationId: `auth-chain-${++chainCounter}`,
    issuedAt: '2026-10-09T12:00:00.000Z',
    scope: 'chain scope',
    boundaries: 'never break the chain',
    timeWindow: { start: '2026-10-09T12:00:00.000Z', end: '2026-10-09T13:00:00.000Z' },
    operatorInstructions: instructions,
    instructionsHash: sha256Hex(Buffer.from(normalizeInstructions(instructions), 'utf8')),
    signerPublicKey: pubJwk,
    scopeSchema: {
      version: '1.0',
      allowedActions: [
        { operation: 'read', resource: 'calendar/events' },
        { operation: 'write', resource: 'calendar/drafts' },
        { operation: 'delete', resource: 'calendar/archive' },
      ],
      deniedActions: [{ operation: 'delete', resource: 'calendar/events' }],
    },
    ...overrides,
  };
}

function makeCompact(b: Record<string, unknown>, priv: KeyObject): string {
  const headerB64 = base64urlEncode(Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'drp-receipt' }), 'utf8'));
  const payloadB64 = base64urlEncode(Buffer.from(jcsCanonicalize(b), 'utf8'));
  const sig = sign('sha256', Buffer.from(`${headerB64}.${payloadB64}`, 'ascii'), {
    key: priv,
    dsaEncoding: 'ieee-p1363',
  });
  return `${headerB64}.${payloadB64}.${base64urlEncode(sig)}`;
}

function makeOrchestratorSig(parentPriv: KeyObject, parentId: string, childId: string): string {
  const binding = `orchestrator-delegation:${parentId}:${childId}`;
  const headerB64 = base64urlEncode(Buffer.from(JSON.stringify({ alg: 'ES256' }), 'utf8'));
  const payloadB64 = base64urlEncode(Buffer.from(binding, 'utf8'));
  const sig = sign('sha256', Buffer.from(`${headerB64}.${payloadB64}`, 'ascii'), {
    key: parentPriv,
    dsaEncoding: 'ieee-p1363',
  });
  return `${headerB64}.${payloadB64}.${base64urlEncode(sig)}`;
}

interface Chain {
  root: TestKey;
  child: TestKey;
  rootCompact: string;
  rootId: string;
  childBody: Record<string, unknown>;
  childCompact: string;
  childId: string;
  orchSig: string;
}

function buildChain(childOverrides: Record<string, unknown> = {}): Chain {
  const root = genKey();
  const child = genKey();
  const rootCompact = makeCompact(body(root.pubJwk), root.priv);
  const rootId = normalize(rootCompact).receiptId;
  const childBody = body(child.pubJwk, {
    delegationId: 'auth-chain-child',
    timeWindow: { start: '2026-10-09T12:15:00.000Z', end: '2026-10-09T12:45:00.000Z' },
    scopeSchema: {
      version: '1.0',
      allowedActions: [
        { operation: 'read', resource: 'calendar/events' },
        { operation: 'write', resource: 'calendar/drafts' },
      ],
      deniedActions: [{ operation: 'delete', resource: 'calendar/events' }],
    },
    parentReceiptId: rootId,
    ...childOverrides,
  });
  const childCompact = makeCompact(childBody, child.priv);
  const childId = normalize(childCompact).receiptId;
  const orchSig = makeOrchestratorSig(root.priv, rootId, childId);
  return { root, child, rootCompact, rootId, childBody, childCompact, childId, orchSig };
}

function childInput(c: Chain, orchSig: string | null = c.orchSig) {
  return orchSig === null
    ? { compact: c.childCompact }
    : { compact: c.childCompact, orchestratorSignature: orchSig };
}

// ---------------------------------------------------------------------------

test('valid 2-hop chain verifies; verdict describes the leaf', async () => {
  const c = buildChain();
  const verdict = await verifyChain([c.rootCompact, childInput(c)], { at: AT });
  assert.equal(verdict.valid, true);
  assert.deepEqual(verdict.errors, []);
  assert.equal(verdict.format, 'authproof-jws');
  assert.equal(verdict.receipt!.receiptId, c.childId);
  assert.equal(verdict.receipt!.parentId, c.rootId);
  assert.ok(verdict.warnings.some((w) => w.startsWith('CHAIN_OK')));
  assert.ok(verdict.warnings.includes('CHAIN_HOP_1_ORCHESTRATOR_SIG_OK'));
});

test('child granting an unheld key violates attenuation', async () => {
  const c = buildChain({
    scopeSchema: {
      version: '1.0',
      allowedActions: [
        { operation: 'read', resource: 'calendar/events' },
        { operation: 'admin', resource: 'everything' },
      ],
      deniedActions: [{ operation: 'delete', resource: 'calendar/events' }],
    },
  });
  const verdict = await verifyChain([c.rootCompact, childInput(c)], { at: AT });
  assert.equal(verdict.valid, false);
  assert.ok(
    verdict.errors.some((e) => e.includes('SCOPE_ATTENUATION_VIOLATED') && e.includes('admin::everything')),
    JSON.stringify(verdict.errors),
  );
});

test('child with equal scope size violates the strict-narrowing rule', async () => {
  const c = buildChain({
    scopeSchema: {
      version: '1.0',
      allowedActions: [
        { operation: 'read', resource: 'calendar/events' },
        { operation: 'write', resource: 'calendar/drafts' },
        { operation: 'delete', resource: 'calendar/archive' },
      ],
      deniedActions: [{ operation: 'delete', resource: 'calendar/events' }],
    },
  });
  const verdict = await verifyChain([c.rootCompact, childInput(c)], { at: AT });
  assert.equal(verdict.valid, false);
  assert.ok(verdict.errors.some((e) => e.includes('SCOPE_ATTENUATION_VIOLATED')));
});

test('child dropping a parent denial violates attenuation', async () => {
  const c = buildChain({
    scopeSchema: {
      version: '1.0',
      allowedActions: [{ operation: 'read', resource: 'calendar/events' }],
      deniedActions: [],
    },
  });
  const verdict = await verifyChain([c.rootCompact, childInput(c)], { at: AT });
  assert.equal(verdict.valid, false);
  assert.ok(
    verdict.errors.some((e) => e.includes('SCOPE_ATTENUATION_VIOLATED') && e.includes('delete::calendar/events')),
    JSON.stringify(verdict.errors),
  );
});

test('child window outside the parent window violates containment', async () => {
  const c = buildChain({
    timeWindow: { start: '2026-10-09T11:00:00.000Z', end: '2026-10-09T14:00:00.000Z' },
  });
  const verdict = await verifyChain([c.rootCompact, childInput(c)], { at: AT });
  assert.equal(verdict.valid, false);
  assert.ok(verdict.errors.some((e) => e.includes('WINDOW_CONTAINMENT_VIOLATED')));
});

test('missing orchestratorSignature fails the chain', async () => {
  const c = buildChain();
  const verdict = await verifyChain([c.rootCompact, childInput(c, null)], { at: AT });
  assert.equal(verdict.valid, false);
  assert.ok(verdict.errors.some((e) => e.includes('ORCHESTRATOR_SIG_MISSING')));
});

test('forged orchestratorSignature fails the chain', async () => {
  const c = buildChain();
  // Bind to the wrong child id: the signature is real but for another pair.
  const forged = makeOrchestratorSig(c.root.priv, c.rootId, 'deadbeef');
  const verdict = await verifyChain([c.rootCompact, childInput(c, forged)], { at: AT });
  assert.equal(verdict.valid, false);
  assert.ok(verdict.errors.some((e) => e.includes('ORCHESTRATOR_SIG_INVALID')));
});

test('chain depth limit is enforced', async () => {
  const c = buildChain();
  const verdict = await verifyChain([c.rootCompact, childInput(c)], { at: AT, maxChainDepth: 1 });
  assert.equal(verdict.valid, false);
  assert.ok(verdict.errors.some((e) => e.includes('CHAIN_DEPTH_EXCEEDED')));
});

test('broken hop signature is reported per hop', async () => {
  const c = buildChain();
  const parts = c.childCompact.split('.');
  const broken = `${parts[0]}.${parts[1]}.${base64urlEncode(Buffer.alloc(64, 7))}`;
  const verdict = await verifyChain([c.rootCompact, { compact: broken, orchestratorSignature: c.orchSig }], {
    at: AT,
  });
  assert.equal(verdict.valid, false);
  assert.ok(verdict.errors.some((e) => e.startsWith('CHAIN_HOP_1_INVALID')));
});

test('empty chain is rejected', async () => {
  const verdict = await verifyChain([], { at: AT });
  assert.equal(verdict.valid, false);
  assert.deepEqual(verdict.errors, ['EMPTY_CHAIN']);
});

test('single-hop chain (root only) verifies', async () => {
  const c = buildChain();
  const verdict = await verifyChain([c.rootCompact], { at: AT });
  assert.equal(verdict.valid, true);
  assert.equal(verdict.receipt!.receiptId, c.rootId);
});
