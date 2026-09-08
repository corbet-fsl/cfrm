import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Identity } from '@semaphore-protocol/identity';
import { getCurveFromName } from 'ffjavascript';
import { freezeEligibility, acknowledgementContext, proveAcknowledgement,
  openAcknowledgementLedger, acceptAcknowledgement } from './acknowledgement.js';

const NOW = 1_800_000_000;
const id = text => createHash('sha256').update(text).digest('base64url');
const artifacts = { wasm: new URL('./.artifacts/semaphore.wasm', import.meta.url).pathname,
  zkey: new URL('./.artifacts/semaphore.zkey', import.meta.url).pathname };
let samplePromise;
let curve;
after(async () => { if (curve) await curve.terminate(); });

async function sample() {
  return samplePromise ??= (async () => {
    curve = await getCurveFromName('bn128');
    const identities = Array.from({ length: 100 }, (_, i) => new Identity(`synthetic-member-${i}`));
    const members = identities.map((identity, index) => ({ memberId: id(`member-${index}`), commitment: identity.commitment.toString() }));
    const snapshot = freezeEligibility({ communityId: 'community.example', epoch: 'epoch-1',
      notBefore: NOW, expiresAt: NOW + 60, members, minAnonymity: 16, depth: 7 });
    const senderId = members[0].memberId;
    const context = acknowledgementContext(snapshot, senderId);
    const start = performance.now();
    const proof = await proveAcknowledgement(identities[1], snapshot, context, artifacts);
    console.log(JSON.stringify({ measurement: 'proof-generation', groupMembers: 99,
      depth: 7, milliseconds: Math.round(performance.now() - start), serializedBytes: Buffer.byteLength(JSON.stringify(proof)) }));
    return { identities, members, snapshot, senderId, context, proof };
  })();
}
function ledger(t) {
  const directory = mkdtempSync(join(tmpdir(), 'cfrm-ack-'));
  const path = join(directory, 'ack.sqlite');
  const store = openAcknowledgementLedger(path);
  t.after(() => { store.close(); rmSync(directory, { recursive: true, force: true }); });
  return { store, path };
}

test('another member of the complete qualified set gives one real anonymous acknowledgement', async t => {
  const { snapshot, context, proof, members } = await sample();
  const { store } = ledger(t);
  assert.equal(await acceptAcknowledgement(snapshot, context, proof, store, () => NOW), true);
  assert.equal(store.credits(context.scope), 1);
  assert.deepEqual(Object.keys(proof).sort(), ['merkleTreeDepth', 'merkleTreeRoot', 'nullifier', 'message', 'scope', 'points'].sort());
  assert.equal(JSON.stringify(proof).includes(members[1].memberId), false);
  assert.equal(JSON.stringify(proof).includes(members[1].commitment), false);
});
test('sender self-credit, outsider credit and client-provided smaller subsets are rejected before proving', async () => {
  const { identities, snapshot, context, members } = await sample();
  await assert.rejects(proveAcknowledgement(identities[0], snapshot, context, artifacts));
  await assert.rejects(proveAcknowledgement(new Identity('outsider'), snapshot, context, artifacts));
  const subset = freezeEligibility({ ...snapshot, members: members.slice(0, 20) });
  const proposal = acknowledgementContext(subset, members[0].memberId);
  await assert.rejects(proveAcknowledgement(identities[1], snapshot, proposal, artifacts));
});
test('too-small sets, duplicate identities and duplicate member IDs fail closed', async () => {
  const { snapshot, members } = await sample();
  const small = freezeEligibility({ ...snapshot, members: members.slice(0, 10) });
  assert.throws(() => acknowledgementContext(small, members[0].memberId));
  assert.throws(() => freezeEligibility({ ...snapshot, members: [...members, members[0]] }));
  assert.throws(() => freezeEligibility({ ...snapshot,
    members: [...members.slice(0, 99), { memberId: members[99].memberId, commitment: members[0].commitment }] }));
  assert.throws(() => freezeEligibility({ ...snapshot,
    members: [...members.slice(0, 99), { memberId: members[99].memberId, commitment: '0' }] }));
});
test('parallel replay through independent connections produces exactly one durable credit', async t => {
  const { snapshot, context, proof } = await sample();
  const { store, path } = ledger(t);
  const other = openAcknowledgementLedger(path);
  t.after(() => other.close());
  const results = await Promise.all([
    acceptAcknowledgement(snapshot, context, proof, store, () => NOW),
    acceptAcknowledgement(snapshot, context, proof, other, () => NOW),
  ]);
  assert.deepEqual(results.sort(), [false, true]);
  assert.equal(other.credits(context.scope), 1);
  const resumed = openAcknowledgementLedger(path);
  try {
    assert.equal(await acceptAcknowledgement(snapshot, context, proof, resumed, () => NOW), false);
    assert.equal(resumed.credits(context.scope), 1);
  } finally { resumed.close(); }
});
test('a new epoch and roster do not reset lifetime pair uniqueness', async t => {
  const { snapshot, context, proof, identities, members } = await sample();
  const { store } = ledger(t);
  assert.equal(await acceptAcknowledgement(snapshot, context, proof, store, () => NOW), true);
  const later = freezeEligibility({ ...snapshot, epoch: 'epoch-2', notBefore: NOW + 60,
    expiresAt: NOW + 120, members: members.slice(0, 99) });
  const laterContext = acknowledgementContext(later, members[0].memberId);
  const laterProof = await proveAcknowledgement(identities[1], later, laterContext, artifacts);
  assert.equal(laterContext.scope, context.scope);
  assert.equal(laterProof.nullifier, proof.nullifier);
  assert.notEqual(laterProof.message, proof.message);
  assert.equal(await acceptAcknowledgement(later, laterContext, laterProof, store, () => NOW + 61), false);
  assert.equal(store.credits(context.scope), 1);
});
test('different senders use distinct scopes and independently bounded acknowledgement slots', async t => {
  const { snapshot, context, proof, identities, members } = await sample();
  const { store } = ledger(t);
  const other = acknowledgementContext(snapshot, members[2].memberId);
  const otherProof = await proveAcknowledgement(identities[1], snapshot, other, artifacts);
  assert.notEqual(other.scope, context.scope);
  assert.notEqual(otherProof.nullifier, proof.nullifier);
  assert.equal(await acceptAcknowledgement(snapshot, context, proof, store, () => NOW), true);
  assert.equal(await acceptAcknowledgement(snapshot, other, otherProof, store, () => NOW), true);
});
test('wrong sender, scope, snapshot root, message and forged proof cannot award credit', async t => {
  const { snapshot, context, proof, members } = await sample();
  const { store } = ledger(t);
  const wrong = acknowledgementContext(snapshot, members[2].memberId);
  assert.equal(await acceptAcknowledgement(snapshot, wrong, proof, store, () => NOW), false);
  for (const changed of [
    { ...proof, scope: '1' }, { ...proof, message: '1' }, { ...proof, merkleTreeRoot: '1' },
    { ...proof, points: ['1', ...proof.points.slice(1)] },
  ]) assert.equal(await acceptAcknowledgement(snapshot, context, changed, store, () => NOW), false);
  assert.equal(store.credits(context.scope), 0);
});
test('snapshot expiry is enforced again after proof verification before ledger credit', async t => {
  const { snapshot, context, proof } = await sample();
  const { store } = ledger(t);
  assert.equal(await acceptAcknowledgement(snapshot, context, proof, store, () => NOW - 1), false);
  assert.equal(await acceptAcknowledgement(snapshot, context, proof, store, () => NOW + 60), false);
  let calls = 0;
  assert.equal(await acceptAcknowledgement(snapshot, context, proof, store, () => ++calls === 1 ? NOW : NOW + 60), false);
  assert.equal(store.credits(context.scope), 0);
});
test('caller mutations cannot substitute a previously frozen eligible set', async () => {
  const { snapshot, members } = await sample();
  const copy = structuredClone(members);
  const frozen = freezeEligibility({ ...snapshot, members: copy });
  copy[0].commitment = '1';
  assert.notEqual(frozen.members[0].commitment, '1');
  assert.throws(() => { frozen.members[0].commitment = '1'; });
});

test('a changed proving artifact is rejected before executing its witness generator', async t => {
  const { snapshot, context, identities } = await sample();
  const directory = mkdtempSync(join(tmpdir(), 'cfrm-ack-artifact-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const changed = readFileSync(artifacts.wasm);
  changed[0] ^= 1;
  const path = join(directory, 'changed.wasm');
  writeFileSync(path, changed);
  await assert.rejects(proveAcknowledgement(identities[1], snapshot, context, { ...artifacts, wasm: path }));
});
