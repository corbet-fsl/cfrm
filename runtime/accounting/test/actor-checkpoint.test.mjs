// Trusted-context boundary only. This does not substitute synthetic verdicts
// for account/peer proofs; the production actor still invokes both verifiers.
import test from 'node:test';
import assert from 'node:assert/strict';
import { accountActorPeerContext } from '../actor.mjs';

const root = byte => [...new Uint8Array(31), byte];
const current = Uint8Array.from(root(2));
const acceptance = { statement: { enrollmentRoot: root(1), now: 150 }, acceptedAt: 160 };
const context = () => ({ now: 250, expected: {}, accountPolicy: {}, enrollmentRoot: root(2), authorityExpiresAt: 300,
  acceptanceCheckpoint: { slot: 1, notBefore: 100, expiresAt: 200, root: root(1) } });

test('actor keeps the current roster pin separate from the independently authenticated acceptance checkpoint', () => {
  const input = context(), output = accountActorPeerContext(input, current, acceptance);
  assert.deepEqual(output.enrollmentRoot, root(1));
  assert.equal(Object.hasOwn(output, 'acceptanceCheckpoint'), false);
  assert.deepEqual(input.enrollmentRoot, root(2));
  input.acceptanceCheckpoint.root[31] = 9;
  input.expected.changed = true;
  assert.deepEqual(output.enrollmentRoot, root(1));
  assert.deepEqual(output.expected, {});
  const legacy = context(); delete legacy.acceptanceCheckpoint;
  assert.deepEqual(accountActorPeerContext(legacy, current, acceptance).enrollmentRoot, root(2));
  // The unchanged peer verifier still rejects that legacy root against the
  // old certificate. There is no automatic adoption of a peer-supplied root.
});

test('historical acceptance context cannot bypass current eligibility, certificate time or checkpoint identity', () => {
  for (const mutate of [
    value => { value.enrollmentRoot = root(1); },
    value => { value.authorityExpiresAt = value.now; },
    value => { value.acceptanceCheckpoint.root = root(3); },
    value => { value.acceptanceCheckpoint.root = [1]; },
    value => { value.acceptanceCheckpoint.slot = 2; },
    value => { value.acceptanceCheckpoint.notBefore = 151; },
    value => { value.acceptanceCheckpoint.expiresAt = 160; },
    value => { value.acceptanceCheckpoint.extra = true; },
    value => { value.now = 155; },
  ]) {
    const changed = context(); mutate(changed);
    assert.throws(() => accountActorPeerContext(changed, current, acceptance));
  }
  for (const acceptedAt of [149, 200, 251]) {
    assert.throws(() => accountActorPeerContext(context(), current, { ...acceptance, acceptedAt }));
  }
});
