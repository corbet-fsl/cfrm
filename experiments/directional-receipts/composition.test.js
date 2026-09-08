import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { compositionFixture, terminateCompositionCrypto, NativeRejection, same } from './composition-driver.js';
import { counters, nonce } from './attestation-fixtures.js';

after(terminateCompositionCrypto);
const options = { timeout: 240000 };
const success = { released: true, recipientJoined: true, decrypted: true,
  authenticatedSenderMatches: true, plaintextMatches: true, sameMaterial: true };
const release = (f, output, received) => f.bridge.call('finishRelease', {
  senderCommit: output.senderCommit, recipientRedemption: received.recipientRedemption,
});
const refused = promise => assert.rejects(promise,
  error => error instanceof NativeRejection && error.code === 'release-rejected',
  'A gate rejection must be explicit; a crashed or malformed native child is not a successful negative test');

async function accounted(f, s, preflight) {
  const action = await f.action(preflight);
  const output = await s.service.authorizeAndAcknowledge(action.request);
  const receipt = await action.finish(output);
  const redemption = await f.redemption(receipt);
  const received = await s.service.redeemAcknowledgedReceipt(redemption);
  assert.ok(received, 'Actual receipt redemption succeeds');
  f.checkStatements(output, received, action, preflight);
  return { action, output, redemption, received };
}

test('the same two native certified members enroll, commit both counters, and release authenticated MLS text', options, async t => {
  const f = await compositionFixture(t);
  const s = f.open();
  const preflight = await f.prepare();
  assert.deepEqual(s.count(0), counters());
  assert.deepEqual(s.count(1), counters());
  const action = await f.action(preflight);
  const output = await s.service.authorizeAndAcknowledge(action.request);
  assert.deepEqual(s.count(0), counters(1, 0));
  assert.deepEqual(s.count(1), counters());
  // Well-formed but unusable recipient statement cannot reveal the Welcome.
  const absentReceive = { recipientRedemption: { context: f.context, recipient: preflight.recipient,
    releaseNonce: preflight.releaseNonce, signature: '' } };
  await refused(release(f, output, absentReceive));
  assert.deepEqual(s.count(1), counters());

  const receipt = await action.finish(output);
  const redemption = await f.redemption(receipt);
  const received = await s.service.redeemAcknowledgedReceipt(redemption);
  assert.ok(received, 'Actual native-account receipt permission commits the receive counter');
  assert.deepEqual(s.count(1), counters(0, 1));
  f.checkStatements(output, received, action, preflight);
  const visibleReceive = JSON.stringify({ redemption, received });
  assert.ok(!visibleReceive.includes(f.members[0].memberId) && !visibleReceive.includes(f.members[0].chatPublicKey) &&
    !visibleReceive.includes(action.request.senderAuthorization.nonce) &&
    !visibleReceive.includes(action.request.senderAuthorization.requestHash) &&
    !visibleReceive.includes(action.request.semaphoreProof.nullifier),
  'Receiver service values have no explicit sender-side join');
  await refused(release(f, { ...output, senderCommit: { ...output.senderCommit, signature: '' } }, received));
  assert.ok(same(await release(f, output, received), success), 'Actual counter-backed statements unlock the exact native MLS peers');
  assert.deepEqual(s.ledger.counts(), { authorizations: 1, lifetimeNullifiers: 1, redeemedReceipts: 1 });
});

test('signed peer, request and private-challenge substitutions fail without destroying a valid native release retry', options, async t => {
  const f = await compositionFixture(t);
  const s = f.open();
  const preflight = await f.prepare();
  const { output, received } = await accounted(f, s, preflight);
  // These deliberately re-signed negative witnesses test pending-state binding,
  // not only signature corruption. They are not claimed as ledger attestations.
  for (const mutate of [
    value => { value.sender.memberId = f.members[2].memberId; },
    value => { value.sender.chatPublicKey = f.members[2].chatPublicKey; },
    value => { value.blindedRequestHash = nonce(); },
    value => { value.authorizationNonce = nonce(); },
  ]) {
    const changed = structuredClone(output.senderCommit);
    mutate(changed);
    await refused(release(f, { ...output, senderCommit: f.signNegativeSender(changed) }, received));
  }
  for (const mutate of [
    value => { value.recipient.memberId = f.members[2].memberId; },
    value => { value.recipient.chatPublicKey = f.members[2].chatPublicKey; },
    value => { value.releaseNonce = nonce(); },
    value => { value.context.cohortId = 'different-common-cohort'; },
  ]) {
    const changed = structuredClone(received.recipientRedemption);
    mutate(changed);
    await refused(release(f, output, { recipientRedemption: f.signNegativeRecipient(changed) }));
  }
  assert.ok(same(await release(f, output, received), success), 'The untouched actual statements still release the retained material');
  assert.deepEqual(s.count(0), counters(1, 0));
  assert.deepEqual(s.count(1), counters(0, 1));
});

test('encrypted native pending restore and exact ledger retries retain one debit and the original MLS material', options, async t => {
  const f = await compositionFixture(t);
  const first = f.open();
  const preflight = await f.prepare();
  const { action, output, redemption, received } = await accounted(f, first, preflight);
  first.ledger.close();
  const restored = await f.bridge.call('restorePending', {});
  assert.ok(same(restored, { restored: true, recipientHasWelcome: false }),
    'Native pending state restores locally without exporting its encrypted state or key');
  const reopened = f.open();
  const replayedOutput = await reopened.service.authorizeAndAcknowledge(action.request);
  const replayedReceive = await reopened.service.redeemAcknowledgedReceipt(redemption);
  assert.ok(same(output, replayedOutput), 'The issuance response recovers exactly after reopening the ledger');
  assert.ok(same(received, replayedReceive), 'The recipient attestation recovers exactly after reopening the ledger');
  assert.deepEqual(reopened.count(0), counters(1, 0));
  assert.deepEqual(reopened.count(1), counters(0, 1));
  assert.ok(same(await release(f, replayedOutput, replayedReceive), success), 'Restored pending material joins and decrypts');
  assert.ok(same(await release(f, replayedOutput, replayedReceive), success),
    'Native retry compares the same retained bytes without rejoining or processing an MLS replay');
  assert.deepEqual(reopened.ledger.counts(), { authorizations: 1, lifetimeNullifiers: 1, redeemedReceipts: 1 });
});
