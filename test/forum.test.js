import test from 'node:test';
import assert from 'node:assert/strict';
import { ForumExperiment } from '../src/forum.js';

const policy = {
  initialTokens: 3, epochGrant: 2, maxEpochGrant: 6, tokenCap: 8,
  growthPerActiveEpoch: 1, maxImbalance: 3, pendingCap: 3,
  requestTtl: 5, presenceTtl: 20, voting: false,
  imbalanceEpochs: 0,
};
function fixture(overrides = {}, ids = ['a', 'b', 'c', 'd', 'e']) {
  const admitted = new Set(ids);
  const forum = new ForumExperiment({ ...policy, ...overrides }, id => admitted.has(id));
  for (const id of ids) forum.connect(id, 0);
  return { forum, admitted };
}
function exchange(forum, a = 'a', b = 'b', now = 1) {
  assert.equal(forum.introduce(a, b, now), 'delivered');
  assert.equal(forum.accept(b, a, now), 'accepted');
  assert.equal(forum.reply(b, a, now), 'replied');
}

test('ineligible visitors cannot join or act and expiry is rechecked', () => {
  const { forum, admitted } = fixture();
  assert.equal(forum.connect('outsider', 0), false);
  assert.equal(forum.introduce('outsider', 'b', 1), 'ineligible');
  admitted.delete('a');
  assert.equal(forum.introduce('a', 'b', 1), 'ineligible');
  assert.ok(!forum.roster(1).includes('a'));
});
test('presence vanishes on disconnect or lease expiry, accounting survives', () => {
  const { forum } = fixture();
  forum.introduce('a', 'b', 1);
  forum.disconnect('a');
  assert.ok(!forum.roster(2).includes('a'));
  assert.equal(forum.introduce('a', 'c', 2), 'offline');
  assert.equal(forum.connect('a', 2), true);
  assert.equal(forum.state('a').tokens, 2);
  assert.deepEqual(forum.roster(22), []);
  assert.equal(forum.state('a').sent, 1);
});
test('only a new first approach consumes a token; replay does not recharge', () => {
  const { forum } = fixture();
  exchange(forum);
  const before = forum.state('a');
  assert.equal(forum.introduce('a', 'b', 2), 'established');
  assert.equal(forum.introduce('b', 'a', 2), 'established');
  assert.equal(forum.reply('b', 'a', 2), 'duplicate');
  assert.deepEqual(forum.state('a'), before);
  assert.equal(forum.state('a').tokens, 2);
  assert.equal(forum.state('b').tokens, 3);
});
test('unsolicited delivery never worsens the recipient balance', () => {
  const { forum } = fixture();
  const before = forum.state('b');
  forum.introduce('a', 'b', 1);
  assert.deepEqual(forum.state('b'), before);
  assert.equal(forum.accept('b', 'a', 1), 'accepted');
  assert.equal(forum.state('b').received, 1);
});
test('acceptance and first reply each count once and cannot be applied in reverse', () => {
  const { forum } = fixture();
  forum.introduce('a', 'b', 1);
  assert.equal(forum.accept('a', 'b', 1), 'missing');
  assert.equal(forum.accept('b', 'a', 1), 'accepted');
  assert.equal(forum.accept('b', 'a', 1), 'duplicate');
  assert.equal(forum.reply('a', 'b', 1), 'missing');
  assert.equal(forum.reply('b', 'a', 1), 'replied');
  assert.equal(forum.state('a').sent, 1);
  assert.equal(forum.state('a').received, 1);
  assert.equal(forum.state('b').sent, 1);
  assert.equal(forum.state('b').received, 1);
});
test('zero-token recipients can reply and recover an inbound imbalance', () => {
  const { forum } = fixture({ initialTokens: 1, maxImbalance: 1 });
  forum.introduce('b', 'c', 1);
  forum.introduce('a', 'b', 1);
  forum.accept('b', 'a', 1);
  assert.equal(forum.state('b').tokens, 0);
  assert.equal(forum.reply('b', 'a', 1), 'replied');
  assert.equal(forum.state('a').received, 1);
});
test('outbound and accepted inbound imbalance have symmetric limits', () => {
  const { forum } = fixture({ initialTokens: 8, maxImbalance: 1 });
  forum.introduce('a', 'b', 1);
  assert.equal(forum.introduce('a', 'c', 1), 'outbound-imbalance');
  forum.accept('b', 'a', 1);
  forum.introduce('c', 'b', 1);
  assert.equal(forum.accept('b', 'c', 1), 'inbound-imbalance');
  assert.equal(forum.reply('b', 'a', 1), 'replied');
  assert.equal(forum.accept('b', 'c', 1), 'accepted');
  assert.equal(forum.introduce('a', 'd', 1), 'delivered');
});
test('pending cap and recipient closure limit pile-ons without charging rejected delivery', () => {
  const { forum } = fixture({ pendingCap: 1 });
  forum.introduce('a', 'b', 1);
  assert.equal(forum.introduce('c', 'b', 1), 'inbox-full');
  assert.equal(forum.state('c').tokens, 3);
  forum.setOpen('b', false);
  assert.equal(forum.introduce('d', 'b', 1), 'closed');
  assert.equal(forum.accept('b', 'a', 1), 'accepted');
  assert.equal(forum.reply('b', 'a', 1), 'replied');
});
test('expired delivered introductions never refund tokens or permit recycled first contact', () => {
  const { forum } = fixture();
  forum.introduce('a', 'b', 1);
  assert.equal(forum.accept('b', 'a', 6), 'expired');
  assert.equal(forum.state('a').tokens, 2);
  assert.equal(forum.introduce('a', 'b', 6), 'already-contacted');
  assert.equal(forum.introduce('b', 'a', 6), 'already-contacted');
});
test('declines and local blocks do not create reports or standing penalties', () => {
  const { forum } = fixture();
  forum.introduce('a', 'b', 1);
  const before = forum.state('a');
  assert.equal(forum.decline('b', 'a', 1), 'declined');
  assert.deepEqual(forum.state('a'), before);
  forum.block('c', 'a');
  assert.equal(forum.introduce('a', 'c', 1), 'blocked');
  forum.disconnect('a');
  forum.connect('a', 2);
  assert.equal(forum.introduce('a', 'c', 2), 'blocked');
  assert.deepEqual(forum.state('a'), before);
});
test('self contact is rejected and a blocked accepted sender cannot receive a reply', () => {
  const { forum } = fixture();
  assert.equal(forum.introduce('a', 'a', 1), 'self');
  forum.introduce('a', 'b', 1);
  forum.accept('b', 'a', 1);
  forum.block('a', 'b');
  assert.equal(forum.reply('b', 'a', 1), 'blocked');
  assert.equal(forum.state('a').received, 0);
});
test('idle epochs never earn maturity and accumulated tokens are capped', () => {
  const { forum } = fixture();
  for (let i = 0; i < 30; i++) forum.advanceEpoch();
  assert.equal(forum.state('a').activeEpochs, 0);
  assert.equal(forum.state('a').tokens, 8);
});
test('use earns at most one maturity step per epoch, with bounded grants', () => {
  const { forum } = fixture({ initialTokens: 8 });
  exchange(forum, 'a', 'b');
  exchange(forum, 'a', 'c');
  forum.advanceEpoch();
  assert.equal(forum.state('a').activeEpochs, 1);
  assert.equal(forum.state('a').grantTotal, 11);
  assert.equal(forum.state('a').tokens, 8);
  forum.advanceEpoch();
  assert.equal(forum.state('a').activeEpochs, 1);
});
test('reconnecting cannot reset allowance, history, maturity or governance votes', () => {
  const { forum } = fixture({ voting: true });
  exchange(forum);
  assert.equal(forum.vote('a', 1, 1), 'recorded');
  const before = forum.state('a');
  for (let i = 0; i < 20; i++) { forum.disconnect('a'); forum.connect('a', 1); }
  assert.deepEqual(forum.state('a'), before);
  assert.equal(forum.introduce('a', 'b', 1), 'established');
  assert.equal(forum.vote('a', -1, 1), 'already-voted');
});
test('optional voting changes future epoch allowance by one; ties hold and bounds apply', () => {
  const { forum } = fixture({ voting: true, epochGrant: 2, maxEpochGrant: 3 });
  assert.equal(forum.vote('a', 2, 1), 'invalid-vote');
  forum.vote('a', 1, 1); forum.vote('b', -1, 1);
  forum.advanceEpoch();
  assert.equal(forum.policy.epochGrant, 2);
  forum.vote('a', 1, 1); forum.advanceEpoch();
  assert.equal(forum.policy.epochGrant, 3);
  forum.vote('a', 1, 1); forum.advanceEpoch();
  assert.equal(forum.policy.epochGrant, 3);
  for (let i = 0; i < 5; i++) { forum.vote('a', -1, 1); forum.advanceEpoch(); }
  assert.equal(forum.policy.epochGrant, 0);
});
test('disabled voting has no side effects', () => {
  const { forum } = fixture();
  assert.equal(forum.vote('a', 1, 1), 'disabled');
  forum.advanceEpoch();
  assert.equal(forum.policy.epochGrant, 2);
});
test('the public aggregate output contains no identities, edges, blocks or profiles', () => {
  const { forum } = fixture({}, ['private-a', 'private-b']);
  exchange(forum, 'private-a', 'private-b');
  assert.deepEqual(Object.keys(forum.metrics()).sort(), [
    'activeMembers', 'approaches', 'declines', 'epoch', 'matureMembers',
    'maxBalance', 'reciprocated', 'registeredMembers', 'rejections', 'totalGranted',
  ].sort());
  assert.ok(!JSON.stringify(forum.metrics()).includes('private-'));
});
test('invalid policy values fail closed', () => {
  for (const bad of [{ tokenCap: -1 }, { initialTokens: 9 }, { maxImbalance: 0 },
    { pendingCap: NaN }, { presenceTtl: 0 }, { epochGrant: 7 }, { requestTtl: 0 }]) {
    assert.throws(() => fixture(bad));
  }
});

test('bounded imbalance history restores outreach after unanswered requests without minting maturity', () => {
  const { forum } = fixture({ initialTokens: 8, maxImbalance: 1, imbalanceEpochs: 1 });
  forum.introduce('a', 'b', 1);
  assert.equal(forum.introduce('a', 'c', 1), 'outbound-imbalance');
  forum.advanceEpoch();
  assert.equal(forum.introduce('a', 'c', 1), 'delivered');
  assert.equal(forum.state('a').activeEpochs, 0);
  assert.equal(forum.state('a').sent, 2);
  assert.equal(forum.state('a').tokens, 7);
});
test('multi-epoch windows retain recent debt, then forget only expired balance events', () => {
  const { forum } = fixture({ maxImbalance: 1, imbalanceEpochs: 2 });
  forum.introduce('a', 'b', 1);
  forum.advanceEpoch();
  assert.equal(forum.introduce('a', 'c', 1), 'outbound-imbalance');
  forum.advanceEpoch();
  assert.equal(forum.introduce('a', 'c', 1), 'delivered');
  assert.equal(forum.introduce('a', 'b', 1), 'pending');
});
test('window recovery does not reset token spending, first-contact history or free reply paths', () => {
  const { forum } = fixture({ initialTokens: 1, epochGrant: 0, growthPerActiveEpoch: 0, imbalanceEpochs: 1 });
  forum.introduce('a', 'b', 1);
  forum.advanceEpoch();
  assert.equal(forum.introduce('a', 'c', 1), 'no-tokens');
  forum.accept('b', 'a', 1);
  assert.equal(forum.reply('b', 'a', 1), 'replied');
  assert.equal(forum.introduce('a', 'b', 1), 'established');
});
test('negative or fractional imbalance horizons are rejected', () => {
  assert.throws(() => fixture({ imbalanceEpochs: -1 }));
  assert.throws(() => fixture({ imbalanceEpochs: 1.5 }));
});
