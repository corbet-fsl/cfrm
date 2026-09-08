import test from 'node:test';
import assert from 'node:assert/strict';
import { ForumExperiment } from '../src/forum.js';
import { GroupExperiment } from '../src/groups.js';
import { defaultExperiment } from '../src/simulate.js';

function fixture() {
  const ids = Array.from({ length: 100 }, (_, i) => `person-${i}`);
  const eligible = new Set(ids);
  const forum = new ForumExperiment({ ...defaultExperiment.policy,
    initialTokens: 99, tokenCap: 99, maxImbalance: 99, pendingCap: 100 }, id => eligible.has(id));
  ids.forEach(id => forum.connect(id, 0));
  const groups = new GroupExperiment(forum, 100);
  return { ids, forum, groups };
}

test('100-member group needs 99 individually charged invitations and 99 explicit consents', () => {
  const { ids, forum, groups } = fixture();
  assert.equal(groups.create(ids[0], 'group', 1), 'created');
  for (const recipient of ids.slice(1)) {
    assert.equal(groups.invite(ids[0], 'group', recipient, 1), 'invited');
  }
  assert.equal(forum.state(ids[0]).tokens, 0);
  assert.equal(groups.size('group'), 1);
  assert.equal(groups.send(ids[1], 'group', 1), 'not-member');
  for (const recipient of ids.slice(1)) {
    assert.equal(groups.join(recipient, 'group', 1), 'joined');
  }
  assert.equal(groups.size('group'), 100);
  assert.equal(forum.state(ids[0]).approaches, 99);
  assert.equal(forum.state(ids[1]).sent, 1);
  assert.equal(forum.state(ids[1]).received, 1);
  assert.equal(forum.state(ids[1]).tokens, 99);
});
test('ordinary group messages spend no new-contact allowance and rejected users cannot send', () => {
  const { ids, forum, groups } = fixture();
  groups.create(ids[0], 'group', 1);
  groups.invite(ids[0], 'group', ids[1], 1);
  groups.join(ids[1], 'group', 1);
  const before = forum.state(ids[1]);
  for (let i = 0; i < 100; i++) assert.equal(groups.send(ids[1], 'group', 1), 'allowed');
  assert.deepEqual(forum.state(ids[1]), before);
  assert.equal(groups.send(ids[2], 'group', 1), 'not-member');
});
test('a new group does not turn one token into outreach to arbitrary strangers', () => {
  const { ids, forum, groups } = fixture();
  groups.create(ids[0], 'group', 1);
  groups.invite(ids[0], 'group', ids[1], 1);
  assert.equal(groups.join(ids[2], 'group', 1), 'not-invited');
  assert.equal(groups.invite(ids[2], 'group', ids[3], 1), 'not-member');
  assert.equal(forum.state(ids[2]).sent, 0);
  assert.equal(groups.size('group'), 1);
});
test('group capacity, invitation replay, and local recipient blocks are respected', () => {
  const { ids, forum } = fixture();
  const groups = new GroupExperiment(forum, 2);
  groups.create(ids[0], 'group', 1);
  forum.block(ids[1], ids[0]);
  assert.equal(groups.invite(ids[0], 'group', ids[1], 1), 'blocked');
  forum.unblock(ids[1], ids[0]);
  assert.equal(groups.invite(ids[0], 'group', ids[1], 1), 'invited');
  assert.equal(groups.invite(ids[0], 'group', ids[1], 1), 'already-invited');
  groups.join(ids[1], 'group', 1);
  assert.equal(groups.join(ids[1], 'group', 1), 'already-member');
  assert.equal(groups.invite(ids[0], 'group', ids[2], 1), 'full');
  assert.equal(groups.size('group'), 2);
  assert.equal(forum.state(ids[0]).tokens, 98);
});
test('established contacts may invite without another first-contact charge, but still require consent', () => {
  const { ids, forum, groups } = fixture();
  forum.introduce(ids[0], ids[1], 1);
  forum.accept(ids[1], ids[0], 1);
  forum.reply(ids[1], ids[0], 1);
  groups.create(ids[0], 'group', 1);
  const before = forum.state(ids[0]);
  assert.equal(groups.invite(ids[0], 'group', ids[1], 1), 'invited');
  assert.equal(groups.size('group'), 1);
  assert.equal(groups.join(ids[1], 'group', 1), 'joined');
  assert.deepEqual(forum.state(ids[0]), before);
});
