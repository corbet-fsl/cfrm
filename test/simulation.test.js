import test from 'node:test';
import assert from 'node:assert/strict';
import { simulate, sweep, comparePolicies, defaultExperiment } from '../src/simulate.js';

test('a fixed seed reproduces all numerical experiment output', () => {
  const a = simulate({ ...defaultExperiment, seed: 42 });
  const b = simulate({ ...defaultExperiment, seed: 42 });
  assert.deepEqual(a, b);
  assert.equal(a.config.participants, 100);
  assert.equal(a.timeline.length, defaultExperiment.epochs);
  assert.notDeepEqual(a, simulate({ ...defaultExperiment, seed: 43 }));
});
test('hostile mixtures remain within the token bound over multiple seeds and caps', () => {
  for (const seed of [1, 11, 401]) {
    for (const tokenCap of [3, 8, 20]) {
      const result = simulate({ ...defaultExperiment, seed,
        policy: { ...defaultExperiment.policy, initialTokens: 3, tokenCap } });
      assert.equal(result.invariants.withinGrantBound, true);
      assert.equal(result.invariants.withinTokenCap, true);
      assert.equal(result.invariants.nonnegativeTokens, true);
      assert.equal(result.final.activeMembers, 0);
      assert.ok(result.final.approaches <= result.bound);
    }
  }
});
test('reconnection reset attackers gain no extra allowance', () => {
  const shared = { ...defaultExperiment, seed: 8, epochs: 4 };
  const flooding = simulate({ ...shared, population: { flooder: 10 } });
  const resetting = simulate({ ...shared, population: { resetter: 10 } });
  assert.deepEqual(flooding.final, resetting.final);
  assert.equal(flooding.final.approaches, 30);
});
test('a colluding pair can earn one activity epoch, not repeatedly farm the same first contact', () => {
  const result = simulate({ ...defaultExperiment, population: { 'colluding-pair': 2 }, epochs: 6 });
  assert.equal(result.final.reciprocated, 1);
  assert.equal(result.byBehavior['colluding-pair'].maxActiveEpochs, 1);
  assert.equal(result.final.approaches, 1);
});
test('a colluding ring manufactures bounded maturity from distinct accounts', () => {
  const result = simulate({ ...defaultExperiment, population: { 'colluding-ring': 8 }, epochs: 8 });
  assert.ok(result.final.reciprocated > 1);
  assert.ok(result.byBehavior['colluding-ring'].maxActiveEpochs > 1);
  assert.ok(result.byBehavior['colluding-ring'].maxActiveEpochs <= 7);
  assert.equal(result.invariants.withinGrantBound, true);
});
test('nonreciprocators do not accumulate more accepted inbound imbalance than policy allows', () => {
  const result = simulate({ ...defaultExperiment, population: { cooperative: 80, nonreciprocator: 20 } });
  assert.ok(result.byBehavior.nonreciprocator.maxInboundImbalance <= defaultExperiment.policy.maxImbalance);
  assert.equal(result.byBehavior.nonreciprocator.maxActiveEpochs, 0);
});
test('parameter sweeps return comparable aggregate rows and no contact graph', () => {
  const rows = sweep({ ...defaultExperiment, epochs: 2 }, [1, 2], [2, 4]);
  assert.equal(rows.length, 4);
  assert.deepEqual(Object.keys(rows[0]).sort(), [
    'seed', 'maxImbalance', 'approaches', 'reciprocated', 'unreciprocated',
    'matureMembers', 'withinGrantBound',
  ].sort());
  assert.ok(rows.every(row => row.withinGrantBound));
});
test('invalid or accidentally huge experiment inputs fail before execution', () => {
  for (const change of [{ seed: -1 }, { epochs: 0 }, { rounds: 0 },
    { population: { unknown: 1 } }, { population: { cooperative: 100001 } },
    { population: { 'colluding-pair': 3 } }]) {
    assert.throws(() => simulate({ ...defaultExperiment, ...change }));
  }
});

test('bounded windows preserve late cooperative progress across seeds while lifetime imbalance stalls it', () => {
  for (const seed of [1, 42, 101]) {
    const config = { ...defaultExperiment, seed, epochs: 16 };
    const lifetime = simulate(config);
    const window = simulate({ ...config, policy: { ...config.policy, imbalanceEpochs: 2 } });
    assert.ok(window.byBehavior.cooperative.reciprocatedApproaches > lifetime.byBehavior.cooperative.reciprocatedApproaches);
    assert.ok(window.byBehavior.cooperative.lateApproaches > 0);
    assert.equal(lifetime.byBehavior.cooperative.lateApproaches, 0);
    assert.equal(window.invariants.withinGrantBound, true);
    assert.ok(window.exposure.maxPending <= config.policy.pendingCap);
    assert.equal(window.byBehavior.nonreciprocator.maxActiveEpochs, 0);
  }
});
test('policy comparisons expose both cooperative benefit and hostile reach, with recipient concentration', () => {
  const rows = comparePolicies({ ...defaultExperiment, epochs: 4 }, [1], [0, 2]);
  assert.equal(rows.length, 6);
  for (const row of rows) {
    assert.ok(Number.isSafeInteger(row.cooperativeReciprocated));
    assert.ok(Number.isSafeInteger(row.hostileApproaches));
    assert.ok(Number.isSafeInteger(row.maxUnsolicitedPerTarget));
    assert.ok(row.maxPending <= defaultExperiment.policy.pendingCap);
    assert.equal(row.withinGrantBound, true);
  }
});
