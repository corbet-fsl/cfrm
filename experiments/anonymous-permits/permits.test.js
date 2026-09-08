import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { Worker } from 'node:worker_threads';
import { createEpoch, openLedger, createIssuer, preparePermit, redeemPermit, prepareRedemption, redeemIntroduction } from './permits.js';

const NOW = 1_800_000_000;
let epochPromise;
function epoch() {
  return epochPromise ??= createEpoch({ scope: 'community.example', epoch: 'epoch-1', notBefore: NOW, expiresAt: NOW + 600 });
}
async function setup(t) {
  const dir = mkdtempSync(join(tmpdir(), 'cfrm-permits-'));
  const path = join(dir, 'ledger.sqlite');
  const ledger = openLedger(path);
  t.after(() => { ledger.close(); rmSync(dir, { recursive: true, force: true }); });
  const context = await epoch();
  const issuer = createIssuer(context, ledger, () => NOW);
  return { context, ledger, path, issuer };
}
async function issue(issuer, context, allocation = 'allocation-a') {
  const client = await preparePermit(context.public);
  const response = await issuer.issue(allocation, client.request);
  return { client, response, permit: await client.finish(response) };
}

async function deadline(promise, milliseconds) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('SQLite lock helper timed out')), milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}

// This wrapper only schedules the race at an existing persistence boundary.
// Maintained blind signing, the ledger transaction and SQLite locks remain real.
// The worker changes time before releasing its write lock, so the operation's
// BEGIN cannot acquire the lock with the time sampled by the caller pre-check.
async function withWriterLock({ context, ledger, path }, method, releasedAt, operation) {
  const shared = new Int32Array(new SharedArrayBuffer(3 * Int32Array.BYTES_PER_ELEMENT));
  // [release request, trusted time, worker stage: 0 starting / 1 locked / 2 released]
  Atomics.store(shared, 1, NOW);
  const worker = new Worker(new URL('./sqlite-lock-holder.js', import.meta.url), {
    workerData: { path, shared: shared.buffer, releasedAt },
  });
  let resolveReady, rejectReady, resolveExit, workerError;
  const ready = new Promise((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
  const exited = new Promise(resolve => { resolveExit = resolve; });
  // Always handle startup failure, including cleanup before readiness is awaited.
  ready.catch(() => {});
  worker.on('message', message => {
    if (message === 'locked') resolveReady();
  });
  worker.once('error', error => { workerError = error; rejectReady(error); });
  worker.once('exit', code => {
    rejectReady(new Error(`SQLite lock helper exited before readiness (${code})`));
    resolveExit(code);
  });
  const release = () => { Atomics.store(shared, 0, 1); Atomics.notify(shared, 0); };
  let boundaryCalls = 0;
  const guardedLedger = {
    ...ledger,
    [method](...args) {
      boundaryCalls++;
      assert.equal(Atomics.load(shared, 2), 1, 'the other connection still owns the write lock');
      assert.equal(Atomics.load(shared, 1), NOW, 'caller checks saw the live epoch');
      release();
      return ledger[method](...args);
    },
  };
  try {
    await deadline(ready, 10_000);
    // Prove actual SQLite contention, independently of the worker's readiness flag.
    const probe = new DatabaseSync(path);
    let unexpectedlyAcquired = false;
    try {
      probe.exec('PRAGMA busy_timeout=0');
      assert.throws(() => {
        probe.exec('BEGIN IMMEDIATE');
        unexpectedlyAcquired = true;
      }, /database is locked/);
    } finally {
      if (unexpectedlyAcquired) probe.exec('ROLLBACK');
      probe.close();
    }
    return await operation(createIssuer(context, guardedLedger, () => Atomics.load(shared, 1)));
  } finally {
    release();
    let exitCode;
    try { exitCode = await deadline(exited, 10_000); }
    catch (error) {
      await worker.terminate();
      await exited;
      throw error;
    }
    assert.equal(workerError, undefined, 'lock helper must not fail');
    assert.equal(exitCode, 0, 'lock helper must exit successfully and be reaped');
    assert.equal(Atomics.load(shared, 2), 2, 'the real holding transaction committed');
    assert.equal(Atomics.load(shared, 1), releasedAt, 'time changed before that commit');
    assert.equal(boundaryCalls, 1, 'the intended real ledger operation was reached');
  }
}

function persistedAllocations(path) {
  const db = new DatabaseSync(path);
  try {
    return db.prepare('SELECT id,quota,issued FROM allocations ORDER BY id').all()
      .map(row => ({ ...row }));
  } finally { db.close(); }
}

test('a real blind permit redeems once without account or recipient identifiers', async (t) => {
  const { context, ledger, issuer } = await setup(t);
  issuer.allocate('allocation-a', 2);
  const { client, permit } = await issue(issuer, context);
  assert.deepEqual(Object.keys(client.request), ['blinded']);
  assert.deepEqual(Object.keys(permit).sort(), ['message', 'signature']);
  assert.equal(JSON.stringify(permit).includes('allocation-a'), false);
  assert.equal(await redeemPermit(context.public, ledger, permit, () => NOW), true);
  assert.equal(await redeemPermit(context.public, ledger, permit, () => NOW), false);
  assert.deepEqual(ledger.counts(), { allocations: 1, issuances: 1, spends: 1 });
});

test('blind requests for separate permits differ and the allowance is finite', async (t) => {
  const { context, issuer } = await setup(t);
  issuer.allocate('allocation-a', 2);
  const a = await issue(issuer, context);
  const b = await issue(issuer, context);
  assert.notDeepEqual(a.client.request, b.client.request);
  await assert.rejects(issue(issuer, context));
});

test('retrying an issuance returns the same response without consuming another slot', async (t) => {
  const { context, issuer, ledger } = await setup(t);
  issuer.allocate('allocation-a', 1);
  const client = await preparePermit(context.public);
  const first = await issuer.issue('allocation-a', client.request);
  const second = await issuer.issue('allocation-a', client.request);
  assert.deepEqual(first, second);
  assert.equal(await redeemPermit(context.public, ledger, await client.finish(second), () => NOW), true);
  await assert.rejects(issue(issuer, context));
});

test('reconnecting or repeating allocation cannot replenish allowance', async (t) => {
  const { context, issuer, ledger } = await setup(t);
  issuer.allocate('allocation-a', 1);
  await issue(issuer, context);
  const restarted = createIssuer(context, ledger, () => NOW);
  restarted.allocate('allocation-a', 1);
  assert.throws(() => restarted.allocate('allocation-a', 2));
  await assert.rejects(issue(restarted, context));
});

test('concurrent issuance cannot overspend one allocation', async (t) => {
  const { context, issuer } = await setup(t);
  issuer.allocate('allocation-a', 1);
  const results = await Promise.allSettled([issue(issuer, context), issue(issuer, context)]);
  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
});

test('independent SQLite connections serialize double spending and retain it after restart', async (t) => {
  const { context, issuer, ledger, path } = await setup(t);
  issuer.allocate('allocation-a', 1);
  const { permit } = await issue(issuer, context);
  const second = openLedger(path);
  t.after(() => second.close());
  const results = await Promise.all([
    redeemPermit(context.public, ledger, permit, () => NOW),
    redeemPermit(context.public, second, permit, () => NOW),
  ]);
  assert.deepEqual(results.sort(), [false, true]);
  const third = openLedger(path);
  try {
    assert.equal(await redeemPermit(context.public, third, permit, () => NOW), false);
    await assert.rejects(issue(createIssuer(context, third, () => NOW), context));
  } finally { third.close(); }
});

test('invalid signatures cannot consume a genuine permit', async (t) => {
  const { context, issuer, ledger } = await setup(t);
  issuer.allocate('allocation-a', 1);
  const { permit } = await issue(issuer, context);
  assert.equal(await redeemPermit(context.public, ledger, { ...permit, signature: 'AA' }, () => NOW), false);
  assert.equal(await redeemPermit(context.public, ledger, { ...permit, message: 'AA' }, () => NOW), false);
  assert.equal(await redeemPermit(context.public, ledger, permit, () => NOW), true);
});

test('scope, epoch and validity are checked using trusted public context', async (t) => {
  const { context, issuer, ledger } = await setup(t);
  issuer.allocate('allocation-a', 1);
  const { permit } = await issue(issuer, context);
  for (const changes of [{ scope: 'other.example' }, { epoch: 'epoch-2' }]) {
    assert.equal(await redeemPermit({ ...context.public, ...changes }, ledger, permit, () => NOW), false);
  }
  assert.equal(await redeemPermit(context.public, ledger, permit, () => NOW - 1), false);
  assert.equal(await redeemPermit(context.public, ledger, permit, () => NOW + 600), false);
  assert.equal(await redeemPermit(context.public, ledger, permit, () => NOW), true);
});

test('expired state can be pruned without accepting expired permits', async (t) => {
  const { context, issuer, ledger } = await setup(t);
  issuer.allocate('allocation-a', 1);
  const { permit } = await issue(issuer, context);
  await redeemPermit(context.public, ledger, permit, () => NOW);
  ledger.prune(NOW + 600);
  assert.deepEqual(ledger.counts(), { allocations: 0, issuances: 0, spends: 0 });
  assert.equal(await redeemPermit(context.public, ledger, permit, () => NOW + 600), false);
});


test('validity is rechecked after verification before a first spend', async (t) => {
  const { context, issuer, ledger } = await setup(t);
  issuer.allocate('allocation-a', 1);
  const { permit } = await issue(issuer, context);
  let now = NOW;
  const pending = redeemPermit(context.public, ledger, permit, () => now);
  now = NOW + 600;
  assert.equal(await pending, false);
  assert.equal(ledger.counts().spends, 0);
});

test('expiry and pruning during verification cannot resurrect a spent permit', async (t) => {
  const { context, issuer, ledger, path } = await setup(t);
  issuer.allocate('allocation-a', 1);
  const { permit } = await issue(issuer, context);
  assert.equal(await redeemPermit(context.public, ledger, permit, () => NOW), true);
  const second = openLedger(path);
  t.after(() => second.close());
  let now = NOW;
  const pending = redeemPermit(context.public, ledger, permit, () => now);
  now = NOW + 600;
  second.prune(now);
  assert.equal(await pending, false);
  assert.deepEqual(ledger.counts(), { allocations: 0, issuances: 0, spends: 0 });
});

test('a distinct trusted issuer key cannot silently reuse another key allocation', async (t) => {
  const { context, issuer, ledger } = await setup(t);
  issuer.allocate('allocation-a', 1);
  await issue(issuer, context);
  const replacement = await createEpoch({ scope: 'community.example', epoch: 'epoch-1', notBefore: NOW, expiresAt: NOW + 600 });
  const replacementIssuer = createIssuer(replacement, ledger, () => NOW);
  replacementIssuer.allocate('allocation-a', 1);
  const { permit } = await issue(replacementIssuer, replacement);
  assert.equal(await redeemPermit(replacement.public, ledger, permit, () => NOW), true);
  assert.equal(await redeemPermit(context.public, ledger, permit, () => NOW), false);
  assert.equal(ledger.counts().allocations, 2);
});

test('a recipient can retry an interrupted spend with its persisted anonymous claim', async (t) => {
  const { context, issuer, ledger, path } = await setup(t);
  issuer.allocate('allocation-a', 1);
  const { permit } = await issue(issuer, context);
  const redemption = prepareRedemption(permit);
  assert.deepEqual(Object.keys(redemption).sort(), ['claim', 'permit']);
  assert.match(redemption.claim, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(redemption.claim, prepareRedemption(permit).claim);
  // The first response may be lost; persist the client claim before this call.
  assert.deepEqual(await redeemIntroduction(context.public, ledger, redemption, () => NOW), { accepted: true });
  const restarted = openLedger(path);
  try {
    assert.deepEqual(await redeemIntroduction(context.public, restarted, JSON.parse(JSON.stringify(redemption)), () => NOW), { accepted: true });
    assert.deepEqual(await redeemIntroduction(context.public, restarted, prepareRedemption(permit), () => NOW), { accepted: false });
    assert.equal(await redeemPermit(context.public, restarted, permit, () => NOW), false);
    assert.equal(restarted.counts().spends, 1);
  } finally { restarted.close(); }
});

test('concurrent recipient claims spend once while the winning claim stays idempotent', async (t) => {
  const { context, issuer, ledger } = await setup(t);
  issuer.allocate('allocation-a', 1);
  const { permit } = await issue(issuer, context);
  const claims = [prepareRedemption(permit), prepareRedemption(permit)];
  const results = await Promise.all(claims.map(claim => redeemIntroduction(context.public, ledger, claim, () => NOW)));
  assert.equal(results.filter(result => result.accepted).length, 1);
  const winner = results.findIndex(result => result.accepted);
  assert.deepEqual(await redeemIntroduction(context.public, ledger, claims[winner], () => NOW), { accepted: true });
  assert.equal(ledger.counts().spends, 1);
});

test('invalid or expired redemption claims cannot consume or resurrect permits', async (t) => {
  const { context, issuer, ledger } = await setup(t);
  issuer.allocate('allocation-a', 1);
  const { permit } = await issue(issuer, context);
  const redemption = prepareRedemption(permit);
  for (const invalid of [{ ...redemption, claim: 'AA' }, { ...redemption, memberId: 'unexpected' },
    { ...redemption, permit: { ...permit, signature: 'AA' } }]) {
    assert.deepEqual(await redeemIntroduction(context.public, ledger, invalid, () => NOW), { accepted: false });
  }
  assert.equal(ledger.counts().spends, 0);
  assert.deepEqual(await redeemIntroduction(context.public, ledger, redemption, () => NOW), { accepted: true });
  ledger.prune(NOW + 600);
  assert.deepEqual(await redeemIntroduction(context.public, ledger, redemption, () => NOW + 600), { accepted: false });
  assert.equal(ledger.counts().spends, 0);
});

test('pruned epochs stay retired after restart even if the host wall clock moves backwards', async (t) => {
  const { context, issuer, ledger, path } = await setup(t);
  issuer.allocate('allocation-a', 1);
  const { permit } = await issue(issuer, context);
  const redemption = prepareRedemption(permit);
  assert.deepEqual(await redeemIntroduction(context.public, ledger, redemption, () => NOW), { accepted: true });
  ledger.prune(NOW + 600);
  const restarted = openLedger(path);
  try {
    assert.deepEqual(await redeemIntroduction(context.public, restarted, redemption, () => NOW), { accepted: false });
    assert.equal(await redeemPermit(context.public, restarted, permit, () => NOW), false);
    assert.throws(() => createIssuer(context, restarted, () => NOW).allocate('allocation-a', 1));
    assert.equal(restarted.counts().spends, 0);
  } finally { restarted.close(); }
});

test('issuance after a real writer lock succeeds while the epoch remains live', { timeout: 30_000 }, async (t) => {
  const state = await setup(t);
  state.issuer.allocate('allocation-a', 1);
  const client = await preparePermit(state.context.public);
  const response = await withWriterLock(state, 'issue', NOW + 1,
    issuer => issuer.issue('allocation-a', client.request));
  const permit = await client.finish(response);
  assert.equal(await redeemPermit(state.context.public, state.ledger, permit, () => NOW + 1), true);
  assert.deepEqual(persistedAllocations(state.path), [{ id: 'allocation-a', quota: 1, issued: 1 }]);
  assert.deepEqual(state.ledger.counts(), { allocations: 1, issuances: 1, spends: 1 });
});

test('expiry before acquiring the issuance write lock cannot issue or debit', { timeout: 30_000 }, async (t) => {
  const state = await setup(t);
  state.issuer.allocate('allocation-a', 1);
  const client = await preparePermit(state.context.public);
  let result;
  await withWriterLock(state, 'issue', NOW + 600, async issuer => {
    try { result = { response: await issuer.issue('allocation-a', client.request) }; }
    catch (error) { result = { error }; }
  });
  // Check durable effects separately: a rejection must not merely hide a debit.
  assert.deepEqual(persistedAllocations(state.path), [{ id: 'allocation-a', quota: 1, issued: 0 }]);
  assert.deepEqual(state.ledger.counts(), { allocations: 1, issuances: 0, spends: 0 });
  assert.equal(result.response, undefined);
  assert.match(result.error?.message ?? '', /Permit issuance rejected/);
});

test('allocation after a real writer lock succeeds while the epoch remains live', { timeout: 30_000 }, async (t) => {
  const state = await setup(t);
  await withWriterLock(state, 'allocate', NOW + 1, issuer => issuer.allocate('allocation-a', 1));
  assert.deepEqual(persistedAllocations(state.path), [{ id: 'allocation-a', quota: 1, issued: 0 }]);
  const { permit } = await issue(createIssuer(state.context, state.ledger, () => NOW + 1), state.context);
  assert.equal(await redeemPermit(state.context.public, state.ledger, permit, () => NOW + 1), true);
});

test('expiry before acquiring the allocation write lock cannot create allowance', { timeout: 30_000 }, async (t) => {
  const state = await setup(t);
  let error;
  await withWriterLock(state, 'allocate', NOW + 600, issuer => {
    try { issuer.allocate('allocation-a', 1); }
    catch (failure) { error = failure; }
  });
  assert.deepEqual(persistedAllocations(state.path), []);
  assert.deepEqual(state.ledger.counts(), { allocations: 0, issuances: 0, spends: 0 });
  assert.ok(error instanceof Error, 'expired allocation must reject');
});
