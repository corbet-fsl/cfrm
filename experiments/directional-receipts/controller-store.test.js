import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { join } from 'node:path';
import { redeemPermit } from '../anonymous-permits/permits.js';
import { controllerFixture, configDigest, proofFingerprint, same, NOW } from './controller-fixtures.js';
import { counters } from './attestation-fixtures.js';
import { COMMUNITY, POLICY, b64, hash, json, raw, terminateCrypto, verifyAdmission } from './fixtures.js';

after(terminateCrypto);
const options = { timeout: 240_000 };
const clone = value => structuredClone(value);
const assertSame = (a, b, message) => assert.ok(same(a, b), message);
const counts = (authorizations = 0, lifetimeNullifiers = 0, redeemedReceipts = 0) =>
  ({ authorizations, lifetimeNullifiers, redeemedReceipts });
const failAt = wanted => phase => { if (phase === wanted()) throw new Error('Injected transaction interruption'); };
const permitContextId = context => hash(json(['cfrm.contact.v1', context.scope, context.epoch,
  context.notBefore, context.expiresAt, context.publicKey.kty, context.publicKey.n, context.publicKey.e]));

function allocationRows(f, context) {
  const db = new DatabaseSync(join(f.directory, 'controller.sqlite'), { readOnly: true });
  try { return db.prepare('SELECT count(*) AS n FROM allocations WHERE context=?').get(permitContextId(context)).n; }
  finally { db.close(); }
}

test('sealed complete rule configurations bound cohorts, windows and mathematical RSA keys across purposes and origins', options, async t => {
  const f = await controllerFixture(t);
  const store = f.openStore();
  f.define(store);
  const original = f.configs[0];
  const reordered = Object.fromEntries(Object.entries(original).reverse());
  f.define(store, reordered);
  assertSame(store.origin(original.origin), { config: original, ruleConfigDigest: configDigest(original) });
  const changedRules = clone(original);
  changedRules.rules.epochGrant += 1;
  assert.equal(changedRules.policyDigest, POLICY);
  assert.notEqual(configDigest(changedRules), configDigest(original));
  assert.throws(() => store.defineOrigin(changedRules));
  for (const change of [
    c => { c.policyDigest = hash(Buffer.from('different-eligibility')); },
    c => { c.receiptCohorts[0].redeemUntil -= 1; },
    c => { c.receiptCohorts.push({ ...c.receiptCohorts[1], cohortId: 'late-third', publicKey: clone(f.contexts[2].publicKey) }); },
  ]) {
    const changed = clone(original); change(changed);
    assert.throws(() => store.defineOrigin(changed));
  }
  const invalid = [
    c => { c.receiptCohorts[1].publicKey = clone(c.receiptCohorts[0].publicKey); },
    c => { c.permitContext.publicKey = clone(c.receiptCohorts[0].publicKey); },
    c => { c.receiptCohorts[0].publicKey.n = b64(Buffer.concat([Buffer.of(0), Buffer.from(c.receiptCohorts[0].publicKey.n, 'base64url')])); },
    c => { c.receiptCohorts[0].publicKey.e = 'AAEAAQ'; },
    c => { c.receiptCohorts[0].notBefore -= 1; },
    c => { c.receiptCohorts[1].issueUntil += 1; },
    c => { c.receiptCohorts[1].redeemUntil = c.endsAt + c.graceSeconds + 1; },
    c => { c.permitContext.expiresAt -= 1; },
    c => { c.graceSeconds = c.endsAt - c.notBefore; },
    c => { c.rules.initialAllowance = Number.MAX_SAFE_INTEGER + 1; },
    c => { c.rules.unrecognizedRule = 1; },
    c => { c.receiptCohorts[0].publicKey.d = 'private-key-field'; },
  ];
  for (const [index, change] of invalid.entries()) {
    const isolated = f.openStore({}, `invalid-config-${index}.sqlite`);
    const candidate = clone(original); change(candidate);
    assert.throws(() => isolated.defineOrigin(candidate));
    f.define(isolated); // Invalid definitions did not partially consume keys/origins.
  }
  for (const change of [
    c => { c.receiptCohorts[0].publicKey = clone(original.receiptCohorts[0].publicKey); },
    c => { c.receiptCohorts[0].publicKey = clone(original.permitContext.publicKey); },
    c => { c.permitContext.publicKey = clone(original.receiptCohorts[1].publicKey); },
    c => { c.notBefore += 1; c.permitContext.notBefore += 1; c.receiptCohorts[0].notBefore += 1; },
  ]) {
    const candidate = clone(f.configs[1]); change(candidate);
    assert.throws(() => store.defineOrigin(candidate));
  }
  f.define(store, f.configs[1]); // One-cohort successor: the catalog is bounded, not hardcoded to two.
});

test('two connections enforce aggregate last-unit send and receive caps while exact retries remain recoverable', options, async t => {
  const f = await controllerFixture(t, { maxAuthorizedSend: 1, maxAcknowledgedReceive: 1 });
  const store = f.openStore(); f.define(store);
  const other = f.openStore();
  const services = [f.receiptService(store, 0), f.receiptService(other, 1)];
  const actions = [f.primedAction, await f.controllerAction(1, 0, 2, 1)];
  const attempts = await Promise.allSettled(actions.map((action, i) => services[i].authorizeAndAcknowledge(action.request)));
  assert.equal(attempts.filter(value => value.status === 'fulfilled').length, 1);
  const winner = attempts.findIndex(value => value.status === 'fulfilled');
  const first = attempts[winner].value;
  assertSame(f.state(store, 0).counters, counters(1));
  const opposite = 1 - winner;
  const secondAction = await f.controllerAction(opposite, 3, 1, 1);
  const second = await services[opposite].authorizeAndAcknowledge(secondAction.request);
  const receipts = [await actions[winner].client.finish(first), await secondAction.client.finish(second)];
  const cohortIndices = [winner, opposite];
  const requests = receipts.map((receipt, i) => f.redeemRequest(receipt, cohortIndices[i]));
  const received = await Promise.all(requests.map((request, i) => services[cohortIndices[i]].redeemAcknowledgedReceipt(request)));
  assert.equal(received.filter(Boolean).length, 1);
  assertSame(f.state(store, 1).counters, counters(0, 1));
  assertSame(await services[winner].authorizeAndAcknowledge(actions[winner].request), first);
  const receivedIndex = received.findIndex(Boolean);
  assertSame(await services[cohortIndices[receivedIndex]].redeemAcknowledgedReceipt(requests[receivedIndex]), received[receivedIndex]);
  const changedProof = await f.action(0, 4, 1, { client: actions[winner].client,
    authorization: actions[winner].request.senderAuthorization });
  await assert.rejects(services[winner].authorizeAndAcknowledge(changedProof.request));
  assertSame(store.receiptPort(f.contexts[0].cohortId).counts(), counts(2, 2, 1));
});

test('receipt counters, replay markers and complete signed responses share crash and retry transactions', options, async t => {
  const f = await controllerFixture(t);
  let store = f.openStore(); f.define(store);
  let phase = 'issue-before-commit';
  let service = f.receiptService(store, 0, { fault: failAt(() => phase) });
  const action = f.primedAction;
  await assert.rejects(service.authorizeAndAcknowledge(action.request));
  assertSame(f.state(store, 0).counters, counters());
  assertSame(store.receiptPort(f.contexts[0].cohortId).counts(), counts());
  phase = 'issue-after-commit';
  await assert.rejects(service.authorizeAndAcknowledge(action.request));
  assertSame(f.state(store, 0).counters, counters(1));
  store.close(); f.advance(NOW + 70); store = f.openStore();
  phase = '';
  service = f.receiptService(store, 0, { fault: failAt(() => phase) });
  const response = await service.authorizeAndAcknowledge(action.request);
  assertSame(await service.authorizeAndAcknowledge(action.request), response);
  f.checkCommit(response, action);
  const receipt = await action.client.finish(response);
  phase = 'receive-before-commit';
  assert.equal(await service.redeemAcknowledgedReceipt(f.redeemRequest(receipt)), false);
  assertSame(f.state(store, 1).counters, counters());
  phase = 'receive-after-commit';
  assert.equal(await service.redeemAcknowledgedReceipt(f.redeemRequest(receipt)), false);
  assertSame(f.state(store, 1).counters, counters(0, 1));
  store.close(); f.advance(NOW + 110); store = f.openStore();
  service = f.receiptService(store);
  const recovered = await service.redeemAcknowledgedReceipt(f.redeemRequest(receipt));
  f.checkRedemption(recovered, action);
  assertSame(await service.redeemAcknowledgedReceipt(f.redeemRequest(receipt)), recovered);
  assertSame(store.receiptPort(f.contexts[0].cohortId).counts(), counts(1, 1, 1));
});

test('own signed funding is once per stable account, snapshots full proofs and atomically records nonce and frontier', options, async t => {
  const f = await controllerFixture(t);
  const store = f.openStore(); f.define(store);
  const other = f.openStore();
  const funded = await Promise.all([store.fundInitial(f.initialProof), other.fundInitial(f.initialProof)]);
  assertSame(funded[0], funded[1]);
  assertSame(f.state(store, 0).allocation, { allocationId: funded[0].allocationId, quota: 3, issued: 0 });
  assert.equal(f.state(store, 0).initialOrigin, f.configs[0].origin);
  assert.equal(f.state(store, 0).fundedThrough, f.configs[0].origin);
  const changed = f.operationProof('initial', f.configs[0], 0,
    { nonce: f.initialProof.authorization.nonce, expiresAt: NOW + 29 });
  await f.verifyFunding(changed, f.configs[0], 'initial');
  await assert.rejects(store.fundInitial(changed));
  await assert.rejects(store.fundInitial({ grant: f.grantFor(f.members[2]) }));
  const wrongOwnKey = f.operationProof('initial', f.configs[0], 2);
  wrongOwnKey.authorization.memberId = f.members[3].memberId;
  await assert.rejects(store.fundInitial(wrongOwnKey));
  assert.equal(f.state(store, 3).allocation, null);
  const rotated = f.operationProof('initial', f.configs[0], 0, {}, f.rotate(0));
  await f.verifyFunding(rotated, f.configs[0], 'initial');
  assertSame(await store.fundInitial(rotated), funded[0]);

  // The real verifier is paused, not replaced by an accepting test double.
  let entered, resume;
  const entering = new Promise(resolve => { entered = resolve; });
  const waiting = new Promise(resolve => { resume = resolve; });
  const paused = f.openStore({ verifyAdmission: async (...args) => {
    entered(); await waiting; return verifyAdmission(...args);
  } });
  const mutable = f.operationProof('initial', f.configs[0], 4);
  const snapshot = clone(mutable);
  const pending = paused.fundInitial(mutable);
  let snapshotResult;
  try {
    await Promise.race([entering, pending.then(() => { throw new Error('Funding bypassed the real verifier'); })]);
    Object.assign(mutable, f.operationProof('initial', f.configs[0], 5));
    assert.notEqual(proofFingerprint(mutable), proofFingerprint(snapshot));
    resume();
    snapshotResult = await pending;
  } finally {
    resume(); await pending.catch(() => {});
  }
  assert.equal(snapshotResult.memberId, f.members[4].memberId);
  assertSame(await store.fundInitial(snapshot), snapshotResult);
  assert.equal(f.state(store, 5).allocation, null);

  let phase = 'fund-before-commit';
  const faulty = f.openStore({ fault: failAt(() => phase) });
  const proof = f.operationProof('initial', f.configs[0], 2);
  await assert.rejects(faulty.fundInitial(proof));
  assert.equal(f.state(store, 2).allocation, null);
  assert.equal(f.state(store, 2).fundedThrough, null);
  phase = 'fund-after-commit';
  await assert.rejects(faulty.fundInitial(proof));
  assert.equal(f.state(store, 2).allocation.quota, 3);
  faulty.close();
  const reopened = f.openStore();
  const recovery = await reopened.fundInitial(proof);
  assert.equal(recovery.quota, 3);
  assertSame(await reopened.fundInitial(proof), recovery);

  const next = clone(f.configs[1]);
  next.policyDigest = hash(Buffer.from('renewed-cvld-policy'));
  next.receiptCohorts[0].policyDigest = next.policyDigest;
  f.define(store, next); f.advance(NOW + 240);
  const reset = f.operationProof('initial', next, 0, {}, f.rotate(0));
  await f.verifyFunding(reset, next, 'initial');
  await assert.rejects(store.fundInitial(reset));
  const reusedNonce = f.operationProof('rollover', next, 0, { nonce: f.initialProof.authorization.nonce });
  await f.verifyFunding(reusedNonce, next, 'rollover');
  await assert.rejects(store.rollover(reusedNonce));
  const nextResult = await store.rollover(f.operationProof('rollover', next));
  assert.equal(nextResult.quota, 4);
  assert.equal(f.state(store, 0, 1).initialOrigin, f.configs[0].origin);
});

test('actual permit reservations and rollover serialize final issuance, bounded carry and funding retries', options, async t => {
  const f = await controllerFixture(t);
  const store = f.openStore(); f.define(store); f.define(store, f.configs[1]);
  const other = f.openStore();
  const allocations = {};
  for (const index of [0, 2, 3]) allocations[index] = await store.fundInitial(f.operationProof('initial', f.configs[0], index));
  const interruptedAllocation = await store.fundInitial(f.operationProof('initial', f.configs[0], 6));
  let permitPhase = 'permit-before-commit';
  const permitFaultStore = f.openStore({ fault: failAt(() => permitPhase) });
  const interruptedIssuer = f.permitIssuer(permitFaultStore);
  const interruptedClient = await f.permitClient();
  await assert.rejects(interruptedIssuer.issue(interruptedAllocation.allocationId, interruptedClient.request));
  assert.equal(f.state(store, 6).allocation.issued, 0);
  permitPhase = 'permit-after-commit';
  await assert.rejects(interruptedIssuer.issue(interruptedAllocation.allocationId, interruptedClient.request));
  assert.equal(f.state(store, 6).allocation.issued, 1);
  permitFaultStore.close();
  const recoveredStore = f.openStore();
  const recoveredIssuer = f.permitIssuer(recoveredStore);
  const recoveredOutput = await recoveredIssuer.issue(interruptedAllocation.allocationId, interruptedClient.request);
  assertSame(await recoveredIssuer.issue(interruptedAllocation.allocationId, interruptedClient.request), recoveredOutput);
  const recoveredPermit = await interruptedClient.finish(recoveredOutput);
  assert.equal(await redeemPermit(f.configs[0].permitContext, recoveredStore.permitPort(f.configs[0].origin), recoveredPermit, f.clock), true);
  assert.equal(await redeemPermit(f.configs[0].permitContext, recoveredStore.permitPort(f.configs[0].origin), recoveredPermit, f.clock), false);
  assert.equal(f.state(store, 6).allocation.issued, 1);
  const issuer = f.permitIssuer(store);
  for (const index of [0, 2]) {
    for (let n = 0; n < 2; n++) await issuer.issue(allocations[index].allocationId, (await f.permitClient()).request);
  }
  const last = await Promise.all([f.permitClient(), f.permitClient()]);
  const issued = await Promise.allSettled(last.map(client => issuer.issue(allocations[0].allocationId, client.request)));
  assert.equal(issued.filter(value => value.status === 'fulfilled').length, 1);
  const winner = issued.findIndex(value => value.status === 'fulfilled');
  assertSame(await issuer.issue(allocations[0].allocationId, last[winner].request), issued[winner].value);
  assert.equal(f.state(store, 0).allocation.issued, 3);

  // Schedule expiry exactly at the actual ledger call after blind RSA signing.
  // The standalone primitive separately has real worker/SQLite lock-race tests.
  f.advance(NOW + 239);
  const finalClient = await f.permitClient();
  const port = store.permitPort(f.configs[0].origin);
  let rollover;
  const delayedPort = { ...port, issue(...args) {
    f.advance(NOW + 240);
    rollover = other.rollover(f.operationProof('rollover', f.configs[1], 2));
    return port.issue(...args);
  } };
  const delayedIssuer = f.permitIssuerWithPort(delayedPort);
  await assert.rejects(delayedIssuer.issue(allocations[2].allocationId, finalClient.request));
  assert.ok(rollover, 'The real signing path reached the lock-time expiry seam');
  assert.equal((await rollover).quota, 3);
  assert.equal(f.state(store, 2).allocation.issued, 2);
  assert.equal((await store.rollover(f.operationProof('rollover', f.configs[1], 0))).quota, 2);
  await assert.rejects(issuer.issue(allocations[2].allocationId, finalClient.request));

  let phase = 'fund-before-commit';
  const faulty = f.openStore({ fault: failAt(() => phase) });
  const proof = f.operationProof('rollover', f.configs[1], 3);
  await assert.rejects(faulty.rollover(proof));
  assert.equal(f.state(store, 3, 1).allocation, null);
  assert.equal(f.state(store, 3).fundedThrough, f.configs[0].origin);
  phase = 'fund-after-commit';
  await assert.rejects(faulty.rollover(proof));
  faulty.close();
  const reopened = f.openStore();
  const result = await reopened.rollover(proof);
  assert.equal(result.quota, 4);
  assertSame(await reopened.rollover(proof), result);
});

test('late receipts retain their origin and settlement freezes summaries before pruning, including delayed rollover', options, async t => {
  const f = await controllerFixture(t);
  let store = f.openStore(); f.define(store); f.define(store, f.configs[1]);
  for (const index of [0, 1, 2]) await store.fundInitial(f.operationProof('initial', f.configs[0], index));
  await f.permitIssuer(store).issue(f.state(store, 0).allocation.allocationId, (await f.permitClient()).request);
  const a = f.primedAction;
  const b = await f.controllerAction(1, 2, 1);
  await f.receiptService(store, 0).authorizeAndAcknowledge(a.request);
  const bOutput = await f.receiptService(store, 1).authorizeAndAcknowledge(b.request);
  const bReceipt = await b.client.finish(bOutput);
  f.advance(NOW + 240);
  const next = await store.rollover(f.operationProof('rollover', f.configs[1], 1));
  await store.rollover(f.operationProof('rollover', f.configs[1], 0));
  f.advance(NOW + 310);
  assert.ok(await f.receiptService(store, 1).redeemAcknowledgedReceipt(f.redeemRequest(bReceipt, 1)));
  assertSame(f.state(store, 1).counters, counters(0, 1));
  assertSame(f.state(store, 1, 1).counters, counters());
  assert.equal(f.state(store, 1, 1).allocation.quota, next.quota);
  assert.throws(() => store.settleAndPrune(f.configs[0].origin));
  assert.throws(() => store.receiptPort(f.contexts[0].cohortId).prune(f.clock()));
  assert.throws(() => store.permitPort(f.configs[0].origin).prune(f.clock()));
  f.advance(NOW + 250);
  await assert.rejects(store.rollover(f.operationProof('rollover', f.configs[1], 2)));
  f.advance(NOW + 330);
  let phase = 'settle-before-commit';
  const faulty = f.openStore({ fault: failAt(() => phase) });
  assert.throws(() => faulty.settleAndPrune(f.configs[0].origin));
  assert.equal(f.state(store, 0).settled, false);
  assertSame(store.receiptPort(f.contexts[0].cohortId).counters(COMMUNITY, f.contexts[0].cohortId, f.members[0].memberId), counters(1));
  phase = 'settle-after-commit';
  assert.throws(() => faulty.settleAndPrune(f.configs[0].origin));
  faulty.close(); store.close(); store = f.openStore();
  store.settleAndPrune(f.configs[0].origin);
  assert.equal(f.state(store, 0).settled, true);
  assertSame(f.state(store, 0).counters, counters(1));
  assertSame(f.state(store, 1).counters, counters(0, 1));
  assertSame(store.receiptPort(f.contexts[0].cohortId).counters(COMMUNITY, f.contexts[0].cohortId, f.members[0].memberId), counters());
  assert.equal(allocationRows(f, f.configs[0].permitContext), 0);
  assert.equal((await store.rollover(f.operationProof('rollover', f.configs[1], 2))).quota, 4);
  const reusedPair = await f.controllerAction(2, 0, 1);
  await assert.rejects(f.receiptService(store, 2).authorizeAndAcknowledge(reusedPair.request));
  assertSame(f.state(store, 0, 1).counters, counters());
});

test('own consent, transferable permits and hidden recipient pooling remain explicit without adding operator pair joins', options, async t => {
  const f = await controllerFixture(t, { maxAcknowledgedReceive: 1 });
  const store = f.openStore(); f.define(store);
  const serviceA = f.receiptService(store);
  const action = await f.controllerAction(0, 0, 1, 2); // Permitted hidden-recipient reassignment, not identity equality.
  const output = await serviceA.authorizeAndAcknowledge(action.request);
  const receipt = await action.client.finish(output);
  const request = f.redeemRequest(receipt, 0, 2);
  const noConsent = clone(request); delete noConsent.authorization;
  assert.equal(await serviceA.redeemAcknowledgedReceipt(noConsent), false);
  const received = await serviceA.redeemAcknowledgedReceipt(request);
  assert.ok(received);
  const senderView = JSON.stringify([action.request, output]);
  for (const hidden of [f.members[2].memberId, b64(raw(f.members[2].chat.publicKey)),
    action.client.releaseNonce, hash(Buffer.from(action.client.releaseNonce, 'base64url'))]) assert.equal(senderView.includes(hidden), false);
  const receiverView = JSON.stringify([request, received]);
  for (const hidden of [f.members[0].memberId, action.request.senderAuthorization.nonce,
    action.request.senderAuthorization.requestHash, action.request.semaphoreProof.nullifier]) assert.equal(receiverView.includes(hidden), false);
  const db = new DatabaseSync(join(f.directory, 'controller.sqlite'), { readOnly: true });
  try {
    for (const { name } of db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'").all()) {
      const quoted = '"' + name.replaceAll('"', '""') + '"';
      for (const row of db.prepare(`SELECT * FROM ${quoted}`).all()) {
        const view = JSON.stringify(row);
        assert.equal(view.includes(f.members[0].memberId) && view.includes(f.members[2].memberId), false,
          'No stored row adds the named sender-to-designated-recipient association');
      }
    }
  } finally { db.close(); }
  const declined = await f.controllerAction(1, 3, 1, 2);
  const serviceB = f.receiptService(store, 1);
  const declinedOutput = await serviceB.authorizeAndAcknowledge(declined.request);
  const declinedReceipt = await declined.client.finish(declinedOutput);
  assert.equal(await serviceB.redeemAcknowledgedReceipt(f.redeemRequest(declinedReceipt, 1, 2)), false);
  assertSame(f.state(store, 0).counters, counters(1));
  assertSame(f.state(store, 3).counters, counters(1));
  assertSame(f.state(store, 2).counters, counters(0, 1));
  const allocation = await store.fundInitial(f.initialProof);
  const client = await f.permitClient();
  const permit = await client.finish(await f.permitIssuer(store).issue(allocation.allocationId, client.request));
  assertSame(Object.keys(permit).sort(), ['message', 'signature']);
  // The redeemer needs the bearer token, not the allocating member's account key.
  assert.equal(await redeemPermit(f.configs[0].permitContext, store.permitPort(f.configs[0].origin), permit, f.clock), true);
  assert.equal(await redeemPermit(f.configs[0].permitContext, store.permitPort(f.configs[0].origin), permit, f.clock), false);
  assert.equal(f.state(store, 0).allocation.issued, 1);
});

test('transaction ports are synchronous capabilities revoked after commit, rollback and delayed async continuation', options, async t => {
  const f = await controllerFixture(t);
  const store = f.openStore(); f.define(store);
  let committed;
  store.write(tx => { committed = tx; });
  assert.throws(() => committed.origins.define(f.configs[1]));
  let rolledBack;
  assert.throws(() => store.write(tx => {
    rolledBack = tx; tx.origins.define(f.configs[1]); throw new Error('Injected rollback');
  }));
  assert.equal(store.origin(f.configs[1].origin), null);
  assert.throws(() => rolledBack.origins.define(f.configs[1]));
  let delayed;
  assert.throws(() => store.write(tx => {
    tx.origins.define(f.configs[1]);
    delayed = Promise.resolve().then(() => { assert.throws(() => tx.origins.define(f.configs[1])); });
    return delayed;
  }));
  await delayed;
  assert.equal(store.origin(f.configs[1].origin), null);
  f.define(store, f.configs[1]);
});

test('settling one of two expired origins prunes only its receipt and permit source rows', options, async t => {
  const f = await controllerFixture(t);
  const store = f.openStore(); f.define(store); f.define(store, f.configs[1]);
  await store.fundInitial(f.initialProof);
  await f.receiptService(store).authorizeAndAcknowledge(f.primedAction.request);
  f.advance(NOW + 240);
  const next = await store.rollover(f.operationProof('rollover', f.configs[1]));
  await f.permitIssuer(store, 1).issue(next.allocationId, (await f.permitClient(1)).request);
  const nextAction = await f.controllerAction(2, 0, 2);
  await f.receiptService(store, 2).authorizeAndAcknowledge(nextAction.request);
  f.advance(NOW + 540);
  store.settleAndPrune(f.configs[0].origin);
  assert.equal(allocationRows(f, f.configs[0].permitContext), 0);
  assert.equal(allocationRows(f, f.configs[1].permitContext), 1);
  assert.equal(f.state(store, 0, 1).settled, false);
  assertSame(store.receiptPort(f.contexts[2].cohortId).counters(COMMUNITY, f.contexts[2].cohortId, f.members[0].memberId), counters(1));
  assertSame(f.state(store, 0, 1).allocation, { allocationId: next.allocationId, quota: 4, issued: 1 });
  store.settleAndPrune(f.configs[1].origin);
  assert.equal(allocationRows(f, f.configs[1].permitContext), 0);
  assert.equal(f.state(store, 0, 1).settled, true);
  assertSame(f.state(store, 0, 1).counters, counters(1));
  assertSame(f.state(store, 0, 1).allocation, { allocationId: next.allocationId, quota: 4, issued: 1 });
});
