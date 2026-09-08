import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { join } from 'node:path';
import { openDirectionalLedger, createDirectionalService } from './receipts.js';
import { fixture, terminateCrypto, NOW, COMMUNITY, b64, suite,
  verifyAdmission } from './fixtures.js';

after(terminateCrypto);

function open(t, f, changes = {}) {
  const path = join(f.directory, 'directional.sqlite');
  const ledger = openDirectionalLedger(path);
  f.disposables.push(ledger);
  const options = { ledger, cohort: f.cohort, checkpointTrust: f.checkpointTrust,
    admissionTrust: f.admissionTrust, verifyAdmission, clock: f.clock,
    maxAuthorizedSend: 16, maxAcknowledgedReceive: 64, maxPending: 2,
    maxRequestBytes: 32768, authorizationSeconds: 30, ...changes };
  const service = createDirectionalService(options);
  return { ledger, path, service, options,
    count: (index, cohortId = options.cohort.public.cohortId) =>
      ledger.counters(COMMUNITY, cohortId, f.members[index].memberId) };
}
async function issued(service, action) {
  const response = await service.authorizeAndAcknowledge(action.request);
  assert.deepEqual(Object.keys(response), ['blindSignature']);
  return { response, receipt: await action.client.finish(response) };
}
async function rejected(service, request) {
  await assert.rejects(service.authorizeAndAcknowledge(request));
}
const counters = (authorizedSend = 0, acknowledgedReceive = 0) => ({ authorizedSend, acknowledgedReceive });

test('real sender-excluded proof creates one recoverable receipt, with each own-account action required', async t => {
  const f = await fixture(t);
  const s = open(t, f);
  await assert.rejects(f.action(0, 0));
  const action = await f.action();
  assert.equal(action.request.checkpoint.commitments.length - 1, 16);
  const { receipt } = await issued(s.service, action);
  assert.deepEqual(s.count(0), counters(1, 0));
  assert.deepEqual(s.count(1), counters());
  assert.equal(await s.service.redeemAcknowledgedReceipt(f.redemption(receipt)), true);
  assert.deepEqual(s.count(1), counters(0, 1));
});

test('copied grants, altered purpose/request, invalid proof and unsolicited sender targets cannot debit', async t => {
  const f = await fixture(t);
  const s = open(t, f);
  const action = await f.action();
  for (const mutate of [
    request => { request.senderAuthorization.signature = ''; },
    request => { request.senderAuthorization.purpose = 'ordinary-permit'; },
    request => { request.senderAuthorization.senderId = f.members[2].memberId; },
    request => { request.senderAdmission = f.grantFor(f.members[2]); },
    request => { request.blindedReceiptRequest.blinded = 'A'.repeat(512); },
    request => { request.senderAuthorization.expiresAt = NOW; },
    request => { request.semaphoreProof.points[0] = '1'; },
    request => { request.checkpoint.commitments.pop(); },
    request => { request.senderBinding.commitment = f.members[1].identity.commitment.toString(); },
  ]) {
    const altered = structuredClone(action.request);
    mutate(altered);
    await rejected(s.service, altered);
  }
  assert.deepEqual(s.count(0), counters());
  assert.deepEqual(s.count(2), counters());
  await issued(s.service, action); // Negative attempts consume no authorization or nullifier.
  assert.deepEqual(s.count(0), counters(1, 0));
});

test('account-bound receipt needs its owner signature; copying an admission or token is insufficient', async t => {
  const f = await fixture(t);
  const s = open(t, f);
  const { receipt } = await issued(s.service, await f.action());
  assert.equal(await s.service.redeemAcknowledgedReceipt(f.redemption(receipt, f.members[2])), false);
  const missing = f.redemption(receipt);
  missing.authorization.signature = '';
  assert.equal(await s.service.redeemAcknowledgedReceipt(missing), false);
  const changed = f.redemption(receipt);
  changed.authorization.purpose = 'authorized-send';
  assert.equal(await s.service.redeemAcknowledgedReceipt(changed), false);
  const wrongReceipt = f.redemption(receipt);
  wrongReceipt.receipt = { ...receipt, message: b64(Buffer.alloc(128)) };
  assert.equal(await s.service.redeemAcknowledgedReceipt(wrongReceipt), false);
  assert.deepEqual(s.count(1), counters());
  const good = f.redemption(receipt);
  assert.equal(await s.service.redeemAcknowledgedReceipt(good), true);
  assert.equal(await s.service.redeemAcknowledgedReceipt(good), true);
  assert.deepEqual(s.count(1), counters(0, 1));
  assert.deepEqual(s.count(2), counters());
});

test('parallel identical issuance and redemption over independent SQLite connections increment once', async t => {
  const f = await fixture(t);
  const a = open(t, f);
  const b = open(t, f);
  const action = await f.action();
  const [first, duplicate] = await Promise.all([a.service.authorizeAndAcknowledge(action.request),
    b.service.authorizeAndAcknowledge(action.request)]);
  assert.deepEqual(first, duplicate);
  assert.deepEqual(b.count(0), counters(1, 0));
  const receipt = await action.client.finish(first);
  const redemption = f.redemption(receipt);
  assert.deepEqual(await Promise.all([a.service.redeemAcknowledgedReceipt(redemption),
    b.service.redeemAcknowledgedReceipt(redemption)]), [true, true]);
  assert.deepEqual(b.count(1), counters(0, 1));
  assert.deepEqual(b.ledger.counts(), { authorizations: 1, lifetimeNullifiers: 1, redeemedReceipts: 1 });
});

test('one authorization used by two distinct provers spends only the winning lifetime nullifier', async t => {
  const f = await fixture(t);
  const s = open(t, f);
  const a = await f.action();
  const b = await f.action(0, 2, 1, { client: a.client, authorization: a.request.senderAuthorization });
  const attempts = await Promise.allSettled([s.service.authorizeAndAcknowledge(a.request),
    s.service.authorizeAndAcknowledge(b.request)]);
  assert.equal(attempts.filter(value => value.status === 'fulfilled').length, 1);
  const loser = attempts[0].status === 'rejected' ? 1 : 2;
  await issued(s.service, await f.action(0, loser));
  assert.deepEqual(s.count(0), counters(2, 0));
  assert.equal(s.ledger.counts().lifetimeNullifiers, 2);
});

test('interruption before the issuance commit rolls back all four coupled writes', async t => {
  const f = await fixture(t);
  let fail = true;
  const s = open(t, f, { fault: phase => {
    if (fail && phase === 'issue-before-commit') { fail = false; throw new Error('Injected precommit interruption'); }
  } });
  const action = await f.action();
  await rejected(s.service, action.request);
  assert.deepEqual(s.count(0), counters());
  assert.deepEqual(s.ledger.counts(), { authorizations: 0, lifetimeNullifiers: 0, redeemedReceipts: 0 });
  await issued(s.service, action);
  assert.deepEqual(s.count(0), counters(1, 0));
});

test('lost committed response is recovered after restart and checkpoint expiry without a second debit', async t => {
  const f = await fixture(t);
  const s = open(t, f, { fault: phase => {
    if (phase === 'issue-after-commit') throw new Error('Injected lost response');
  } });
  const action = await f.action();
  await rejected(s.service, action.request);
  assert.deepEqual(s.count(0), counters(1, 0));
  s.ledger.close();
  f.advance(NOW + 70); // Authorization and checkpoint expired, common receipt recovery window still open.
  const resumed = open(t, f);
  const first = await resumed.service.authorizeAndAcknowledge(action.request);
  const again = await resumed.service.authorizeAndAcknowledge(action.request);
  assert.deepEqual(first, again);
  const receipt = await action.client.finish(first);
  assert.equal(await resumed.service.redeemAcknowledgedReceipt(f.redemption(receipt)), true);
  assert.deepEqual(resumed.count(0), counters(1, 0));
  assert.deepEqual(resumed.count(1), counters(0, 1));
  const uncached = await f.action(0, 2);
  await issued(resumed.service, uncached);
  assert.deepEqual(resumed.count(0), counters(2, 0));
});

test('receive commit is atomic and a lost success can be retried after reopening', async t => {
  const f = await fixture(t);
  let phaseToFail = 'receive-before-commit';
  const s = open(t, f, { fault: phase => { if (phase === phaseToFail) throw new Error('Injected receive interruption'); } });
  const { receipt } = await issued(s.service, await f.action());
  const redemption = f.redemption(receipt);
  assert.equal(await s.service.redeemAcknowledgedReceipt(redemption), false);
  assert.deepEqual(s.count(1), counters());
  assert.equal(s.ledger.counts().redeemedReceipts, 0);
  phaseToFail = 'receive-after-commit';
  assert.equal(await s.service.redeemAcknowledgedReceipt(redemption), false);
  assert.deepEqual(s.count(1), counters(0, 1));
  s.ledger.close();
  const resumed = open(t, f);
  assert.equal(await resumed.service.redeemAcknowledgedReceipt(redemption), true);
  assert.deepEqual(resumed.count(1), counters(0, 1));
});

test('new checkpoints and cohort keys cannot reset a lifetime directed nullifier', async t => {
  const f = await fixture(t);
  const s = open(t, f);
  const first = await f.action();
  await issued(s.service, first);
  f.advance(NOW + 120);
  const context = { ...f.cohort.public, cohortId: 'cohort-2', notBefore: NOW + 120,
    issueUntil: NOW + 240, redeemUntil: NOW + 420,
    publicKey: await crypto.subtle.exportKey('jwk', f.alternateKeys.publicKey) };
  const next = open(t, f, { cohort: { public: context, privateKey: f.alternateKeys.privateKey } });
  const client = await f.prepare(f.members[1], context, f.alternateKeys);
  const authorization = f.authorization(f.members[0], client.request, { cohortId: context.cohortId });
  const repeated = await f.action(0, 1, 1, { client, authorization });
  assert.equal(repeated.request.semaphoreProof.nullifier, first.request.semaphoreProof.nullifier);
  await rejected(next.service, repeated.request);
  assert.deepEqual(next.count(0), counters());
  assert.deepEqual(next.count(0, 'cohort-1'), counters(1, 0));
});

test('an honest reversed action balances both sides without consuming an ordinary-reply permit', async t => {
  const f = await fixture(t);
  const s = open(t, f);
  const outbound = await issued(s.service, await f.action(0, 1));
  assert.equal(await s.service.redeemAcknowledgedReceipt(f.redemption(outbound.receipt, f.members[1])), true);
  const reverse = await issued(s.service, await f.action(1, 0));
  assert.equal(await s.service.redeemAcknowledgedReceipt(f.redemption(reverse.receipt, f.members[0])), true);
  assert.deepEqual(s.count(0), counters(1, 1));
  assert.deepEqual(s.count(1), counters(1, 1));
  // No permit ledger/API exists in this experiment: this does not prove a prior message or same-pair reply.
});

test('a malicious qualified prover can prepare the hidden receipt for the named sender', async t => {
  const f = await fixture(t);
  const s = open(t, f);
  const action = await f.action(0, 1, 0);
  const { receipt } = await issued(s.service, action);
  assert.equal(await s.service.redeemAcknowledgedReceipt(f.redemption(receipt, f.members[0])), true);
  assert.deepEqual(s.count(0), counters(1, 1));
  assert.deepEqual(s.count(1), counters()); // The hidden receipt owner is not proven to equal the prover.
});

test('three colluders pool k(k-1) receipts on one account while each sender stays bounded by k-1', async t => {
  const f = await fixture(t);
  const s = open(t, f);
  const k = 3;
  for (let sender = 0; sender < k; sender++) {
    for (let prover = 0; prover < k; prover++) {
      if (sender === prover) continue;
      const { receipt } = await issued(s.service, await f.action(sender, prover, 0));
      assert.equal(await s.service.redeemAcknowledgedReceipt(f.redemption(receipt, f.members[0])), true);
    }
  }
  assert.deepEqual(s.count(0), counters(k - 1, k * (k - 1)));
  assert.deepEqual(s.count(1), counters(k - 1, 0));
  assert.deepEqual(s.count(2), counters(k - 1, 0));
  await rejected(s.service, (await f.action(0, 1, 0)).request);
  assert.equal(s.ledger.counts().lifetimeNullifiers, k * (k - 1));
});

test('outside sender authorizations enlarge pooled credit, but outsiders cannot be debited without consent', async t => {
  const f = await fixture(t);
  const s = open(t, f);
  for (const prover of [0, 1]) {
    const action = await f.action(3, prover, 0);
    const forged = structuredClone(action.request);
    forged.senderAuthorization.signature = '';
    await rejected(s.service, forged);
    const { receipt } = await issued(s.service, action);
    assert.equal(await s.service.redeemAcknowledgedReceipt(f.redemption(receipt, f.members[0])), true);
  }
  assert.deepEqual(s.count(3), counters(2, 0));
  assert.deepEqual(s.count(0), counters(0, 2));
  assert.deepEqual(s.count(1), counters());
});

test('omitted receive recording remains possible and delayed redemption credits its issuance cohort only', async t => {
  const f = await fixture(t);
  const s = open(t, f);
  await issued(s.service, await f.action(0, 1)); // Modified/lost client deliberately never redeems.
  const delayed = await issued(s.service, await f.action(0, 2));
  assert.deepEqual(s.count(0), counters(2, 0));
  assert.deepEqual(s.count(1), counters());
  assert.deepEqual(s.count(2), counters());
  f.advance(NOW + 150);
  const wrongCohort = f.redemption(delayed.receipt, f.members[2], { cohortId: 'cohort-2' });
  assert.equal(await s.service.redeemAcknowledgedReceipt(wrongCohort), false);
  assert.equal(await s.service.redeemAcknowledgedReceipt(f.redemption(delayed.receipt, f.members[2])), true);
  assert.deepEqual(s.count(2), counters(0, 1));
  assert.deepEqual(s.count(2, 'cohort-2'), counters());
  assert.equal(s.ledger.counts().redeemedReceipts, 1); // Totals need not become equal.
});

test('pruning expiry state persists a retirement floor and retains lifetime nullifiers after clock rollback', async t => {
  const f = await fixture(t);
  const s = open(t, f);
  const action = await f.action();
  const { receipt } = await issued(s.service, action);
  f.advance(NOW + 300);
  assert.equal(await s.service.redeemAcknowledgedReceipt(f.redemption(receipt)), false);
  await rejected(s.service, action.request);
  s.ledger.prune(f.clock());
  assert.equal(s.ledger.counts().authorizations, 0);
  assert.equal(s.ledger.counts().lifetimeNullifiers, 1);
  s.ledger.close();
  f.advance(NOW + 10);
  const resumed = open(t, f);
  await rejected(resumed.service, action.request);
  assert.equal(await resumed.service.redeemAcknowledgedReceipt(f.redemption(receipt)), false);
});

test('an RSA signature obtained under another purpose key cannot create an acknowledged-receive credit', async t => {
  const f = await fixture(t);
  const s = open(t, f);
  // A malicious client blinds a correctly labelled receipt to an unrelated permit signing key.
  const client = await f.prepare(f.members[1], f.cohort.public, f.alternateKeys);
  const blindSignature = await suite.blindSign(f.alternateKeys.privateKey,
    Uint8Array.from(Buffer.from(client.request.blinded, 'base64url')));
  const crossPurpose = await client.finish({ blindSignature: b64(blindSignature) });
  assert.equal(await s.service.redeemAcknowledgedReceipt(f.redemption(crossPurpose)), false);
  assert.deepEqual(s.count(1), counters());
  const { receipt } = await issued(s.service, await f.action());
  assert.equal(await s.service.redeemAcknowledgedReceipt(f.redemption(receipt)), true);
});

test('a cohort cannot reuse another registered cohort signing key or silently raise its recorded limits', async t => {
  const f = await fixture(t);
  const s = open(t, f, { maxAuthorizedSend: 1 });
  await issued(s.service, await f.action());
  const reusedKey = { public: { ...f.cohort.public, cohortId: 'other-cohort' }, privateKey: f.cohort.privateKey };
  assert.throws(() => createDirectionalService({ ...s.options, cohort: reusedKey }));
  assert.throws(() => createDirectionalService({ ...s.options, maxAuthorizedSend: 2 }));
  assert.deepEqual(s.count(0), counters(1, 0));
});

test('a wrong same-algorithm private key rejects before any sender debit or lifetime nullifier consumption', async t => {
  const f = await fixture(t);
  const wrong = open(t, f, { cohort: { public: f.cohort.public, privateKey: f.alternateKeys.privateKey } });
  const alternate = await crypto.subtle.exportKey('jwk', f.alternateKeys.publicKey);
  const modulus = BigInt('0x' + Buffer.from(alternate.n, 'base64url').toString('hex'));
  let client;
  // Avoid an accidental RSA range rejection masking the missing public/private
  // binding: this valid honest blind request is also in the wrong key's range.
  for (let attempt = 0; attempt < 64; attempt++) {
    const candidate = await f.prepare();
    if (BigInt('0x' + Buffer.from(candidate.request.blinded, 'base64url').toString('hex')) < modulus) {
      client = candidate;
      break;
    }
  }
  assert.ok(client, 'A bounded honest blind request must be in both modulus ranges');
  const action = await f.action(0, 1, 1, { client });
  await rejected(wrong.service, action.request);
  assert.deepEqual(wrong.count(0), counters());
  assert.equal(wrong.ledger.counts().lifetimeNullifiers, 0);
  const correct = open(t, f);
  const { receipt } = await issued(correct.service, action);
  assert.equal(await correct.service.redeemAcknowledgedReceipt(f.redemption(receipt)), true);
});

test('an exhausted receive cap rejects the next receipt without consuming it or creating allowance', async t => {
  const f = await fixture(t);
  const s = open(t, f, { maxAcknowledgedReceive: 1 });
  const first = await issued(s.service, await f.action(0, 1, 1));
  const second = await issued(s.service, await f.action(2, 1, 1));
  assert.equal(await s.service.redeemAcknowledgedReceipt(f.redemption(first.receipt)), true);
  assert.equal(await s.service.redeemAcknowledgedReceipt(f.redemption(second.receipt)), false);
  assert.deepEqual(s.count(1), counters(0, 1));
  assert.deepEqual(s.ledger.counts(), { authorizations: 2, lifetimeNullifiers: 2, redeemedReceipts: 1 });
});

test('concurrent authorizations cannot exceed the named sender cap or fan one receipt out to 99 accounts', async t => {
  const f = await fixture(t);
  const a = open(t, f, { maxAuthorizedSend: 1 });
  const b = open(t, f, { maxAuthorizedSend: 1 });
  const actions = [await f.action(0, 1), await f.action(0, 2)];
  const results = await Promise.allSettled([a.service.authorizeAndAcknowledge(actions[0].request),
    b.service.authorizeAndAcknowledge(actions[1].request)]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  const winner = results[0].status === 'fulfilled' ? 0 : 1;
  const receipt = await actions[winner].client.finish(results[winner].value);
  const recipient = f.members[winner + 1];
  assert.equal(await a.service.redeemAcknowledgedReceipt(f.redemption(receipt, recipient)), true);
  for (let index = 0; index < 99; index++) {
    // These are 99 independently signed attempts by admitted accounts, not a claim of a 100-member fixture.
    const member = f.members[(winner + 2 + index) % f.members.length];
    if (member === recipient) continue;
    assert.equal(await a.service.redeemAcknowledgedReceipt(f.redemption(receipt, member)), false);
  }
  assert.deepEqual(a.count(0), counters(1, 0));
  assert.equal(a.ledger.counts().redeemedReceipts, 1);
});

test('authorization expiry after asynchronous admission verification cannot commit or consume quota', async t => {
  const f = await fixture(t);
  let expireDuringVerification = true;
  const s = open(t, f, { verifyAdmission: async input => {
    const valid = verifyAdmission(input);
    if (expireDuringVerification) f.advance(NOW + 30);
    return valid;
  } });
  const action = await f.action();
  await rejected(s.service, action.request);
  assert.deepEqual(s.count(0), counters());
  expireDuringVerification = false;
  const fresh = await f.action();
  for (const altered of [
    { ...fresh.request, extra: true },
    { ...fresh.request, blindedReceiptRequest: { blinded: 'A'.repeat(32769) } },
  ]) await rejected(s.service, altered);
  await issued(s.service, fresh);
  assert.deepEqual(s.count(0), counters(1, 0));
});

test('wire and retained rows contain no explicit sender-recipient join, without claiming timing anonymity', async t => {
  const f = await fixture(t);
  const s = open(t, f);
  const action = await f.action();
  const { receipt } = await issued(s.service, action);
  const redemption = f.redemption(receipt);
  assert.equal(await s.service.redeemAcknowledgedReceipt(redemption), true);
  const sender = f.members[0].memberId;
  const recipient = f.members[1].memberId;
  assert.equal(JSON.stringify(action.request).includes(recipient), false);
  assert.equal(JSON.stringify(redemption).includes(sender), false);
  for (const marker of [action.request.senderAuthorization.nonce, action.request.semaphoreProof.nullifier,
    action.request.senderAuthorization.requestHash, action.request.blindedReceiptRequest.blinded]) {
    assert.equal(JSON.stringify(redemption).includes(marker), false);
  }
  const db = new DatabaseSync(s.path, { readOnly: true });
  try {
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
    assert.ok(tables.length > 0);
    for (const { name } of tables) {
      assert.match(name, /^[a-z_]+$/);
      for (const row of db.prepare(`SELECT * FROM ${name}`).all()) {
        const values = Object.values(row).map(value => value instanceof Uint8Array ? b64(value) : String(value));
        const encoded = values.join('\n');
        assert.equal(encoded.includes(sender) && encoded.includes(recipient), false);
      }
    }
  } finally { db.close(); }
  // One issuance followed immediately by one redemption still has a one-candidate timing set.
  assert.equal(s.ledger.counts().authorizations, 1);
  assert.equal(s.ledger.counts().redeemedReceipts, 1);
  t.diagnostic(JSON.stringify({ namedIssuances: 1, redemptions: 1, timingCandidates: 1,
    networkAnonymityTested: false }));
});
