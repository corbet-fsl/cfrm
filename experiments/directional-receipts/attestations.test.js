import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createDirectionalService } from './receipts.js';
import { createReleaseReceiptService } from './attestations.js';
import { NOW, b64, hash, raw, terminateCrypto, verifyAdmission } from './fixtures.js';
import { releaseFixture, issued, rejected, counters, nonce, keys } from './attestation-fixtures.js';

after(terminateCrypto);

test('actual sender and receiver counter commits produce the exact separately signed cmsg statements', async t => {
  const f = await releaseFixture(t);
  const s = f.open();
  await assert.rejects(f.action(0, 0));
  const action = await f.action();
  assert.equal(action.request.checkpoint.commitments.length - 1, 16);
  const { output, receipt } = await issued(f, s.service, action);
  assert.equal(Buffer.from(receipt.message, 'base64url').length, 160);
  assert.deepEqual(s.count(0), counters(1, 0));
  assert.deepEqual(s.count(1), counters());
  assert.equal(output.senderCommit.context.expiresAt, NOW + 300);
  assert.notEqual(output.senderCommit.context.expiresAt, action.request.senderAuthorization.expiresAt);
  const received = await s.service.redeemAcknowledgedReceipt(f.redemption(receipt));
  f.checkRedemption(received, action);
  assert.deepEqual(s.count(1), counters(0, 1));
});

test('invalid authorization or proof cannot produce a sender statement, and the receiver must separately consent', async t => {
  const f = await releaseFixture(t);
  const s = f.open();
  const action = await f.action();
  for (const mutate of [
    request => { request.senderAuthorization.signature = ''; },
    request => { request.senderAuthorization.purpose = 'acknowledged-receive'; },
    request => { request.semaphoreProof.points[0] = '1'; },
    request => { request.checkpoint.commitments.pop(); },
    request => { request.senderAdmission = f.grantFor(f.members[2]); },
  ]) {
    const request = structuredClone(action.request);
    mutate(request);
    await rejected(s.service, request);
  }
  assert.deepEqual(s.count(0), counters());
  const { receipt } = await issued(f, s.service, action);
  const absentConsent = f.redemption(receipt);
  absentConsent.authorization.signature = '';
  assert.equal(await s.service.redeemAcknowledgedReceipt(absentConsent), false);
  assert.equal(await s.service.redeemAcknowledgedReceipt(f.redemption(receipt, f.members[2])), false);
  const changed = f.redemption(receipt);
  const bytes = Buffer.from(receipt.message, 'base64url');
  bytes[159] ^= 1;
  changed.receipt = { ...receipt, message: b64(bytes) };
  assert.equal(await s.service.redeemAcknowledgedReceipt(changed), false);
  assert.deepEqual(s.count(1), counters());
  f.checkRedemption(await s.service.redeemAcknowledgedReceipt(f.redemption(receipt)), action);
});

test('a sender precommit interruption rolls back the attestation together with nonce, nullifier and debit', async t => {
  const f = await releaseFixture(t);
  let fail = true;
  const s = f.open({ fault: phase => {
    if (fail && phase === 'issue-before-commit') { fail = false; throw new Error('Injected precommit interruption'); }
  } });
  const action = await f.action();
  await rejected(s.service, action.request);
  assert.deepEqual(s.count(0), counters());
  assert.deepEqual(s.ledger.counts(), { authorizations: 0, lifetimeNullifiers: 0, redeemedReceipts: 0 });
  await issued(f, s.service, action);
  assert.deepEqual(s.count(0), counters(1, 0));
});

test('a lost sender result recovers after short authorization and checkpoint expiry with unchanged common expiry', async t => {
  const f = await releaseFixture(t);
  const s = f.open({ fault: phase => { if (phase === 'issue-after-commit') throw new Error('Injected lost response'); } });
  const action = await f.action();
  await rejected(s.service, action.request);
  assert.deepEqual(s.count(0), counters(1, 0));
  s.ledger.close();
  f.advance(NOW + 70);
  const resumed = f.open();
  const first = await resumed.service.authorizeAndAcknowledge(action.request);
  const reordered = Object.fromEntries(Object.entries(action.request).reverse());
  const second = await resumed.service.authorizeAndAcknowledge(reordered);
  assert.deepEqual(first, second);
  f.checkCommit(first, action);
  assert.equal(first.senderCommit.context.notBefore, NOW);
  assert.equal(first.senderCommit.context.expiresAt, NOW + 300);
  const receipt = await action.client.finish(first);
  f.checkRedemption(await resumed.service.redeemAcknowledgedReceipt(f.redemption(receipt)), action);
  assert.deepEqual(resumed.count(0), counters(1, 0));
});

test('receiver interruption and fresh authorization recovery return the originally committed key and attestation', async t => {
  const f = await releaseFixture(t);
  let failure = 'receive-before-commit';
  const s = f.open({ fault: phase => { if (phase === failure) throw new Error('Injected receive interruption'); } });
  const action = await f.action();
  const { receipt } = await issued(f, s.service, action);
  const request = f.redemption(receipt);
  assert.equal(await s.service.redeemAcknowledgedReceipt(request), false);
  assert.deepEqual(s.count(1), counters());
  assert.equal(s.ledger.counts().redeemedReceipts, 0);
  failure = 'receive-after-commit';
  assert.equal(await s.service.redeemAcknowledgedReceipt(request), false);
  assert.deepEqual(s.count(1), counters(0, 1));
  s.ledger.close();
  f.advance(NOW + 70);
  const resumed = f.open();
  const first = await resumed.service.redeemAcknowledgedReceipt(f.redemption(receipt));
  f.checkRedemption(first, action);
  const renewedMember = { ...f.members[1], chat: keys() };
  const withRotatedKey = await resumed.service.redeemAcknowledgedReceipt(f.redemption(receipt, renewedMember));
  assert.deepEqual(withRotatedKey, first); // Current authorization can recover, never rewrite the old statement.
  assert.notEqual(withRotatedKey.recipientRedemption.recipient.chatPublicKey, b64(raw(renewedMember.chat.publicKey)));
  assert.deepEqual(resumed.count(1), counters(0, 1));
});

test('independent connections return identical cached sender and receiver results under concurrent replay', async t => {
  const f = await releaseFixture(t);
  const a = f.open();
  const b = f.open();
  const action = await f.action();
  const results = await Promise.all([a.service.authorizeAndAcknowledge(action.request), b.service.authorizeAndAcknowledge(action.request)]);
  assert.deepEqual(results[0], results[1]);
  f.checkCommit(results[0], action);
  const receipt = await action.client.finish(results[0]);
  const redemption = f.redemption(receipt);
  const recovered = await Promise.all([a.service.redeemAcknowledgedReceipt(redemption), b.service.redeemAcknowledgedReceipt(redemption)]);
  assert.deepEqual(recovered[0], recovered[1]);
  f.checkRedemption(recovered[0], action);
  assert.deepEqual(b.count(0), counters(1, 0));
  assert.deepEqual(b.count(1), counters(0, 1));
  assert.deepEqual(b.ledger.counts(), { authorizations: 1, lifetimeNullifiers: 1, redeemedReceipts: 1 });
});

test('a second serial for the same recipient and release nonce cannot create another debit or replacement statement', async t => {
  const f = await releaseFixture(t);
  const s = f.open();
  const releaseNonce = nonce();
  const a = await f.action(0, 1, 1, { client: await f.prepare(f.members[1], releaseNonce) });
  const b = await f.action(2, 1, 1, { client: await f.prepare(f.members[1], releaseNonce) });
  const first = await issued(f, s.service, a);
  const second = await issued(f, s.service, b);
  const attestation = await s.service.redeemAcknowledgedReceipt(f.redemption(first.receipt));
  f.checkRedemption(attestation, a);
  assert.equal(await s.service.redeemAcknowledgedReceipt(f.redemption(second.receipt)), false);
  assert.deepEqual(await s.service.redeemAcknowledgedReceipt(f.redemption(first.receipt)), attestation);
  assert.deepEqual(s.count(1), counters(0, 1));
  assert.equal(s.ledger.counts().redeemedReceipts, 1);
});

test('attestation key purpose, public-private pairing and cohort assignments are fixed and distinct', async t => {
  const f = await releaseFixture(t);
  const s = f.open();
  await issued(f, s.service, await f.action());
  for (const attestationKeys of [
    { senderCommit: f.attestationKeys.recipientRedemption, recipientRedemption: f.attestationKeys.senderCommit },
    { senderCommit: f.attestationKeys.senderCommit, recipientRedemption: f.attestationKeys.senderCommit },
    { ...f.attestationKeys, senderCommit: { ...f.attestationKeys.senderCommit, privateKey: keys().privateKey } },
    { ...f.attestationKeys, recipientRedemption: { publicKey: raw(keys().publicKey), privateKey: keys().privateKey } },
  ]) assert.throws(() => createReleaseReceiptService({ ...s.options, attestationKeys }));
  assert.deepEqual(s.count(0), counters(1, 0));
});

test('a same-algorithm wrong receipt private key cannot commit a sender attestation', async t => {
  const f = await releaseFixture(t);
  const s = f.open({ cohort: { public: f.cohort.public, privateKey: f.receiptKeys.privateKey } });
  const wrongPublic = await crypto.subtle.exportKey('jwk', f.receiptKeys.publicKey);
  const modulus = BigInt('0x' + Buffer.from(wrongPublic.n, 'base64url').toString('hex'));
  let client;
  for (let attempt = 0; attempt < 64; attempt++) {
    const candidate = await f.prepare();
    if (BigInt('0x' + Buffer.from(candidate.request.blinded, 'base64url').toString('hex')) < modulus) { client = candidate; break; }
  }
  assert.ok(client);
  const action = await f.action(0, 1, 1, { client });
  await rejected(s.service, action.request);
  assert.deepEqual(s.count(0), counters());
  assert.equal(s.ledger.counts().lifetimeNullifiers, 0);
  await issued(f, f.open().service, action);
});

test('raw receipts and release receipts use distinct RSA keys enforced by the same retained registry', async t => {
  const f = await releaseFixture(t);
  const s = f.open();
  const rawOptions = { ...s.options, cohort: f.rawCohort };
  const rawService = createDirectionalService(rawOptions);
  const rawClient = await f.prepareRaw(f.members[1]);
  const authorization = f.authorization(f.members[0], rawClient.request, { cohortId: f.rawCohort.public.cohortId });
  const rawAction = await f.action(0, 1, 1, { client: rawClient, authorization });
  const rawReceipt = await rawClient.finish(await rawService.authorizeAndAcknowledge(rawAction.request));
  assert.equal(await s.service.redeemAcknowledgedReceipt(f.redemption(rawReceipt)), false);
  const reused = { public: { ...f.cohort.public, cohortId: 'release-with-reused-key', publicKey: f.rawCohort.public.publicKey },
    privateKey: f.rawCohort.privateKey };
  assert.throws(() => createReleaseReceiptService({ ...s.options, cohort: reused }));
  const action = await f.action(2, 1);
  const { receipt } = await issued(f, s.service, action);
  f.checkRedemption(await s.service.redeemAcknowledgedReceipt(f.redemption(receipt)), action);
});

test('expired signed results and pruned receipt state cannot be revived by a clock rollback', async t => {
  const f = await releaseFixture(t);
  const s = f.open();
  const action = await f.action();
  const { output, receipt } = await issued(f, s.service, action);
  const attestation = await s.service.redeemAcknowledgedReceipt(f.redemption(receipt));
  f.checkRedemption(attestation, action);
  f.advance(NOW + 300);
  assert.equal(output.senderCommit.context.expiresAt, f.clock());
  assert.equal(attestation.recipientRedemption.context.expiresAt, f.clock());
  assert.equal(await s.service.redeemAcknowledgedReceipt(f.redemption(receipt)), false);
  await rejected(s.service, action.request);
  s.ledger.prune(f.clock());
  assert.deepEqual(s.ledger.counts(), { authorizations: 0, lifetimeNullifiers: 1, redeemedReceipts: 0 });
  s.ledger.close();
  f.advance(NOW + 10);
  const resumed = f.open();
  await rejected(resumed.service, action.request);
  assert.equal(await resumed.service.redeemAcknowledgedReceipt(f.redemption(receipt)), false);
});

test('sender and receive caps reject without issuing a usable statement or consuming the rejected receipt', async t => {
  const f = await releaseFixture(t);
  const s = f.open({ maxAuthorizedSend: 1, maxAcknowledgedReceive: 1 });
  const firstAction = await f.action();
  const first = await issued(f, s.service, firstAction);
  f.checkRedemption(await s.service.redeemAcknowledgedReceipt(f.redemption(first.receipt)), firstAction);
  await rejected(s.service, (await f.action(0, 2)).request);
  const second = await issued(f, s.service, await f.action(2, 1));
  assert.equal(await s.service.redeemAcknowledgedReceipt(f.redemption(second.receipt)), false);
  assert.deepEqual(s.count(0), counters(1, 0));
  assert.deepEqual(s.count(1), counters(0, 1));
  assert.deepEqual(s.ledger.counts(), { authorizations: 2, lifetimeNullifiers: 2, redeemedReceipts: 1 });
});

test('malicious hidden-owner reassignment still pools real signed receive credits without proving prover ownership', async t => {
  const f = await releaseFixture(t);
  const s = f.open();
  for (let sender = 0; sender < 3; sender++) {
    for (let prover = 0; prover < 3; prover++) {
      if (sender === prover) continue;
      const action = await f.action(sender, prover, 0);
      const { receipt } = await issued(f, s.service, action);
      const attestation = await s.service.redeemAcknowledgedReceipt(f.redemption(receipt, f.members[0]));
      f.checkRedemption(attestation, action, f.members[0]);
      if (prover !== 0) assert.notEqual(attestation.recipientRedemption.recipient.memberId, f.members[prover].memberId);
    }
  }
  assert.deepEqual(s.count(0), counters(2, 6));
  assert.deepEqual(s.count(1), counters(2, 0));
  assert.deepEqual(s.count(2), counters(2, 0));
});

test('matching recipient evidence can originate from a different authorized sender without asserting token provenance', async t => {
  const f = await releaseFixture(t);
  const s = f.open();
  const releaseNonce = nonce();
  const original = await f.action(0, 1, 1, { client: await f.prepare(f.members[1], releaseNonce) });
  const other = await f.action(2, 1, 1, { client: await f.prepare(f.members[1], releaseNonce) });
  const originalResult = await issued(f, s.service, original);
  const alternateResult = await issued(f, s.service, other);
  const received = await s.service.redeemAcknowledgedReceipt(f.redemption(alternateResult.receipt));
  f.checkCommit(originalResult.output, original);
  f.checkRedemption(received, original); // Same expected recipient/challenge; different signing interaction.
  assert.notEqual(original.request.senderAuthorization.requestHash, other.request.senderAuthorization.requestHash);
  assert.deepEqual(s.count(0), counters(1, 0));
  assert.deepEqual(s.count(2), counters(1, 0));
  assert.deepEqual(s.count(1), counters(0, 1));
});

test('release nonce and sender authorization fields remain separated across operator payloads and retained rows', async t => {
  const f = await releaseFixture(t);
  const s = f.open();
  const action = await f.action();
  const { output, receipt } = await issued(f, s.service, action);
  const request = f.redemption(receipt);
  const received = await s.service.redeemAcknowledgedReceipt(request);
  f.checkRedemption(received, action);
  const sender = f.members[0].memberId;
  const recipient = f.members[1].memberId;
  const senderSide = JSON.stringify([action.request, output]);
  const recipientSide = JSON.stringify([request, received]);
  for (const value of [recipient, b64(raw(f.members[1].chat.publicKey)), action.client.releaseNonce,
    hash(Buffer.from(action.client.releaseNonce, 'base64url'))]) assert.equal(senderSide.includes(value), false);
  for (const value of [sender, action.request.senderAuthorization.nonce, action.request.senderAuthorization.requestHash,
    action.request.semaphoreProof.nullifier]) assert.equal(recipientSide.includes(value), false);
  const db = new DatabaseSync(s.path, { readOnly: true });
  try {
    for (const { name } of db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all()) {
      assert.match(name, /^[a-z_]+$/);
      for (const row of db.prepare(`SELECT * FROM ${name}`).all()) {
        const encoded = Object.values(row).map(value => value instanceof Uint8Array ? b64(value) : String(value)).join('\n');
        assert.equal(encoded.includes(sender) && encoded.includes(recipient), false);
        if (encoded.includes(sender)) assert.equal(encoded.includes(action.client.releaseNonce), false);
      }
    }
  } finally { db.close(); }
  t.diagnostic(JSON.stringify({ tested: 'explicit-field-separation', timingCandidates: 1, networkAnonymityTested: false }));
});

test('authorization expiry during asynchronous verification prevents both debit and attestation', async t => {
  const f = await releaseFixture(t);
  let expire = true;
  const s = f.open({ verifyAdmission: async input => {
    const valid = verifyAdmission(input);
    if (expire) f.advance(NOW + 30);
    return valid;
  } });
  await rejected(s.service, (await f.action()).request);
  assert.deepEqual(s.count(0), counters());
  assert.deepEqual(s.ledger.counts(), { authorizations: 0, lifetimeNullifiers: 0, redeemedReceipts: 0 });
  expire = false;
  await issued(f, s.service, await f.action());
  assert.deepEqual(s.count(0), counters(1, 0));
});
