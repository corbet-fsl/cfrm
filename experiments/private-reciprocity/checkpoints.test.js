import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { Identity } from '@semaphore-protocol/identity';
import { getCurveFromName } from 'ffjavascript';
import { createEnrollmentService, enrollmentBytes, enrollmentMessage, openEnrollmentLedger } from './enrollment.js';
import { createCheckpointPublisher, verifyCheckpoint, verifyEnrollmentBinding,
  registeredAcknowledgementContext } from './checkpoints.js';
import { proveRegisteredAcknowledgement, acceptRegisteredAcknowledgement,
  openAcknowledgementLedger } from './acknowledgement.js';

if (!process.env.CVLD_ADMISSION_MODULE) throw new Error('Pinned real cvld admission module is required');
const { verifyAdmission, admissionBytes } = await import(pathToFileURL(process.env.CVLD_ADMISSION_MODULE).href);
const NOW = 1_800_000_000; // An exact 60-second boundary.
const id = value => createHash('sha256').update(value).digest('base64url');
const keys = () => generateKeyPairSync('ed25519');
const raw = key => Buffer.from(key.export({ format: 'jwk' }).x, 'base64url');
const serializeSignature = signature => ({ R8: signature.R8.map(String), S: String(signature.S) });
const numericOrder = (a, b) => BigInt(a) < BigInt(b) ? -1 : BigInt(a) > BigInt(b) ? 1 : 0;
const artifacts = { wasm: new URL('./.artifacts/semaphore.wasm', import.meta.url).pathname,
  zkey: new URL('./.artifacts/semaphore.zkey', import.meta.url).pathname };
let curve;
after(async () => { if (curve) await curve.terminate(); });

async function fixture(t, count = 3) {
  const directory = mkdtempSync(join(tmpdir(), 'cfrm-checkpoints-'));
  const path = join(directory, 'registered.sqlite');
  const issuer = keys();
  const publisherKey = keys();
  const communityId = 'community.example';
  const policyDigest = id('policy');
  const ledger = openEnrollmentLedger(path);
  let now = NOW;
  let duringVerification;
  const enrollmentOptions = { communityId, policyDigest, trustedPublicKey: raw(issuer.publicKey),
    verifyAdmission: async input => {
      const valid = verifyAdmission(input);
      if (duringVerification) duringVerification();
      return valid;
    }, ledger, clock: () => now, challengeSeconds: 5 };
  const enrollment = createEnrollmentService(enrollmentOptions);
  const publisherOptions = { ledger, communityId, policyDigest, signingKey: publisherKey.privateKey,
    clock: () => now, epochSeconds: 60, minAnonymity: 16, depth: 7, maxRetainedLinks: 128 };
  const disposables = [];
  t.after(() => {
    for (const disposable of disposables.reverse()) disposable.close();
    enrollment.close(); ledger.close(); rmSync(directory, { recursive: true, force: true });
  });
  const publisher = createCheckpointPublisher(publisherOptions);
  disposables.push(publisher);
  const members = Array.from({ length: count }, (_, index) => ({
    memberId: id(`registered-${index}`), identity: new Identity(`synthetic-registered-${index}`), chat: keys(),
  }));
  function grantFor(member, changes = {}) {
    const grant = { version: 1, issuerKeyId: id(raw(issuer.publicKey)), communityId,
      memberId: member.memberId, chatPublicKey: raw(member.chat.publicKey).toString('base64url'), policyDigest,
      issuedAt: now, expiresAt: now + 120, ...changes };
    return { ...grant, signature: sign(null, admissionBytes(grant), issuer.privateKey).toString('base64url') };
  }
  async function request(member = members[0], changes = {}, service = enrollment) {
    const grant = grantFor(member, changes);
    const envelope = await service.begin(grant, member.identity.commitment.toString());
    return { grant, ...envelope, publicKey: member.identity.publicKey.map(String),
      semaphoreSignature: serializeSignature(member.identity.signMessage(enrollmentMessage(envelope.challenge))),
      chatSignature: sign(null, enrollmentBytes(envelope.challenge), member.chat.privateKey).toString('base64url') };
  }
  async function renew(member = members[0], changes = {}, service = enrollment) {
    return service.enroll(await request(member, changes, service));
  }
  const trust = { trustedPublicKey: raw(publisherKey.publicKey), communityId, policyDigest, clock: () => now };
  return { ledger, path, publisher, publisherOptions, enrollment, enrollmentOptions, members, request,
    renew, grantFor, publisherKey, communityId, policyDigest, trust, disposables,
    advance: value => { now = value; }, onVerify: fn => { duringVerification = fn; } };
}

test('a signed checkpoint includes every registered qualification covering its whole interval, without member IDs', async t => {
  const f = await fixture(t);
  for (const member of f.members) assert.equal(await f.renew(member), true);
  const checkpoint = f.publisher.publish();
  assert.equal(verifyCheckpoint({ checkpoint, ...f.trust }), true);
  assert.deepEqual(checkpoint.commitments, f.members.map(m => m.identity.commitment.toString()).sort(numericOrder));
  assert.equal(checkpoint.notBefore, NOW);
  assert.equal(checkpoint.expiresAt, NOW + 60);
  assert.equal(checkpoint.epoch, NOW / 60);
  for (const member of f.members) {
    assert.equal(JSON.stringify(checkpoint).includes(member.memberId), false);
    assert.equal(JSON.stringify(checkpoint).includes(raw(member.chat.publicKey).toString('base64url')), false);
  }
});

test('a validity ending exactly at checkpoint expiry qualifies; one second short never shortens the epoch', async t => {
  const f = await fixture(t);
  assert.equal(await f.renew(f.members[0], { expiresAt: NOW + 60 }), true);
  assert.equal(await f.renew(f.members[1], { expiresAt: NOW + 59 }), true);
  assert.equal(await f.renew(f.members[2], { expiresAt: NOW + 180 }), true);
  const checkpoint = f.publisher.publish();
  assert.equal(checkpoint.expiresAt, NOW + 60);
  assert.deepEqual(checkpoint.commitments, [f.members[0], f.members[2]].map(m => m.identity.commitment.toString()).sort(numericOrder));
  f.advance(NOW + 60);
  assert.equal(verifyCheckpoint({ checkpoint, ...f.trust }), false);
  assert.deepEqual(f.publisher.publish().commitments, [f.members[2].identity.commitment.toString()]);
});

test('fresh admission and key possession renew eligibility while immutable binding survives expiry and restart', async t => {
  const f = await fixture(t, 1);
  assert.equal(await f.renew(f.members[0], { expiresAt: NOW + 60 }), true);
  const binding = f.publisher.binding(f.members[0].memberId);
  assert.equal(verifyEnrollmentBinding({ binding, ...f.trust }), true);
  f.publisher.publish();
  f.advance(NOW + 60);
  assert.deepEqual(f.publisher.publish().commitments, []);
  assert.equal(await f.renew(), true);
  assert.deepEqual(f.publisher.publish().commitments, []); // Frozen current epoch never changes.
  f.advance(NOW + 120);
  const reopenedLedger = openEnrollmentLedger(f.path);
  f.disposables.push(reopenedLedger);
  const reopened = createCheckpointPublisher({ ...f.publisherOptions, ledger: reopenedLedger });
  f.disposables.push(reopened);
  assert.deepEqual(reopened.binding(f.members[0].memberId), binding);
  assert.deepEqual(reopened.publish().commitments, [f.members[0].identity.commitment.toString()]);
});

test('copied admission, replay or missing certified key possession cannot refresh a qualification', async t => {
  const f = await fixture(t, 1);
  const initial = await f.request(f.members[0], { expiresAt: NOW + 60 });
  assert.equal(await f.enrollment.enroll(initial), true);
  assert.equal(await f.enrollment.enroll(initial), false);
  const copied = await f.request(f.members[0], { expiresAt: NOW + 180 });
  assert.equal(await f.enrollment.enroll({ ...copied, chatSignature: '' }), false);
  f.advance(NOW + 60);
  assert.deepEqual(f.publisher.publish().commitments, []);
});

test('qualification expiry during asynchronous cvld verification cannot be committed', async t => {
  const f = await fixture(t, 1);
  const pending = await f.request(f.members[0], { expiresAt: NOW + 2 });
  f.onVerify(() => f.advance(NOW + 2));
  assert.equal(await f.enrollment.enroll(pending), false);
  f.onVerify(undefined);
  assert.deepEqual(f.publisher.publish().commitments, []);
  assert.throws(() => f.publisher.binding(f.members[0].memberId));
});

test('no caller can supply a subset, and late registration cannot rewrite a frozen epoch', async t => {
  const f = await fixture(t);
  assert.equal(await f.renew(f.members[0]), true);
  const first = f.publisher.publish();
  assert.throws(() => f.publisher.publish({ commitments: [] }));
  assert.equal(await f.renew(f.members[1]), true);
  assert.deepEqual(f.publisher.publish(), first);
  f.advance(NOW + 60);
  const next = f.publisher.publish();
  assert.deepEqual(next.commitments, f.members.slice(0, 2).map(m => m.identity.commitment.toString()).sort(numericOrder));
  assert.equal(next.previousDigest, first.digest);
  assert.equal(verifyCheckpoint({ checkpoint: next, ...f.trust, previous: first }), true);
});

test('independent publishers share one immutable epoch and cannot substitute another policy or signing key', async t => {
  const f = await fixture(t, 1);
  assert.equal(await f.renew(), true);
  const first = f.publisher.publish();
  const otherLedger = openEnrollmentLedger(f.path);
  f.disposables.push(otherLedger);
  const other = createCheckpointPublisher({ ...f.publisherOptions, ledger: otherLedger });
  f.disposables.push(other);
  assert.deepEqual(other.publish(), first);
  for (const change of [{ policyDigest: id('different-policy') }, { signingKey: keys().privateKey }, { epochSeconds: 30 }]) {
    const conflicting = createCheckpointPublisher({ ...f.publisherOptions, ledger: otherLedger, ...change });
    f.disposables.push(conflicting);
    assert.throws(() => conflicting.publish());
  }
});

test('durable epoch and clock floors reject rollback even after reopening the publisher', async t => {
  const f = await fixture(t, 1);
  assert.equal(await f.renew(), true);
  f.publisher.publish();
  f.advance(NOW + 60);
  const latest = f.publisher.publish();
  const otherLedger = openEnrollmentLedger(f.path);
  f.disposables.push(otherLedger);
  const other = createCheckpointPublisher({ ...f.publisherOptions, ledger: otherLedger });
  f.disposables.push(other);
  f.advance(NOW);
  assert.throws(() => other.publish());
  assert.equal(verifyCheckpoint({ checkpoint: latest, ...f.trust }), false);
});

test('pinned issuer, policy, exact encodings and signatures reject altered checkpoint or sender binding', async t => {
  const f = await fixture(t);
  for (const member of f.members) assert.equal(await f.renew(member), true);
  const checkpoint = f.publisher.publish();
  const binding = f.publisher.binding(f.members[0].memberId);
  assert.equal(verifyCheckpoint({ checkpoint, ...f.trust, trustedPublicKey: raw(keys().publicKey) }), false);
  assert.equal(verifyCheckpoint({ checkpoint, ...f.trust, policyDigest: id('other') }), false);
  for (const change of [{ commitments: checkpoint.commitments.slice(1) },
    { commitments: [...checkpoint.commitments].reverse() }, { expiresAt: checkpoint.expiresAt + 1 }, { extra: true }]) {
    assert.equal(verifyCheckpoint({ checkpoint: { ...checkpoint, ...change }, ...f.trust }), false);
  }
  for (const change of [{ memberId: f.members[1].memberId },
    { commitment: f.members[1].identity.commitment.toString() }, { communityId: 'other.example' }, { extra: true }]) {
    assert.equal(verifyEnrollmentBinding({ binding: { ...binding, ...change }, ...f.trust }), false);
  }
});

test('a client with a previous checkpoint rejects rollback and a broken signed chain', async t => {
  const f = await fixture(t, 1);
  assert.equal(await f.renew(), true);
  const first = f.publisher.publish();
  assert.equal(verifyCheckpoint({ checkpoint: first, ...f.trust, previous: first }), true);
  f.advance(NOW + 60);
  const next = f.publisher.publish();
  assert.equal(verifyCheckpoint({ checkpoint: next, ...f.trust, previous: first }), true);
  assert.equal(verifyCheckpoint({ checkpoint: first, ...f.trust, previous: next }), false);
  assert.equal(verifyCheckpoint({ checkpoint: next, ...f.trust, previous: { ...first, digest: id('wrong-chain') } }), false);
});

test('compact authenticated links let a returning client catch up without archived membership rosters', async t => {
  const f = await fixture(t, 1);
  assert.equal(await f.renew(f.members[0], { expiresAt: NOW + 240 }), true);
  const first = f.publisher.publish();
  f.advance(NOW + 60);
  const middle = f.publisher.publish();
  f.advance(NOW + 120);
  const latest = f.publisher.publish();
  const links = f.publisher.links(first.epoch, latest.epoch);
  assert.equal(links.length, 1);
  assert.equal(links[0].digest, middle.digest);
  assert.equal(Object.hasOwn(links[0], 'commitments'), false);
  assert.equal(JSON.stringify(links).includes(f.members[0].memberId), false);
  assert.equal(verifyCheckpoint({ checkpoint: latest, ...f.trust, previous: first }), false);
  assert.equal(verifyCheckpoint({ checkpoint: latest, ...f.trust, previous: first, links }), true);
  assert.equal(verifyCheckpoint({ checkpoint: latest, ...f.trust, previous: first,
    links: [{ ...links[0], digest: id('forged-link') }] }), false);
});

test('a configured compact-link retention ceiling never silently bypasses a missing chain segment', async t => {
  const f = await fixture(t, 0);
  const bounded = createCheckpointPublisher({ ...f.publisherOptions, maxRetainedLinks: 2 });
  f.disposables.push(bounded);
  const first = bounded.publish();
  f.advance(NOW + 60); bounded.publish();
  f.advance(NOW + 120); bounded.publish();
  f.advance(NOW + 180);
  const latest = bounded.publish();
  const remaining = bounded.links(first.epoch, latest.epoch);
  assert.equal(remaining.length, 1); // Latest link also occupies one of the two retained slots.
  assert.equal(verifyCheckpoint({ checkpoint: latest, ...f.trust, previous: first, links: remaining }), false);
});

test('registered proofs exclude only the independently certified sender commitment and retain lifetime replay bounds', async t => {
  curve = await getCurveFromName('bn128');
  const f = await fixture(t, 17);
  for (const member of f.members) assert.equal(await f.renew(member), true);
  const checkpoint = f.publisher.publish();
  const binding = f.publisher.binding(f.members[0].memberId);
  const context = registeredAcknowledgementContext(checkpoint, binding, f.trust);
  assert.equal(context.senderId, f.members[0].memberId);
  assert.equal(context.anonymitySetSize, 16);
  await assert.rejects(proveRegisteredAcknowledgement(f.members[0].identity, checkpoint, binding, f.trust, artifacts));
  assert.throws(() => registeredAcknowledgementContext(checkpoint,
    { ...binding, commitment: f.members[1].identity.commitment.toString() }, f.trust));
  const proof = await proveRegisteredAcknowledgement(f.members[1].identity, checkpoint, binding, f.trust, artifacts);
  const store = openAcknowledgementLedger(join(dirname(f.path), 'ack.sqlite'));
  f.disposables.push(store);
  assert.equal(await acceptRegisteredAcknowledgement(checkpoint, binding, f.trust, proof, store), true);
  assert.equal(await acceptRegisteredAcknowledgement(checkpoint, binding, f.trust, proof, store), false);
  f.advance(NOW + 60);
  const next = f.publisher.publish();
  const nextProof = await proveRegisteredAcknowledgement(f.members[1].identity, next, binding, f.trust, artifacts);
  assert.equal(nextProof.nullifier, proof.nullifier);
  assert.equal(await acceptRegisteredAcknowledgement(next, binding, f.trust, nextProof, store), false);
});
