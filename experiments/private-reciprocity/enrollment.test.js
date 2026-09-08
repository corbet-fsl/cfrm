import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Identity } from '@semaphore-protocol/identity';
import { createEnrollmentService, deriveSemaphoreIdentity, enrollmentBytes,
  enrollmentMessage, openEnrollmentLedger } from './enrollment.js';

const NOW = 1_800_000_000;
const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const id = text => createHash('sha256').update(text).digest('base64url');
const key = () => generateKeyPairSync('ed25519');
const raw = publicKey => publicKey.export({ format: 'jwk' }).x;
const certBytes = grant => Buffer.from(JSON.stringify(['cvld.admission.v1', grant.issuerKeyId,
  grant.communityId, grant.memberId, grant.chatPublicKey, grant.policyDigest, grant.issuedAt, grant.expiresAt]));
const signatureJSON = signature => ({ R8: signature.R8.map(String), S: String(signature.S) });

function verifyFixture({ grant, trustedPublicKey, communityId, policyDigest, now }) {
  try {
    return grant.version === 1 && grant.communityId === communityId && grant.policyDigest === policyDigest &&
      grant.issuerKeyId === id(trustedPublicKey) && grant.issuedAt <= now && now < grant.expiresAt &&
      verify(null, certBytes(grant), createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519',
        x: Buffer.from(trustedPublicKey).toString('base64url') }, format: 'jwk' }), Buffer.from(grant.signature, 'base64url'));
  } catch { return false; }
}

function fixture(t) {
  const issuer = key();
  const chat = key();
  const communityId = 'community.example';
  const memberId = id('member');
  const policyDigest = id('policy');
  const walletMaterial = new Uint8Array(32).fill(7); // Synthetic wallet.storageKey('cfrm-semaphore') output.
  const identity = deriveSemaphoreIdentity(walletMaterial, communityId);
  let now = NOW;
  const directory = mkdtempSync(join(tmpdir(), 'cfrm-enrollment-'));
  const path = join(directory, 'bindings.sqlite');
  const ledger = openEnrollmentLedger(path);
  const options = { communityId, policyDigest, trustedPublicKey: Buffer.from(raw(issuer.publicKey), 'base64url'),
    verifyAdmission: verifyFixture, ledger, clock: () => now, challengeSeconds: 5 };
  const service = createEnrollmentService(options);
  t.after(() => { service.close(); ledger.close(); rmSync(directory, { recursive: true, force: true }); });
  const certify = (chatKey = chat, owner = memberId, changes = {}) => {
    const grant = { version: 1, issuerKeyId: id(options.trustedPublicKey), communityId, memberId: owner,
      chatPublicKey: raw(chatKey.publicKey), policyDigest, issuedAt: NOW, expiresAt: NOW + 100, ...changes };
    return { ...grant, signature: sign(null, certBytes(grant), issuer.privateKey).toString('base64url') };
  };
  const request = async (sem = identity, chatKey = chat, grant = certify(chatKey), target = service) => {
    const envelope = await target.begin(grant, sem.commitment.toString());
    return { grant, ...envelope, publicKey: sem.publicKey.map(String),
      semaphoreSignature: signatureJSON(sem.signMessage(enrollmentMessage(envelope.challenge))),
      chatSignature: sign(null, enrollmentBytes(envelope.challenge), chatKey.privateKey).toString('base64url') };
  };
  return { service, ledger, identity, chat, issuer, walletMaterial, communityId, memberId,
    options, path, certify, request, advance: value => { now = value; } };
}

test('restored wallet material gives one stable community identity independent of chat/passkey rewrapping', () => {
  const walletMaterial = new Uint8Array(32).fill(7);
  const before = deriveSemaphoreIdentity(walletMaterial, 'community.example');
  const restored = deriveSemaphoreIdentity(Uint8Array.from(walletMaterial), 'community.example');
  assert.equal(before.commitment, restored.commitment);
  assert.notEqual(before.commitment, deriveSemaphoreIdentity(walletMaterial, 'other.example').commitment);
  assert.throws(() => deriveSemaphoreIdentity(new Uint8Array(31), 'community.example'));
});
test('both certified chat-key and existing Semaphore key possession create one immutable binding', async t => {
  const { service, ledger, request, memberId, communityId, identity } = fixture(t);
  assert.equal(await service.enroll(await request()), true);
  assert.deepEqual(ledger.members(communityId), [{ memberId, commitment: identity.commitment.toString() }]);
});
test('copied admission or copied Semaphore public key without its corresponding signature cannot enroll', async t => {
  const { service, request } = fixture(t);
  const valid = await request();
  assert.equal(await service.enroll({ ...valid, chatSignature: '' }), false);
  assert.equal(await service.enroll({ ...valid, semaphoreSignature: { R8: ['0', '1'], S: '0' } }), false);
  assert.equal(await service.enroll(valid), true);
});
test('a second valid commitment cannot replace the same stable member binding', async t => {
  const { service, ledger, request, communityId, identity } = fixture(t);
  assert.equal(await service.enroll(await request()), true);
  assert.equal(await service.enroll(await request(new Identity('replacement'))), false);
  assert.equal(ledger.members(communityId)[0].commitment, identity.commitment.toString());
});
test('new certified chat keys may authenticate the existing binding without rotating its Semaphore identity', async t => {
  const { service, request, ledger, communityId, identity } = fixture(t);
  assert.equal(await service.enroll(await request()), true);
  assert.equal(await service.enroll(await request(identity, key())), true);
  assert.equal(ledger.members(communityId).length, 1);
});
test('one commitment cannot be attached to multiple admitted member IDs in the same community', async t => {
  const { service, request, identity, chat, certify } = fixture(t);
  assert.equal(await service.enroll(await request()), true);
  assert.equal(await service.enroll(await request(identity, chat, certify(chat, id('other-member')))), false);
});
test('neutral and torsion public points are rejected even when cofactored signature equations could pass', async t => {
  const { service, certify, chat } = fixture(t);
  for (const publicKey of [[0n, 1n], [0n, FIELD - 1n]]) {
    const grant = certify();
    const commitment = Identity.generateCommitment(publicKey).toString();
    const envelope = await service.begin(grant, commitment);
    const chatSignature = sign(null, enrollmentBytes(envelope.challenge), chat.privateKey).toString('base64url');
    assert.equal(await service.enroll({ grant, ...envelope, publicKey: publicKey.map(String),
      chatSignature, semaphoreSignature: { R8: ['0', '1'], S: '0' } }), false);
  }
});
test('off-curve points, coordinate aliases and malformed signature scalars are rejected', async t => {
  const { service, request } = fixture(t);
  const valid = await request();
  for (const publicKey of [['1', '1'], ['0', (FIELD + 1n).toString()], ['01', '1']]) {
    assert.equal(await service.enroll({ ...valid, publicKey }), false);
  }
  for (const S of ['-1', '00', FIELD.toString()]) {
    assert.equal(await service.enroll({ ...valid, semaphoreSignature: { ...valid.semaphoreSignature, S } }), false);
  }
});
test('challenge replay and expiry cannot create or rotate a binding', async t => {
  const { service, request, advance } = fixture(t);
  const first = await request();
  assert.equal(await service.enroll(first), true);
  assert.equal(await service.enroll(first), false);
  const expired = await request();
  advance(NOW + 5);
  assert.equal(await service.enroll(expired), false);
});
test('independent connections and a restarted service cannot change the committed mapping', async t => {
  const { service, request, identity, chat, certify, options, ledger, path, communityId } = fixture(t);
  let otherLedger = openEnrollmentLedger(path);
  let otherService = createEnrollmentService({ ...options, ledger: otherLedger });
  t.after(() => { otherService.close(); otherLedger.close(); });
  assert.equal(await service.enroll(await request()), true);
  const replacement = new Identity('second-process-replacement');
  assert.equal(await otherService.enroll(await request(replacement, chat, certify(), otherService)), false);
  assert.equal(otherLedger.members(communityId)[0].commitment, identity.commitment.toString());

  otherService.close();
  otherLedger.close();
  otherLedger = openEnrollmentLedger(path);
  otherService = createEnrollmentService({ ...options, ledger: otherLedger });
  assert.equal(otherLedger.members(communityId)[0].commitment, identity.commitment.toString());
  assert.equal(await otherService.enroll(await request(replacement, chat, certify(), otherService)), false);
  assert.equal(await otherService.enroll(await request(identity, chat, certify(), otherService)), true);
  assert.equal(ledger.members(communityId).length, 1);
});
test('two independent services racing different commitments can commit only one binding', async t => {
  const { service, request, identity, chat, certify, options, ledger, path, communityId, memberId } = fixture(t);
  const otherLedger = openEnrollmentLedger(path);
  const otherService = createEnrollmentService({ ...options, ledger: otherLedger });
  t.after(() => { otherService.close(); otherLedger.close(); });
  const replacement = new Identity('racing-replacement');
  const first = await request();
  const second = await request(replacement, chat, certify(), otherService);
  const outcomes = await Promise.all([service.enroll(first), otherService.enroll(second)]);
  assert.equal(outcomes.filter(Boolean).length, 1);
  const expected = [{ memberId, commitment: (outcomes[0] ? identity : replacement).commitment.toString() }];
  assert.deepEqual(ledger.members(communityId), expected);
  assert.deepEqual(otherLedger.members(communityId), expected);
});
