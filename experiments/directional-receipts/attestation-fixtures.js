// Independent reference encoding and synthetic participants; actual crypto.
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, verify } from 'node:crypto';
import { join } from 'node:path';
import { openDirectionalLedger } from './receipts.js';
import { createReleaseReceiptService } from './attestations.js';
import { fixture, COMMUNITY, json, hash, b64, raw, suite, verifyAdmission } from './fixtures.js';

export const keys = () => generateKeyPairSync('ed25519');
export const nonce = () => b64(randomBytes(32));
export function releaseDomain(context) {
  return hash(json(['cfrm.directional.release-receipt.v1', context.communityId, context.policyDigest,
    context.cohortId, context.notBefore, context.issueUntil, context.redeemUntil,
    context.publicKey.kty, context.publicKey.n, context.publicKey.e]));
}
export function commonContext(cohort) {
  return { communityId: cohort.communityId, policyDigest: cohort.policyDigest,
    cohortId: cohort.cohortId, notBefore: cohort.notBefore, expiresAt: cohort.redeemUntil };
}
export function commitBytes(value) {
  return json(['cfrm.directional.commit.v1', value.context.communityId, value.context.policyDigest,
    value.context.cohortId, value.sender.memberId, value.sender.chatPublicKey,
    value.authorizationNonce, value.blindedRequestHash, value.context.notBefore, value.context.expiresAt]);
}
export function redemptionBytes(value) {
  return json(['cfrm.directional.redemption.v1', value.context.communityId, value.context.policyDigest,
    value.context.cohortId, value.recipient.memberId, value.recipient.chatPublicKey,
    value.releaseNonce, value.context.notBefore, value.context.expiresAt]);
}
export const counters = (authorizedSend = 0, acknowledgedReceive = 0) => ({ authorizedSend, acknowledgedReceive });

export async function releaseFixture(t) {
  const f = await fixture(t);
  const rawPublic = structuredClone(f.cohort.public);
  const rawPrivate = f.cohort.privateKey;
  const prepareRaw = f.prepare;
  const senderKey = keys();
  const receiverKey = keys();
  f.attestationKeys = {
    senderCommit: { publicKey: raw(senderKey.publicKey), privateKey: senderKey.privateKey },
    recipientRedemption: { publicKey: raw(receiverKey.publicKey), privateKey: receiverKey.privateKey },
  };
  f.senderAttestationKey = senderKey.publicKey;
  f.recipientAttestationKey = receiverKey.publicKey;
  f.rawCohort = { public: rawPublic, privateKey: rawPrivate };
  f.prepareRaw = recipient => prepareRaw(recipient, rawPublic, f.receiptKeys);
  // The baseline's other RSA key is independently generated and was never
  // registered for the raw receipt purpose in this fixture's fresh database.
  f.cohort.public = { ...rawPublic, version: 2, purpose: 'release-acknowledged-receive',
    cohortId: 'release-cohort-1', publicKey: await crypto.subtle.exportKey('jwk', f.alternateKeys.publicKey) };
  f.cohort.privateKey = f.alternateKeys.privateKey;
  f.prepare = async (recipient = f.members[1], releaseNonce = nonce(), changes = {}) => {
    const context = changes.context ?? f.cohort.public;
    const signingKeys = changes.signingKeys ?? f.alternateKeys;
    const prepared = suite.prepare(Uint8Array.from(Buffer.concat([
      Buffer.from(releaseDomain(context), 'base64url'), Buffer.from(recipient.memberId, 'base64url'),
      randomBytes(32), Buffer.from(releaseNonce, 'base64url'),
    ])));
    assert.equal(prepared.length, 160);
    const { blindedMsg, inv } = await suite.blind(signingKeys.publicKey, prepared);
    return { releaseNonce, request: { blinded: b64(blindedMsg) },
      finish: async response => ({ message: b64(prepared),
        signature: b64(await suite.finalize(signingKeys.publicKey, prepared,
          Uint8Array.from(Buffer.from(response.blindSignature, 'base64url')), inv)) }) };
  };
  f.open = (changes = {}) => {
    const path = join(f.directory, 'release.sqlite');
    const ledger = openDirectionalLedger(path);
    f.disposables.push(ledger);
    const options = { ledger, cohort: f.cohort, attestationKeys: f.attestationKeys,
      checkpointTrust: f.checkpointTrust, admissionTrust: f.admissionTrust, verifyAdmission,
      clock: f.clock, maxAuthorizedSend: 16, maxAcknowledgedReceive: 64,
      maxPending: 2, maxRequestBytes: 32768, authorizationSeconds: 30, ...changes };
    return { ledger, path, options, service: createReleaseReceiptService(options),
      count: index => ledger.counters(COMMUNITY, f.cohort.public.cohortId, f.members[index].memberId) };
  };
  f.checkCommit = (output, action) => {
    assert.deepEqual(Object.keys(output).sort(), ['blindSignature', 'senderCommit']);
    const { signature, ...statement } = output.senderCommit;
    assert.deepEqual(statement, { context: commonContext(f.cohort.public),
      sender: { memberId: action.request.senderAdmission.memberId, chatPublicKey: action.request.senderAdmission.chatPublicKey },
      authorizationNonce: action.request.senderAuthorization.nonce,
      blindedRequestHash: action.request.senderAuthorization.requestHash });
    assert.equal(verify(null, commitBytes(output.senderCommit), f.senderAttestationKey,
      Buffer.from(signature, 'base64url')), true);
    assert.equal(verify(null, commitBytes(output.senderCommit), f.recipientAttestationKey,
      Buffer.from(signature, 'base64url')), false);
  };
  f.checkRedemption = (output, action, member = f.members[1]) => {
    assert.ok(output);
    assert.deepEqual(Object.keys(output), ['recipientRedemption']);
    const { signature, ...statement } = output.recipientRedemption;
    assert.deepEqual(statement, { context: commonContext(f.cohort.public),
      recipient: { memberId: member.memberId, chatPublicKey: b64(raw(member.chat.publicKey)) },
      releaseNonce: action.client.releaseNonce });
    assert.equal(verify(null, redemptionBytes(output.recipientRedemption), f.recipientAttestationKey,
      Buffer.from(signature, 'base64url')), true);
    assert.equal(verify(null, redemptionBytes(output.recipientRedemption), f.senderAttestationKey,
      Buffer.from(signature, 'base64url')), false);
  };
  return f;
}

export async function issued(f, service, action) {
  const output = await service.authorizeAndAcknowledge(action.request);
  f.checkCommit(output, action);
  return { output, receipt: await action.client.finish(output) };
}
export async function rejected(service, request) {
  await assert.rejects(service.authorizeAndAcknowledge(request));
}
