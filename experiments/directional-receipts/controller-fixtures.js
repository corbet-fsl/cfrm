// Synthetic Node participants, actual pinned verification/proofs/blind RSA.
// Native identity continuity is separately established; no native claim here.
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { verifyProof } from '@semaphore-protocol/proof';
import { createEpoch, createIssuer, preparePermit } from '../anonymous-permits/permits.js';
import { createReleaseReceiptService } from './attestations.js';
import { releaseFixture, nonce } from './attestation-fixtures.js';
import { allocationBytes } from './allocation-fixtures.js';
import { verifyAllocationProof } from './allocation-authorization.js';
import { openAccountingStore } from './controller-store.js';
import { NOW, COMMUNITY, POLICY, json, hash, b64, suite, verifyAdmission } from './fixtures.js';

export { NOW };
export const same = (a, b) => isDeepStrictEqual(a, b);
const rsa = key => ({ kty: key.kty, n: key.n, e: key.e });
const canonical = value => Array.isArray(value) ? value.map(canonical) :
  value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
// Independent reference encoding, never imported from the store under test.
export const configDigest = config => hash(json(['cfrm.controller.origin.v1', canonical(config)]));
export const proofFingerprint = proof => hash(json(canonical(proof)));

let extrasPromise;
async function extras() {
  return extrasPromise ??= (async () => {
    const futureReceipt = await suite.generateKey({ publicExponent: Uint8Array.of(1, 0, 1), modulusLength: 3072 });
    const permit0 = await createEpoch({ scope: COMMUNITY, epoch: 'rule-epoch-1', notBefore: NOW, expiresAt: NOW + 240 });
    const permit1 = await createEpoch({ scope: COMMUNITY, epoch: 'rule-epoch-2', notBefore: NOW + 240, expiresAt: NOW + 480 });
    return { futureReceipt, futurePublic: rsa(await crypto.subtle.exportKey('jwk', futureReceipt.publicKey)),
      permits: [permit0, permit1].map(epoch => ({ public: { ...epoch.public, publicKey: rsa(epoch.public.publicKey) }, privateKey: epoch.privateKey })) };
  })();
}

export async function controllerFixture(t, ruleChanges = {}) {
  const f = await releaseFixture(t); // Only its real Node crypto/enrollment fixtures; never f.open().
  const extra = await extras();
  const receiptA = { ...f.cohort.public, cohortId: 'receipt-origin-1-a', publicKey: rsa(f.cohort.public.publicKey) };
  const receiptB = { ...receiptA, cohortId: 'receipt-origin-1-b', issueUntil: NOW + 240,
    redeemUntil: NOW + 330, publicKey: rsa(await crypto.subtle.exportKey('jwk', f.receiptKeys.publicKey)) };
  const receiptC = { ...receiptA, cohortId: 'receipt-origin-2-a', notBefore: NOW + 240,
    issueUntil: NOW + 480, redeemUntil: NOW + 540, publicKey: extra.futurePublic };
  f.cohort.public = receiptA;
  const rules = { initialAllowance: 3, epochGrant: 2, carryCap: 4,
    maxAuthorizedSend: 4, maxAcknowledgedReceive: 4, ...ruleChanges };
  const configs = [
    { version: 1, communityId: COMMUNITY, policyDigest: POLICY, origin: 'rule-epoch-1', previousOrigin: null,
      notBefore: NOW, endsAt: NOW + 240, graceSeconds: 120, rules: { ...rules },
      receiptCohorts: [receiptA, receiptB], permitContext: extra.permits[0].public },
    { version: 1, communityId: COMMUNITY, policyDigest: POLICY, origin: 'rule-epoch-2', previousOrigin: 'rule-epoch-1',
      notBefore: NOW + 240, endsAt: NOW + 480, graceSeconds: 60, rules: { ...rules },
      receiptCohorts: [receiptC], permitContext: extra.permits[1].public },
  ];
  const receiptKeys = [f.alternateKeys, f.receiptKeys, extra.futureReceipt];
  const contexts = [receiptA, receiptB, receiptC];
  const operationProof = (operation = 'initial', config = configs[0], memberIndex = 0, changes = {}, memberOverride) => {
    const member = memberOverride ?? f.members[memberIndex];
    const authorization = { operation, communityId: config.communityId, policyDigest: config.policyDigest,
      ruleConfigDigest: configDigest(config), origin: config.origin, memberId: member.memberId,
      nonce: nonce(), issuedAt: f.clock(), expiresAt: f.clock() + 30, ...changes };
    return { grant: f.grantFor(member, { policyDigest: config.policyDigest }), authorization: { ...authorization,
      signature: b64(sign(null, allocationBytes(authorization), member.chat.privateKey)) } };
  };
  const verifyFunding = async (proof, config, operation) => {
    const verified = await verifyAllocationProof({ proof,
      expected: { operation, communityId: config.communityId, policyDigest: config.policyDigest,
        ruleConfigDigest: configDigest(config), origin: config.origin, authorizationSeconds: 30 },
      trustedPublicKey: f.admissionTrust.trustedPublicKey, clock: f.clock, verifyAdmission });
    assert.ok(verified && verified.memberId === proof.authorization.memberId,
      'Actual cvld and own-key allocation authorization verify before the store boundary');
  };
  const initialProof = operationProof();
  await verifyFunding(initialProof, configs[0], 'initial');
  const primedAction = await f.action();
  assert.equal(await verifyProof(primedAction.request.semaphoreProof), true);
  t.diagnostic('Controller prerequisites: real allocation proof, 17 enrollments, 16 alternatives, actual Semaphore/RSA preparation');

  const open = (changes = {}, name = 'controller.sqlite') => {
    const store = openAccountingStore(join(f.directory, name), { communityId: COMMUNITY,
      trustedPublicKey: f.admissionTrust.trustedPublicKey, clock: f.clock, verifyAdmission,
      maxCohorts: 4, maxRequestBytes: 32768, authorizationSeconds: 30, ...changes });
    f.disposables.push(store);
    return store;
  };
  const define = (store, config = configs[0]) => {
    assert.ok(same(store.defineOrigin(config), { origin: config.origin, ruleConfigDigest: configDigest(config) }),
      'The store seals the complete public configuration using the independent canonical digest');
  };
  const receiptService = (store, index = 0, changes = {}) => createReleaseReceiptService({
    ledger: store.receiptPort(contexts[index].cohortId),
    cohort: { public: contexts[index], privateKey: receiptKeys[index].privateKey }, attestationKeys: f.attestationKeys,
    checkpointTrust: f.checkpointTrust, admissionTrust: f.admissionTrust, verifyAdmission, clock: f.clock,
    maxAuthorizedSend: rules.maxAuthorizedSend, maxAcknowledgedReceive: rules.maxAcknowledgedReceive,
    maxPending: 2, maxRequestBytes: 32768, authorizationSeconds: 30, ...changes,
  });
  const action = async (index = 0, senderIndex = 0, proverIndex = 1, recipientIndex = proverIndex) => {
    const client = await f.prepare(f.members[recipientIndex], nonce(), { context: contexts[index], signingKeys: receiptKeys[index] });
    const authorization = f.authorization(f.members[senderIndex], client.request, { cohortId: contexts[index].cohortId });
    return f.action(senderIndex, proverIndex, recipientIndex, { client, authorization });
  };
  const redeemRequest = (receipt, index = 0, memberIndex = 1) =>
    f.redemption(receipt, f.members[memberIndex], { cohortId: contexts[index].cohortId });
  const permitIssuer = (store, originIndex = 0) =>
    createIssuer(extra.permits[originIndex], store.permitPort(configs[originIndex].origin), f.clock);
  const permitIssuerWithPort = (port, originIndex = 0) => createIssuer(extra.permits[originIndex], port, f.clock);
  const permitClient = (originIndex = 0) => preparePermit(extra.permits[originIndex].public);
  const state = (store, index = 0, originIndex = 0) => store.snapshot(configs[originIndex].origin, f.members[index].memberId);
  const rotate = index => ({ ...f.members[index], chat: generateKeyPairSync('ed25519') });
  return { ...f, configs, contexts, openStore: open, define, operationProof, verifyFunding, initialProof,
    primedAction, receiptService, controllerAction: action, redeemRequest, permitIssuer, permitIssuerWithPort,
    permitClient, state, rotate };
}
