// Synthetic test participants, real maintained cryptographic implementations.
// Independent wire construction deliberately does not import the service under test.
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { Group } from '@semaphore-protocol/group';
import { Identity } from '@semaphore-protocol/identity';
import { generateProof } from '@semaphore-protocol/proof';
import { getCurveFromName } from 'ffjavascript';
import { createEnrollmentService, enrollmentBytes, enrollmentMessage,
  openEnrollmentLedger } from '../private-reciprocity/enrollment.js';
import { createCheckpointPublisher, registeredAcknowledgementContext } from '../private-reciprocity/checkpoints.js';

if (!process.env.CVLD_ADMISSION_MODULE) throw new Error('Pinned real cvld admission module is required');
export const { verifyAdmission, admissionBytes } = await import(pathToFileURL(process.env.CVLD_ADMISSION_MODULE).href);
export const NOW = 1_800_000_000;
export const COMMUNITY = 'community.example';
export const POLICY = hash(Buffer.from('directional-experiment-policy'));
export const suite = RSABSSA.SHA384.PSS.Randomized();
export const json = value => Buffer.from(JSON.stringify(value));
export const b64 = value => Buffer.from(value).toString('base64url');
export function hash(bytes) { return createHash('sha256').update(bytes).digest('base64url'); }
export const scalarHash = value => BigInt('0x' + createHash('sha256').update(json(value)).digest('hex')).toString();
export const raw = key => Buffer.from(key.export({ format: 'jwk' }).x, 'base64url');
const keys = () => generateKeyPairSync('ed25519');
const artifacts = { wasm: new URL('../private-reciprocity/.artifacts/semaphore.wasm', import.meta.url).pathname,
  zkey: new URL('../private-reciprocity/.artifacts/semaphore.zkey', import.meta.url).pathname };
let commonPromise;
let curve;
export async function terminateCrypto() { if (curve) await curve.terminate(); }

export function receiptDomain(context) {
  return hash(json(['cfrm.directional.receipt.v1', context.communityId, context.policyDigest,
    context.cohortId, context.notBefore, context.issueUntil, context.redeemUntil,
    context.publicKey.kty, context.publicKey.n, context.publicKey.e]));
}
export function senderBytes(value) {
  return json(['cfrm.directional.authorize.v1', value.communityId, value.policyDigest,
    value.cohortId, value.senderId, value.requestHash, value.nonce, value.issuedAt, value.expiresAt]);
}
export function receiveBytes(value) {
  return json(['cfrm.directional.redeem.v1', value.communityId, value.policyDigest,
    value.cohortId, value.memberId, value.receiptHash, value.nonce, value.issuedAt, value.expiresAt]);
}
export function proofMessage(checkpoint, authorization) {
  return scalarHash(['cfrm.directional.ack.v1', checkpoint.digest,
    b64(senderBytes(authorization)), authorization.signature, authorization.requestHash]);
}

async function common() {
  return commonPromise ??= (async () => {
    const manifest = JSON.parse(readFileSync(new URL('../private-reciprocity/artifacts.json', import.meta.url)));
    for (const [kind, entry] of Object.entries(manifest.files)) {
      const content = readFileSync(artifacts[kind]);
      assert.equal(content.length, entry.bytes);
      assert.equal(createHash('sha256').update(content).digest('hex'), entry.sha256);
    }
    curve = await getCurveFromName('bn128');
    const receiptKeys = await suite.generateKey({ publicExponent: Uint8Array.of(1, 0, 1), modulusLength: 3072 });
    const alternateKeys = await suite.generateKey({ publicExponent: Uint8Array.of(1, 0, 1), modulusLength: 3072 });
    const issuer = keys();
    const publisherKey = keys();
    const members = Array.from({ length: 17 }, (_, index) => ({ memberId: hash(Buffer.from(`directional-member-${index}`)),
      identity: new Identity(`synthetic-directional-member-${index}`), chat: keys() }));
    const publicContext = { version: 1, purpose: 'acknowledged-receive', communityId: COMMUNITY,
      policyDigest: POLICY, cohortId: 'cohort-1', notBefore: NOW, issueUntil: NOW + 120,
      redeemUntil: NOW + 300, publicKey: await crypto.subtle.exportKey('jwk', receiptKeys.publicKey) };
    return { issuer, publisherKey, members, receiptKeys, alternateKeys, publicContext };
  })();
}

export async function fixture(t) {
  const shared = await common();
  const directory = mkdtempSync(join(tmpdir(), 'cfrm-directional-'));
  const disposables = [];
  let now = NOW;
  const clock = () => now;
  const enrollmentLedger = openEnrollmentLedger(join(directory, 'enrollment.sqlite'));
  const admissionTrust = { trustedPublicKey: raw(shared.issuer.publicKey), communityId: COMMUNITY, policyDigest: POLICY };
  const enrollment = createEnrollmentService({ ...admissionTrust, verifyAdmission, ledger: enrollmentLedger,
    clock, challengeSeconds: 5 });
  const publisher = createCheckpointPublisher({ ledger: enrollmentLedger, communityId: COMMUNITY,
    policyDigest: POLICY, signingKey: shared.publisherKey.privateKey, clock, epochSeconds: 60,
    minAnonymity: 16, depth: 7, maxRetainedLinks: 32 });
  const checkpointTrust = { trustedPublicKey: raw(shared.publisherKey.publicKey), communityId: COMMUNITY,
    policyDigest: POLICY, clock };
  t.after(() => {
    for (const disposable of disposables.reverse()) disposable.close();
    publisher.close(); enrollment.close(); enrollmentLedger.close();
    rmSync(directory, { recursive: true, force: true });
  });
  function grantFor(member, changes = {}) {
    const grant = { version: 1, issuerKeyId: hash(raw(shared.issuer.publicKey)), communityId: COMMUNITY,
      memberId: member.memberId, chatPublicKey: b64(raw(member.chat.publicKey)), policyDigest: POLICY,
      issuedAt: NOW, expiresAt: NOW + 600, ...changes };
    return { ...grant, signature: b64(sign(null, admissionBytes(grant), shared.issuer.privateKey)) };
  }
  for (const member of shared.members) {
    const grant = grantFor(member);
    const envelope = await enrollment.begin(grant, member.identity.commitment.toString());
    const semaphoreSignature = member.identity.signMessage(enrollmentMessage(envelope.challenge));
    assert.equal(await enrollment.enroll({ grant, ...envelope, publicKey: member.identity.publicKey.map(String),
      semaphoreSignature: { R8: semaphoreSignature.R8.map(String), S: String(semaphoreSignature.S) },
      chatSignature: b64(sign(null, enrollmentBytes(envelope.challenge), member.chat.privateKey)) }), true);
  }
  const cohort = { public: structuredClone(shared.publicContext), privateKey: shared.receiptKeys.privateKey };
  const f = { ...shared, directory, disposables, clock, grantFor, enrollmentLedger, publisher,
    checkpointTrust, admissionTrust, cohort, advance: value => { now = value; } };
  f.prepare = async (recipient = shared.members[1], context = cohort.public, signingKeys = shared.receiptKeys) => {
    // Serial and RSA unblinding state stay client-side. A client recovery adapter must encrypt them.
    const prepared = suite.prepare(Uint8Array.from(Buffer.concat([
      Buffer.from(receiptDomain(context), 'base64url'), Buffer.from(recipient.memberId, 'base64url'), randomBytes(32),
    ])));
    const { blindedMsg, inv } = await suite.blind(signingKeys.publicKey, prepared);
    return { request: { blinded: b64(blindedMsg) },
      finish: async response => ({ message: b64(prepared),
        signature: b64(await suite.finalize(signingKeys.publicKey, prepared,
          Uint8Array.from(Buffer.from(response.blindSignature, 'base64url')), inv)) }) };
  };
  f.authorization = (sender, request, changes = {}) => {
    const authorization = { version: 1, purpose: 'authorized-send', communityId: COMMUNITY, policyDigest: POLICY,
      cohortId: cohort.public.cohortId, senderId: sender.memberId,
      requestHash: hash(Buffer.from(request.blinded, 'base64url')), nonce: b64(randomBytes(32)),
      issuedAt: now, expiresAt: now + 30, ...changes };
    return { ...authorization, signature: b64(sign(null, senderBytes(authorization), sender.chat.privateKey)) };
  };
  f.action = async (senderIndex = 0, proverIndex = 1, recipientIndex = proverIndex, options = {}) => {
    const sender = shared.members[senderIndex];
    const prover = shared.members[proverIndex];
    const client = options.client ?? await f.prepare(shared.members[recipientIndex]);
    const authorization = options.authorization ?? f.authorization(sender, client.request);
    const checkpoint = options.checkpoint ?? publisher.publish();
    const senderBinding = publisher.binding(sender.memberId);
    const context = registeredAcknowledgementContext(checkpoint, senderBinding, checkpointTrust);
    const group = new Group(checkpoint.commitments.filter(value => value !== senderBinding.commitment).map(BigInt));
    if (group.indexOf(prover.identity.commitment) < 0) throw new Error('Prover is excluded');
    const semaphoreProof = await generateProof(prover.identity, group,
      proofMessage(checkpoint, authorization), context.scope, context.depth, artifacts);
    return { client, request: { senderAuthorization: authorization, senderAdmission: grantFor(sender),
      checkpoint, senderBinding, blindedReceiptRequest: client.request, semaphoreProof } };
  };
  f.redemption = (receipt, member = shared.members[1], changes = {}) => {
    const authorization = { version: 1, purpose: 'acknowledged-receive', communityId: COMMUNITY,
      policyDigest: POLICY, cohortId: cohort.public.cohortId, memberId: member.memberId,
      receiptHash: hash(json([receipt.message, receipt.signature])), nonce: b64(randomBytes(32)),
      issuedAt: now, expiresAt: now + 30, ...changes };
    return { receipt, admission: grantFor(member), authorization: { ...authorization,
      signature: b64(sign(null, receiveBytes(authorization), member.chat.privateKey)) } };
  };
  return f;
}
