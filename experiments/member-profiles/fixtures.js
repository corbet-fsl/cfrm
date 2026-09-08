// Synthetic local holders/providers. None of this fixture is operator code.
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { createProfileOwner, createProfileReader } from './protocol.js';

if (!process.env.CVLD_ROOT) throw new Error('Set CVLD_ROOT to the tested public cvld checkout; no implicit package download');
const root = resolve(process.env.CVLD_ROOT);
const cvld = await import(pathToFileURL(resolve(root, 'src/index.js')));
const client = await import(pathToFileURL(resolve(root, 'src/client.js')));
const require = createRequire(resolve(root, 'package.json'));
const { Presentation, anoncredsNodeJS } = require('@hyperledger/anoncreds-nodejs');

export const NOW = 1_800_000_000;
export const COMMUNITY = 'community.example';
export const ENDPOINT = { host: 'pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion', port: 443 };
export const textBytes = text => new TextEncoder().encode(text);
export const frame = object => textBytes(JSON.stringify(object));
export const decode = bytes => JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
export const digest = bytes => createHash('sha256').update(bytes).digest('base64url');
export const randomId = () => randomBytes(32).toString('base64url');
export function challengeBytes(value) {
  return frame(['cfrm.profile.v1', 'challenge', value.communityId, value.ownerMemberId,
    value.ownerChatPublicKey, value.onionHost, value.onionPort, value.sessionId,
    value.readerNonce, value.ownerNonce, value.policyDigest, value.issuedAt, value.expiresAt]);
}
export function responseBytes(challenge, profileDigest) {
  return frame(['cfrm.profile.v1', 'response', digest(challengeBytes(challenge)), profileDigest]);
}
export function referenceRequest(issuer, challenge) {
  const bytes = createHash('sha256').update(challengeBytes(challenge)).digest('hex');
  const restrictions = [{ cred_def_id: issuer.credentialDefinitionId }];
  return {
    name: 'cfrm-profile-read', version: '1', nonce: BigInt(`0x${bytes}`).toString(10),
    requested_attributes: Object.fromEntries(['community_id', 'policy'].map(name => [name, { name, restrictions }])),
    requested_predicates: {
      eligible: { name: 'eligible', p_type: '>=', p_value: 1, restrictions },
      valid_until: { name: 'valid_until', p_type: '>=', p_value: challenge.expiresAt, restrictions },
    },
  };
}
let shared;
export async function credentialFixture() {
  if (!shared) shared = (async () => {
    const gate = generateKeyPairSync('ed25519');
    const policy = { version: 'profiles', mode: 'any', factors: ['phone'] };
    const issuer = cvld.createIssuer({ issuerId: 'https://issuer.example/profiles', communityId: COMMUNITY,
      policy, clock: () => NOW, maxCredentialLifetimeSeconds: 1000,
      receiptStore: cvld.createMemoryReceiptStore({ maxEntries: 100 }),
      attesters: { synthetic: { factor: 'phone', publicKey: gate.publicKey.export({ format: 'pem', type: 'spki' }) } } });
    const holder = cvld.createHolder();
    const memberId = randomId();
    const offer = issuer.offer();
    const pending = holder.request(issuer.public, offer, memberId);
    const receiptId = randomId();
    const attestation = { keyId: 'synthetic', factor: 'phone', receiptId,
      issuanceDigest: cvld.issuanceDigest(offer, pending.request), policyDigest: cvld.policyDigest(policy), validUntil: NOW + 900 };
    attestation.signature = sign(null, cvld.encodeAttestation(attestation), gate.privateKey).toString('base64url');
    pending.accept(await issuer.issue({ offer, request: pending.request, attestations: [attestation] }));
    // Export/decrypt exclusively within the synthetic holder's process. This
    // fixture accesses local private state to test a future cvld proof API.
    const wrappingKey = randomBytes(32);
    const encryptedState = await holder.exportState({ wrappingKey });
    const local = JSON.parse(new TextDecoder().decode(await client.openLocalState({
      envelope: encryptedState, key: wrappingKey, context: 'cvld.holder.v1',
    })));
    function prove(request) {
      const proof = Presentation.create({ presentationRequest: request,
        credentials: [{ credential: local.credential }],
        credentialsProve: [
          ...['community_id', 'policy'].map(referent => ({ entryIndex: 0, isPredicate: false, referent, reveal: true })),
          ...['eligible', 'valid_until'].map(referent => ({ entryIndex: 0, isPredicate: true, referent, reveal: true })),
        ], schemas: { [issuer.public.schemaId]: issuer.public.schema },
        credentialDefinitions: { [issuer.public.credentialDefinitionId]: issuer.public.credentialDefinition },
        selfAttest: {}, linkSecret: local.linkSecret });
      try { return proof.toJson(); } finally { proof.handle.clear(); }
    }
    function verify(request, json) {
      try {
        const proof = Presentation.fromJson(json);
        try { return proof.verify({ presentationRequest: request,
          schemas: { [issuer.public.schemaId]: issuer.public.schema },
          credentialDefinitions: { [issuer.public.credentialDefinitionId]: issuer.public.credentialDefinition } });
        } finally { proof.handle.clear(); }
      } catch { return false; }
    }
    return { issuer: issuer.public, policyDigest: cvld.policyDigest(policy), memberId, receiptId,
      secret: local.linkSecret, exactExpiry: String(attestation.validUntil), prove, verify, anoncredsNodeJS };
  })();
  return shared;
}
export async function protocolFixture(overrides = {}) {
  const credential = await credentialFixture();
  const signing = generateKeyPairSync('ed25519');
  const issuerSigning = generateKeyPairSync('ed25519');
  const publicKey = Buffer.from(issuerSigning.publicKey.export({ format: 'jwk' }).x, 'base64url');
  const grant = { version: 1, issuerKeyId: cvld.admissionKeyId(publicKey), communityId: COMMUNITY,
    memberId: randomId(), chatPublicKey: signing.publicKey.export({ format: 'jwk' }).x,
    policyDigest: credential.policyDigest, issuedAt: NOW, expiresAt: NOW + 300 };
  grant.signature = sign(null, cvld.admissionBytes(grant), issuerSigning.privateKey).toString('base64url');
  let now = NOW;
  let proveCalls = 0;
  const wire = [];
  const destinations = [];
  const limits = { maxProfileBytes: 4096, maxFrameBytes: 100000, maxProofBytes: 80000,
    maxChallengeSeconds: 30, maxReplayEntries: 100, maxConcurrentProofs: 2, ...overrides.limits };
  const trust = { communityId: COMMUNITY, policyDigest: credential.policyDigest,
    publicIssuer: credential.issuer, trustedPublicKey: publicKey, verifyAdmission: cvld.verifyAdmission };
  const identity = { grant,
    signProfileChallenge: value => sign(null, challengeBytes(value), signing.privateKey).toString('base64url'),
    signProfileResponse: (value, profileDigest) => sign(null, responseBytes(value, profileDigest), signing.privateKey).toString('base64url') };
  const owner = createProfileOwner({ ...trust, identity, clock: () => now, limits,
    verifyEligibilityProof: async (request, proof) => credential.verify(request, proof), ...overrides.owner });
  owner.setText(limits.maxProfileBytes < 64 ? 'Hello' : 'A quiet place to discuss shared interests.');
  owner.activate({ endpoint: ENDPOINT, leaseExpiresAt: NOW + 120 });
  // In-memory transport double: validates routing intent, not Tor anonymity.
  const onionTransport = { async open(endpoint) {
    destinations.push(structuredClone(endpoint));
    if (JSON.stringify(endpoint) !== JSON.stringify(ENDPOINT)) throw new Error('Onion destination unavailable');
    return { async exchange(bytes) {
      wire.push({ direction: 'reader-to-owner', bytes: new Uint8Array(bytes) });
      const result = await owner.handle(bytes);
      wire.push({ direction: 'owner-to-reader', bytes: new Uint8Array(result) });
      return result;
    }, close() {} };
  } };
  const reader = createProfileReader({ ...trust, clock: () => now, limits,
    expectedOwner: { memberId: grant.memberId, endpoint: ENDPOINT }, onionTransport,
    proveEligibility: async request => { proveCalls++; return credential.prove(request); }, ...overrides.reader });
  return { owner, reader, grant, identity, signing, credential, limits, trust, wire, destinations, onionTransport,
    setNow(value) { now = value; }, proveCalls: () => proveCalls };
}
