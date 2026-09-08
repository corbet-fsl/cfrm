// Synthetic grants and participants, actual cvld verification and maintained
// Ed25519. No provider, RSA, Semaphore or controller state is simulated here.
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { pathToFileURL } from 'node:url';

if (!process.env.CVLD_ADMISSION_MODULE) throw new Error('Pinned real cvld admission module is required');
const { admissionBytes, verifyAdmission } = await import(pathToFileURL(process.env.CVLD_ADMISSION_MODULE).href);

export const NOW = 1_800_000_000;
export const b64 = value => Buffer.from(value).toString('base64url');
export const raw = key => Buffer.from(key.export({ format: 'jwk' }).x, 'base64url');
export const hash = value => createHash('sha256').update(value).digest('base64url');
export const keys = () => generateKeyPairSync('ed25519');
export const nonce = () => b64(randomBytes(32));

// Independent wire construction; never import the verifier under test.
export function allocationBytes(value, domain = 'cfrm.allocation.authorize.v1') {
  return Buffer.from(JSON.stringify([domain, value.operation, value.communityId,
    value.policyDigest, value.ruleConfigDigest, value.origin, value.memberId,
    value.nonce, value.issuedAt, value.expiresAt]));
}

export function allocationFixture() {
  const issuer = keys();
  const member = { memberId: nonce(), chat: keys() };
  let now = NOW;
  const expected = { operation: 'initial', communityId: 'community.example',
    policyDigest: hash('synthetic-eligibility-policy'),
    ruleConfigDigest: hash('synthetic-immutable-rule-config'), origin: 'rule-epoch-1',
    authorizationSeconds: 90 };
  function grant(changes = {}, signingKey = issuer.privateKey) {
    const value = { version: 1, issuerKeyId: hash(raw(issuer.publicKey)),
      communityId: expected.communityId, policyDigest: expected.policyDigest,
      memberId: member.memberId, chatPublicKey: b64(raw(member.chat.publicKey)),
      issuedAt: NOW, expiresAt: NOW + 600, ...changes };
    return { ...value, signature: b64(sign(null, admissionBytes(value), signingKey)) };
  }
  function authorization(changes = {}, signingKey = member.chat.privateKey, domain) {
    const value = { operation: expected.operation, communityId: expected.communityId,
      policyDigest: expected.policyDigest, ruleConfigDigest: expected.ruleConfigDigest,
      origin: expected.origin, memberId: member.memberId, nonce: nonce(),
      issuedAt: NOW, expiresAt: NOW + 60, ...changes };
    return { ...value, signature: b64(sign(null, allocationBytes(value, domain), signingKey)) };
  }
  const proof = () => ({ grant: grant(), authorization: authorization() });
  const options = (candidate = proof(), changes = {}) => ({
    proof: candidate, expected: structuredClone(expected), trustedPublicKey: Uint8Array.from(raw(issuer.publicKey)),
    clock: () => now, verifyAdmission, ...changes,
  });
  return { issuer, member, expected, grant, authorization, proof, options,
    advance(value) { now = value; } };
}

export function verifiedClaims(proof) {
  const { authorization: a, grant: g } = proof;
  return { operation: a.operation, communityId: a.communityId, policyDigest: a.policyDigest,
    ruleConfigDigest: a.ruleConfigDigest, origin: a.origin, memberId: a.memberId,
    nonce: a.nonce, issuedAt: a.issuedAt, expiresAt: a.expiresAt,
    chatPublicKey: g.chatPublicKey, grantIssuedAt: g.issuedAt, grantExpiresAt: g.expiresAt };
}
