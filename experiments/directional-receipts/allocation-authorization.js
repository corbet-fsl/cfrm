import { createPublicKey, verify } from 'node:crypto';

const exact = (value, fields) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join(',') === [...fields].sort().join(',');
const positive = value => Number.isSafeInteger(value) && value > 0;
const operation = value => value === 'initial' || value === 'rollover';

function scope(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9._:/-]{1,128}$/.test(value)) {
    throw new TypeError('Invalid allocation scope');
  }
}

function bytes(value, length) {
  if (typeof value !== 'string' || value.length !== Math.ceil(length * 4 / 3) ||
    !/^[A-Za-z0-9_-]+$/.test(value)) throw new TypeError('Invalid canonical bytes');
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.length !== length || decoded.toString('base64url') !== value) {
    throw new TypeError('Invalid canonical bytes');
  }
  return decoded;
}

function interval(value) {
  if (!positive(value.issuedAt) || !positive(value.expiresAt) || value.expiresAt <= value.issuedAt) {
    throw new TypeError('Invalid allocation validity');
  }
}

const current = (value, now) => positive(now) && now >= value.issuedAt && now < value.expiresAt;

function signingBytes(value) {
  return Buffer.from(JSON.stringify(['cfrm.allocation.authorize.v1', value.operation,
    value.communityId, value.policyDigest, value.ruleConfigDigest, value.origin,
    value.memberId, value.nonce, value.issuedAt, value.expiresAt]));
}

/**
 * Experimental stateless ownership check for a controller funding request.
 *
 * The trusted expected context pins both the cvld eligibility policy and the
 * separate immutable numerical-rule configuration. The controller alone owns
 * authorization consumption, request fingerprints, allocations and frontiers.
 *
 * Returns null for rejected input. A valid result is not proof that an allowance
 * was funded or that this nonce remains unused; those require the store's write
 * transaction and another trusted-time check after acquiring its lock.
 */
export async function verifyAllocationProof(options) {
  try {
    if (!exact(options, ['proof', 'expected', 'trustedPublicKey', 'clock', 'verifyAdmission'])) return null;
    const { clock, verifyAdmission } = options;
    if (typeof clock !== 'function' || typeof verifyAdmission !== 'function' ||
      !(options.trustedPublicKey instanceof Uint8Array) || options.trustedPublicKey.length !== 32) return null;

    // Neither caller mutation during an await nor a verifier mutating its own
    // argument copy may replace the claims returned from this snapshot.
    const proof = structuredClone(options.proof);
    const expected = structuredClone(options.expected);
    const pin = Uint8Array.from(options.trustedPublicKey);
    if (!exact(proof, ['grant', 'authorization']) ||
      !exact(expected, ['operation', 'communityId', 'policyDigest', 'ruleConfigDigest', 'origin', 'authorizationSeconds']) ||
      !operation(expected.operation) || !positive(expected.authorizationSeconds) || expected.authorizationSeconds > 300) return null;
    scope(expected.communityId); scope(expected.origin);
    bytes(expected.policyDigest, 32); bytes(expected.ruleConfigDigest, 32);

    const { grant, authorization } = proof;
    if (!exact(grant, ['version', 'issuerKeyId', 'communityId', 'memberId', 'chatPublicKey',
      'policyDigest', 'issuedAt', 'expiresAt', 'signature']) || grant.version !== 1 ||
      !exact(authorization, ['operation', 'communityId', 'policyDigest', 'ruleConfigDigest',
        'origin', 'memberId', 'nonce', 'issuedAt', 'expiresAt', 'signature'])) return null;
    for (const field of ['operation', 'communityId', 'policyDigest', 'ruleConfigDigest', 'origin']) {
      if (authorization[field] !== expected[field]) return null;
    }
    if (grant.communityId !== expected.communityId || grant.policyDigest !== expected.policyDigest ||
      grant.memberId !== authorization.memberId) return null;
    for (const field of ['issuerKeyId', 'memberId', 'chatPublicKey', 'policyDigest']) bytes(grant[field], 32);
    bytes(grant.signature, 64);
    bytes(authorization.memberId, 32); bytes(authorization.nonce, 32);
    const signature = bytes(authorization.signature, 64);
    interval(grant); interval(authorization);
    if (authorization.expiresAt - authorization.issuedAt > expected.authorizationSeconds ||
      authorization.issuedAt < grant.issuedAt || authorization.expiresAt > grant.expiresAt) return null;

    const before = clock();
    if (!current(grant, before) || !current(authorization, before)) return null;
    const chatKey = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: grant.chatPublicKey }, format: 'jwk' });
    if (!verify(null, signingBytes(authorization), chatKey, signature)) return null;
    const admitted = await verifyAdmission({ grant: structuredClone(grant), trustedPublicKey: Uint8Array.from(pin),
      communityId: expected.communityId, policyDigest: expected.policyDigest, now: before });
    if (admitted !== true) return null;
    const now = clock();
    if (!current(grant, now) || !current(authorization, now)) return null;

    return { operation: authorization.operation, communityId: authorization.communityId,
      policyDigest: authorization.policyDigest, ruleConfigDigest: authorization.ruleConfigDigest,
      origin: authorization.origin, memberId: authorization.memberId, nonce: authorization.nonce,
      issuedAt: authorization.issuedAt, expiresAt: authorization.expiresAt, chatPublicKey: grant.chatPublicKey,
      grantIssuedAt: grant.issuedAt, grantExpiresAt: grant.expiresAt };
  } catch { return null; }
}
