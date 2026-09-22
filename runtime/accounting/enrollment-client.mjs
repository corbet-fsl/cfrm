import { checkpointFromVerified } from './hashes.mjs';
import { hex } from './encoding.mjs';
import { fieldBytes } from './primitives.mjs';
import {
  ACCOUNT_HASH_SCHEME, delegationShape, publicEntry, publicationShape,
  publicationSigningBytes, sortPublicationDelegations, sameEntry,
} from './enrollment-publication.mjs';

const integer = value => Number.isSafeInteger(value) && value > 0;
const clone = value => structuredClone(value);
const digestBytes = value => {
  if (value instanceof Uint8Array && value.length === 32) return value.slice();
  if (Array.isArray(value) && value.length === 32 && value.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) {
    return Uint8Array.from(value);
  }
  throw new TypeError('Invalid delegation digest');
};
const entryFrom = (delegation, digest) => publicEntry({
  memberId: delegation.admission.memberId,
  accountKey: delegation.accountPublicKey,
  secretHash: delegation.stateSecretCommitment,
  issuedAt: delegation.issuedAt,
  expiresAt: delegation.expiresAt,
  delegationDigest: hex(digest),
});
const equal = (left, right) => JSON.stringify(left) === JSON.stringify(right);

/**
 * Browser-side acquisition for a common cfrm enrollment. The supplied
 * verifyPublication callback must verify the Ed25519 operator signature over
 * publicationSigningBytes; verifyDelegation must be the actual generated cmsg
 * verifier and return its 32-byte digest. Neither callback may return a bool
 * for delegation verification.
 */
export function createEnrollmentClient(options = {}) {
  const { communityId, policyDigest, community, hashes, clock, transport,
    verifyDelegation, verifyPublication, checkpointPeriodSeconds } = options;
  if (typeof communityId !== 'string' || typeof policyDigest !== 'string'
      || !(community instanceof Uint8Array) || community.length !== 32
      || !hashes || typeof hashes.enrollment !== 'function' || typeof hashes.enrollmentNode !== 'function'
      || typeof clock !== 'function' || typeof transport !== 'function'
      || typeof verifyDelegation !== 'function' || typeof verifyPublication !== 'function'
      || !Number.isSafeInteger(checkpointPeriodSeconds) || checkpointPeriodSeconds <= 0) {
    throw new TypeError('Explicit enrollment client configuration is required');
  }
  let lastClock = 0;
  function now() {
    const value = clock();
    if (!integer(value) || value < lastClock) throw new Error('Enrollment clock is invalid');
    lastClock = value;
    return value;
  }
  async function prepare(input, at = now()) {
    const delegation = delegationShape(input);
    if (delegation.admission.communityId !== communityId || delegation.admission.policyDigest !== policyDigest
        || delegation.expiresAt <= at || delegation.issuedAt > at || delegation.hashScheme !== ACCOUNT_HASH_SCHEME) {
      throw new Error('Enrollment delegation rejected');
    }
    let digest;
    try { digest = digestBytes(await verifyDelegation({ delegation: clone(delegation), communityId, policyDigest, now: at })); }
    catch { throw new Error('Enrollment delegation rejected'); }
    return { delegation: clone(delegation), digest, entry: entryFrom(delegation, digest) };
  }
  function checkWindow(publication, at) {
    const slotStart = publication.slot * checkpointPeriodSeconds;
    const slotEnd = (publication.slot + 1) * checkpointPeriodSeconds;
    if (!Number.isSafeInteger(slotStart) || publication.notBefore !== slotStart
        || publication.expiresAt !== slotEnd || at < publication.notBefore || at >= publication.expiresAt) {
      throw new Error('Enrollment publication is stale');
    }
  }
  async function verifyAndBuild(publicationInput, prepared, at) {
    const publication = publicationShape(publicationInput);
    if (publication.communityId !== communityId || publication.policyDigest !== policyDigest) throw new Error('Enrollment publication rejected');
    checkWindow(publication, at);
    let callbackResult;
    try { callbackResult = await verifyPublication(clone(publication), { communityId, policyDigest, bytes: publicationSigningBytes(publication) }); }
    catch { throw new Error('Enrollment publication rejected'); }
    const wrappers = [];
    for (const wrapper of publication.delegations) {
      let delegation, digest;
      try {
        delegation = delegationShape(wrapper.delegation);
        if (delegation.admission.communityId !== communityId || delegation.admission.policyDigest !== policyDigest
            || delegation.expiresAt < publication.expiresAt) throw new Error('scope');
        digest = digestBytes(await verifyDelegation({ delegation: clone(delegation), communityId, policyDigest, now: at }));
      } catch { throw new Error('Enrollment publication rejected'); }
      const entry = entryFrom(delegation, digest);
      if (!sameEntry(entry, wrapper.entry)) throw new Error('Enrollment publication rejected');
      wrappers.push({ delegation, entry });
    }
    const sorted = sortPublicationDelegations(wrappers);
    if (!equal(sorted, publication.delegations)) throw new Error('Enrollment publication rejected');
    if (callbackResult !== true && Array.isArray(callbackResult)) {
      if (callbackResult.length !== sorted.length || callbackResult.some((entry, index) => !sameEntry(entry, sorted[index].entry))) {
        throw new Error('Enrollment publication rejected');
      }
    } else if (callbackResult !== true) throw new Error('Enrollment publication rejected');
    const checkpoint = await checkpointFromVerified(community, sorted.map(value => value.entry), hashes);
    if (!equal(Array.from(fieldBytes(checkpoint.root)), publication.root)) {
      throw new Error('Enrollment publication rejected');
    }
    if (prepared) {
      const own = sorted.find(value => value.entry.memberId === prepared.entry.memberId);
      if (!own) {
        // The current slot may already be frozen. The server's signed
        // publication is still valid evidence of the prior roster; absence of
        // this member means eligibility begins at the next configured slot.
        return Object.freeze({
          status: 'pending', eligibleAt: publication.expiresAt,
          publication: clone(publication), checkpoint,
          entries: sorted.map(value => clone(value.entry)),
        });
      }
      if (own.entry.memberId !== prepared.entry.memberId
          || own.entry.accountKey !== prepared.entry.accountKey
          || own.entry.secretHash !== prepared.entry.secretHash) {
        throw new Error('Enrollment publication rejected');
      }
    }
    return Object.freeze({ status: 'eligible', publication: clone(publication), checkpoint, entries: sorted.map(value => clone(value.entry)) });
  }
  return Object.freeze({
    async prepare(input) { return prepare(input); },
    async acquire(delegationInput) {
      const prepared = await prepare(delegationInput);
      let response;
      try { response = await transport({ action: 'enroll', delegation: clone(prepared.delegation) }); }
      catch { throw new Error('Enrollment unavailable'); }
      if (!response || response.action !== 'enroll' || !response.publication) throw new Error('Enrollment unavailable');
      return verifyAndBuild(response.publication, prepared, now());
    },
    async current() {
      let response;
      try { response = await transport({ action: 'current' }); }
      catch { throw new Error('Enrollment unavailable'); }
      if (!response || response.action !== 'current' || !response.publication) return null;
      return verifyAndBuild(response.publication, undefined, now());
    },
  });
}
