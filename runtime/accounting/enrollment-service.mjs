import { sign } from 'node:crypto';
import { checkpointFromVerified } from './hashes.mjs';
import { fieldBytes } from './primitives.mjs';
import { hex } from './encoding.mjs';
import {
  ENROLLMENT_DOMAIN, publicationSigningBytes, publicationShape,
  sortPublicationDelegations,
} from './enrollment-publication.mjs';

export const ACCOUNT_HASH_SCHEME = 'poseidon2-bn254-fixed-128-v1';
const DELEGATION_KEYS = ['version', 'hashScheme', 'admission', 'authorization',
  'accountPublicKey', 'stateSecretCommitment', 'issuedAt', 'expiresAt', 'signature'];
const PUBLIC_ENTRY_KEYS = ['memberId', 'accountKey', 'secretHash', 'issuedAt', 'expiresAt', 'delegationDigest'];
const memberIdPattern = /^[A-Za-z0-9_-]{43}$/;
const hex32 = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const hex64 = value => typeof value === 'string' && /^[0-9a-f]{128}$/.test(value);
const integer = value => Number.isSafeInteger(value) && value > 0;
const clone = value => structuredClone(value);
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const bytes32 = value => {
  if (!(value instanceof Uint8Array) || value.length !== 32) throw new TypeError('32-byte value required');
  return value;
};
const digestBytes = value => {
  if (value instanceof Uint8Array && value.length === 32) return value.slice();
  if (Array.isArray(value) && value.length === 32 && value.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) {
    return Uint8Array.from(value);
  }
  throw new TypeError('Invalid delegation digest');
};

export function publicEntry(value) {
  if (!exact(value, PUBLIC_ENTRY_KEYS) || !memberIdPattern.test(value.memberId)
      || !hex64(value.accountKey) || !hex32(value.secretHash) || !hex32(value.delegationDigest)
      || !integer(value.issuedAt) || !integer(value.expiresAt) || value.expiresAt <= value.issuedAt) {
    throw new TypeError('Invalid verified enrollment');
  }
  return clone(value);
}

export function delegationShape(value) {
  if (!exact(value, DELEGATION_KEYS) || value.version !== 1
      || value.hashScheme !== ACCOUNT_HASH_SCHEME || !value.admission || !value.authorization
      || typeof value.admission.communityId !== 'string' || typeof value.admission.memberId !== 'string'
      || typeof value.admission.policyDigest !== 'string' || !memberIdPattern.test(value.admission.memberId)
      || !hex64(value.accountPublicKey) || !hex32(value.stateSecretCommitment)
      || !integer(value.issuedAt) || !integer(value.expiresAt) || value.expiresAt <= value.issuedAt
      || typeof value.signature !== 'string') throw new TypeError('Invalid accounting delegation');
  return clone(value);
}

function normalize({ delegation: input, digest, communityId, policyDigest, now }) {
  const delegation = delegationShape(input);
  if (delegation.admission.communityId !== communityId || delegation.admission.policyDigest !== policyDigest
      || delegation.expiresAt <= now || delegation.issuedAt > now) throw new Error('Delegation is outside the trusted community interval');
  const digestValue = digestBytes(digest);
  const entry = publicEntry({
    memberId: delegation.admission.memberId,
    accountKey: delegation.accountPublicKey,
    secretHash: delegation.stateSecretCommitment,
    issuedAt: delegation.issuedAt,
    expiresAt: delegation.expiresAt,
    delegationDigest: hex(digestValue),
  });
  return { delegation, digest: digestValue, entry };
}

function slotFor(now, period) {
  if (!Number.isSafeInteger(period) || period <= 0) throw new TypeError('Explicit checkpoint period required');
  const slot = Math.floor(now / period);
  const end = (slot + 1) * period;
  if (!Number.isSafeInteger(slot) || !Number.isSafeInteger(end) || end <= now) throw new Error('Checkpoint time outside bounds');
  return { slot, notBefore: slot * period, expiresAt: end };
}

async function signPublication(publication, privateKey) {
  if (!privateKey) throw new TypeError('Trusted enrollment signing key required');
  const signature = sign(null, Buffer.from(publicationSigningBytes(publication)), privateKey).toString('base64url');
  return publicationShape({ ...publication, signature });
}

/**
 * Server-side enrollment boundary. The store is Node-only and must provide
 * list, upsert, observeClock, pending, putPending, and markInstalled. The
 * verifier is the actual cmsg verifyAccountingDelegation bridge and returns
 * its 32-byte digest; booleans and caller supplied digests are rejected.
 */
export function createEnrollmentService(options = {}) {
  const { communityId, policyDigest, community, hashes, clock, verifyDelegation, store,
    checkpointPeriodSeconds, maxMembers, operatorPrivateKey, installCheckpoint } = options;
  if (typeof communityId !== 'string' || communityId.length < 1
      || typeof policyDigest !== 'string' || typeof clock !== 'function'
      || typeof verifyDelegation !== 'function' || !store
      || typeof store.list !== 'function' || typeof store.upsert !== 'function'
      || typeof store.observeClock !== 'function' || typeof store.pending !== 'function'
      || typeof store.putPending !== 'function' || typeof store.markInstalled !== 'function'
      || !hashes || typeof hashes.enrollment !== 'function' || typeof hashes.enrollmentNode !== 'function'
      || !Number.isSafeInteger(checkpointPeriodSeconds) || checkpointPeriodSeconds <= 0
      || !Number.isSafeInteger(maxMembers) || maxMembers < 1 || maxMembers > 65536
      || typeof installCheckpoint !== 'function' || !operatorPrivateKey) {
    throw new TypeError('Explicit enrollment verifier, publisher and store are required');
  }
  bytes32(community);
  let closed = false;
  let lastClock = 0;
  const currentTime = async () => {
    if (closed) throw new Error('Enrollment service is closed');
    const value = clock();
    if (!integer(value)) throw new Error('Trusted enrollment clock required');
    if (value < lastClock) throw new Error('Enrollment clock moved backwards');
    await store.observeClock(communityId, value);
    lastClock = value;
    return value;
  };
  async function verify(input, now) {
    const delegation = delegationShape(input);
    let digest;
    try { digest = await verifyDelegation({ delegation: clone(delegation), communityId, policyDigest, now }); }
    catch { throw new Error('Accounting delegation rejected'); }
    if (digest === true || digest === false || digest === undefined || digest === null) {
      throw new Error('Typed delegation digest required');
    }
    return normalize({ delegation, digest, communityId, policyDigest, now });
  }
  async function records(now) {
    const values = await store.list(communityId);
    if (!Array.isArray(values) || values.length > maxMembers) throw new Error('Enrollment registry unavailable');
    const seen = new Set(), result = [];
    for (const value of values) {
      if (!value || !Object.hasOwn(value, 'delegation')) throw new Error('Unverified enrollment registry record');
      // Shape-check before filtering. A malformed expired row is registry
      // corruption; an explicitly expired, otherwise valid row is retained
      // for renewal but omitted from this live checkpoint.
      const delegation = delegationShape(value.delegation);
      if (delegation.expiresAt <= now) continue;
      const verified = await verify(delegation, now);
      if (seen.has(verified.entry.memberId)) throw new Error('Duplicate enrolled member');
      seen.add(verified.entry.memberId);
      result.push(verified);
    }
    return result;
  }
  async function publishAt(now) {
    const { slot, notBefore, expiresAt } = slotFor(now, checkpointPeriodSeconds);
    const existing = await store.pending(communityId, slot);
    if (existing) {
      const publication = publicationShape(existing.publication);
      if (!existing.installed) {
        await installCheckpoint({ slot, root: publication.root.slice() });
        await store.markInstalled(communityId, slot);
      }
      return clone(publication);
    }
    const verified = (await records(now)).filter(value => value.entry.expiresAt >= expiresAt);
    if (verified.length === 0) throw new Error('No delegation valid for checkpoint slot');
    const sorted = sortPublicationDelegations(verified.map(value => ({ delegation: value.delegation, entry: value.entry })));
    const checkpoint = await checkpointFromVerified(community, sorted.map(value => value.entry), hashes);
    const unsigned = {
      version: 1, domain: ENROLLMENT_DOMAIN, communityId, policyDigest, slot, notBefore, expiresAt,
      root: Array.from(fieldBytes(checkpoint.root)), delegations: sorted,
    };
    const publication = await signPublication(unsigned, operatorPrivateKey);
    const durable = await store.putPending(communityId, slot, publication);
    const exactPublication = publicationShape(durable.publication);
    if (!durable.installed) {
      await installCheckpoint({ slot, root: exactPublication.root.slice() });
      await store.markInstalled(communityId, slot);
    }
    return clone(exactPublication);
  }
  return Object.freeze({
    async enroll(delegationInput) {
      const now = await currentTime();
      const verified = await verify(delegationInput, now);
      await store.upsert(communityId, { delegation: verified.delegation, digest: hex(verified.digest), entry: verified.entry });
      return clone(verified.entry);
    },
    async verifiedEntries() {
      return (await records(await currentTime())).map(value => clone(value.entry));
    },
    async buildCheckpoint() {
      const values = await records(await currentTime());
      const entries = values.sort((a, b) => a.entry.memberId < b.entry.memberId ? -1 : a.entry.memberId > b.entry.memberId ? 1 : 0).map(value => value.entry);
      const checkpoint = await checkpointFromVerified(community, entries, hashes);
      return Object.freeze({ checkpoint, entries: clone(entries) });
    },
    async publishCheckpoint() { return publishAt(await currentTime()); },
    async current() {
      // This also creates the current slot on a fresh server. If there is no
      // delegation valid through the slot end, publishAt reports the explicit
      // unavailable condition instead of silently returning null.
      return publishAt(await currentTime());
    },
    close() { closed = true; },
  });
}
