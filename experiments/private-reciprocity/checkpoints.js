import { createHash, createPublicKey, sign, verify } from 'node:crypto';
import { Group } from '@semaphore-protocol/group';

const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const json = value => Buffer.from(JSON.stringify(value));
const hash = value => createHash('sha256').update(value).digest('base64url');
const scalarHash = value => BigInt('0x' + createHash('sha256').update(json(value)).digest('hex')).toString();
const integer = value => Number.isSafeInteger(value) && value > 0;
const scope = value => typeof value === 'string' && /^[A-Za-z0-9._:/-]{1,256}$/.test(value);
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const checkpointFields = ['version', 'issuerKeyId', 'communityId', 'policyDigest', 'epochSeconds',
  'epoch', 'notBefore', 'expiresAt', 'minAnonymity', 'depth', 'previousDigest', 'commitments', 'digest', 'signature'];
const bindingFields = ['version', 'issuerKeyId', 'communityId', 'memberId', 'commitment', 'signature'];
const linkFields = ['version', 'issuerKeyId', 'communityId', 'epoch', 'previousDigest', 'digest', 'signature'];

function bytes(value, length) {
  if (typeof value !== 'string' || value.length !== Math.ceil(length * 4 / 3) || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new TypeError('Invalid public encoding');
  }
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.length !== length || decoded.toString('base64url') !== value) throw new TypeError('Invalid public encoding');
  return decoded;
}
function commitment(value) {
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,77}$/.test(value) || BigInt(value) >= FIELD) {
    throw new TypeError('Invalid canonical commitment');
  }
  return value;
}
function publicKey(value) {
  if (!(value instanceof Uint8Array) || value.length !== 32) throw new TypeError('An explicitly trusted public key is required');
  return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(value).toString('base64url') }, format: 'jwk' });
}
function checkpointBytes(value) {
  if (value.version !== 1 || !scope(value.communityId) || !integer(value.epochSeconds) || value.epochSeconds > 2678400 ||
    !integer(value.epoch) || !integer(value.notBefore) || !integer(value.expiresAt) ||
    Math.floor(value.notBefore / value.epochSeconds) !== value.epoch ||
    value.expiresAt !== (value.epoch + 1) * value.epochSeconds || value.notBefore >= value.expiresAt ||
    !integer(value.minAnonymity) || value.minAnonymity < 16 || value.minAnonymity > 128 || value.depth !== 7 ||
    !Array.isArray(value.commitments) || value.commitments.length > 129) throw new TypeError('Invalid bounded checkpoint');
  bytes(value.issuerKeyId, 32); bytes(value.policyDigest, 32);
  if (value.previousDigest !== null) bytes(value.previousDigest, 32);
  let previous = 0n;
  for (const valueString of value.commitments) {
    const current = BigInt(commitment(valueString));
    if (current <= previous) throw new TypeError('Commitments must be strictly numerically ordered');
    previous = current;
  }
  return json(['cfrm.eligibility.checkpoint.v1', value.issuerKeyId, value.communityId, value.policyDigest,
    value.epochSeconds, value.epoch, value.notBefore, value.expiresAt, value.minAnonymity, value.depth,
    value.previousDigest, value.commitments]);
}
function bindingBytes(value) {
  if (value.version !== 1 || !scope(value.communityId)) throw new TypeError('Invalid enrollment binding');
  bytes(value.issuerKeyId, 32); bytes(value.memberId, 32); commitment(value.commitment);
  return json(['cfrm.semaphore.binding.v1', value.issuerKeyId, value.communityId, value.memberId, value.commitment]);
}
function linkBytes(value) {
  if (value.version !== 1 || !scope(value.communityId) || !integer(value.epoch)) throw new TypeError('Invalid checkpoint link');
  bytes(value.issuerKeyId, 32); bytes(value.digest, 32);
  if (value.previousDigest !== null) bytes(value.previousDigest, 32);
  return json(['cfrm.eligibility.link.v1', value.issuerKeyId, value.communityId,
    value.epoch, value.previousDigest, value.digest]);
}

export function verifyEnrollmentBinding({ binding, trustedPublicKey, communityId }) {
  try {
    if (!exact(binding, bindingFields) || binding.communityId !== communityId ||
      binding.issuerKeyId !== hash(trustedPublicKey)) return false;
    return verify(null, bindingBytes(binding), publicKey(trustedPublicKey), bytes(binding.signature, 64));
  } catch { return false; }
}

export function verifyCheckpoint({ checkpoint, trustedPublicKey, communityId, policyDigest, clock, previous, links = [] }) {
  try {
    if (!exact(checkpoint, checkpointFields) || checkpoint.communityId !== communityId || checkpoint.policyDigest !== policyDigest ||
      checkpoint.issuerKeyId !== hash(trustedPublicKey) || typeof clock !== 'function') return false;
    const payload = checkpointBytes(checkpoint);
    bytes(checkpoint.digest, 32);
    const now = clock();
    if (!integer(now) || now < checkpoint.notBefore || now >= checkpoint.expiresAt || checkpoint.digest !== hash(payload) ||
      !verify(null, payload, publicKey(trustedPublicKey), bytes(checkpoint.signature, 64))) return false;
    if (!Array.isArray(links) || links.length > 4096) return false;
    if (previous !== undefined) {
      if (!integer(previous.epoch)) return false;
      bytes(previous.digest, 32);
      if (checkpoint.epoch < previous.epoch || (checkpoint.epoch === previous.epoch &&
        (checkpoint.digest !== previous.digest || links.length))) return false;
      let previousEpoch = previous.epoch;
      let previousDigest = previous.digest;
      for (const link of links) {
        if (!exact(link, linkFields) || link.communityId !== communityId || link.issuerKeyId !== checkpoint.issuerKeyId ||
          link.epoch <= previousEpoch || link.epoch >= checkpoint.epoch || link.previousDigest !== previousDigest ||
          !verify(null, linkBytes(link), publicKey(trustedPublicKey), bytes(link.signature, 64))) return false;
        previousEpoch = link.epoch; previousDigest = link.digest;
      }
      if (checkpoint.epoch > previous.epoch && checkpoint.previousDigest !== previousDigest) return false;
    } else if (links.length) {
      return false; // Unanchored history is not an authenticated catch-up.
    }
    return true;
  } catch { return false; }
}

/** Trusted publisher operations; a network adapter must authenticate binding delivery. */
export function createCheckpointPublisher(options) {
  const { ledger, communityId, policyDigest, signingKey, clock, epochSeconds, minAnonymity, depth, maxRetainedLinks } = options;
  if (!scope(communityId) || typeof ledger?.publishCheckpoint !== 'function' || typeof ledger?.binding !== 'function' ||
    typeof clock !== 'function' || signingKey?.type !== 'private' || signingKey?.asymmetricKeyType !== 'ed25519' ||
    typeof ledger?.checkpointLinks !== 'function' || !integer(maxRetainedLinks) || maxRetainedLinks > 4096 ||
    !integer(epochSeconds) || epochSeconds > 2678400 || !integer(minAnonymity) || minAnonymity < 16 || minAnonymity > 128 || depth !== 7) {
    throw new TypeError('Explicit bounded publisher configuration is required');
  }
  bytes(policyDigest, 32);
  const issuerKeyId = hash(Buffer.from(createPublicKey(signingKey).export({ format: 'jwk' }).x, 'base64url'));
  const configuration = Object.freeze({ communityId, policyDigest, issuerKeyId, epochSeconds, minAnonymity, depth, maxRetainedLinks });
  let closed = false;
  function active() { if (closed) throw new Error('Publisher is closed'); }
  return {
    publish(...args) {
      active();
      if (args.length) throw new TypeError('Publication accepts no caller-selected roster');
      return ledger.publishCheckpoint(configuration, fields => {
        const checkpoint = { version: 1, issuerKeyId, communityId, policyDigest, epochSeconds, minAnonymity, depth, ...fields };
        const payload = checkpointBytes(checkpoint);
        const signedCheckpoint = { ...checkpoint, digest: hash(payload), signature: sign(null, payload, signingKey).toString('base64url') };
        const link = { version: 1, issuerKeyId, communityId, epoch: checkpoint.epoch,
          previousDigest: checkpoint.previousDigest, digest: signedCheckpoint.digest };
        return { checkpoint: signedCheckpoint,
          link: { ...link, signature: sign(null, linkBytes(link), signingKey).toString('base64url') } };
      }, clock);
    },
    binding(memberId) {
      active(); bytes(memberId, 32);
      const registered = ledger.binding(communityId, memberId);
      if (!registered) throw new Error('Member has no immutable enrollment');
      const binding = { version: 1, issuerKeyId, communityId, memberId, commitment: registered.commitment };
      return { ...binding, signature: sign(null, bindingBytes(binding), signingKey).toString('base64url') };
    },
    links(afterEpoch, beforeEpoch) {
      active();
      if (!integer(afterEpoch) || !integer(beforeEpoch) || beforeEpoch <= afterEpoch) throw new TypeError('Invalid checkpoint link interval');
      return ledger.checkpointLinks(communityId, afterEpoch, beforeEpoch);
    },
    close() { closed = true; },
  };
}

export function registeredAcknowledgementContext(checkpoint, binding, trust) {
  if (!verifyCheckpoint({ ...trust, checkpoint }) || !verifyEnrollmentBinding({ ...trust, binding })) {
    throw new Error('Authenticated current checkpoint and independent sender binding are required');
  }
  if (!checkpoint.commitments.includes(binding.commitment)) throw new Error('Sender is not qualified for the entire checkpoint');
  const others = checkpoint.commitments.filter(value => value !== binding.commitment);
  if (others.length < checkpoint.minAnonymity) throw new Error('Insufficient anonymity set');
  const group = new Group(others.map(BigInt));
  return Object.freeze({ communityId: checkpoint.communityId, epoch: String(checkpoint.epoch),
    notBefore: checkpoint.notBefore, expiresAt: checkpoint.expiresAt, senderId: binding.memberId,
    eligibleDigest: checkpoint.digest, root: group.root.toString(), depth: checkpoint.depth,
    anonymitySetSize: others.length,
    scope: scalarHash(['cfrm.ack.scope.v1', checkpoint.communityId, binding.memberId]),
    message: scalarHash(['cfrm.ack.registered.v1', checkpoint.digest, binding.memberId]),
  });
}
