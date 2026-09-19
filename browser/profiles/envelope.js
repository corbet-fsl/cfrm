import { authorityExpiry, decode, digest, encode, exact, fresh, json, positive, random,
  reject, scope, signing, textDecoder, trustCopy, utf8, verifyAuthority, verifySignature } from './crypto.js';

const FIELDS = ['version', 'communityId', 'memberId', 'chatPublicKey', 'profileEpoch', 'sequence',
  'issuedAt', 'expiresAt', 'nonce', 'profileDigest', 'discriminators', 'ciphertext', 'signature'];
export const LIMIT_FIELDS = ['maxProfileBytes', 'maxEnvelopeBytes', 'maxProfileSeconds',
  'maxFrameBytes', 'maxProofBytes', 'maxChallengeSeconds', 'maxKeySeconds', 'maxReplayEntries',
  'maxConcurrentProofs', 'maxRequestsPerWindow', 'requestWindowSeconds'];
export function limitsCopy(value) {
  exact(value, LIMIT_FIELDS);
  for (const field of LIMIT_FIELDS) positive(value[field]);
  if (value.maxProfileBytes + 16 > value.maxEnvelopeBytes || value.maxEnvelopeBytes > value.maxFrameBytes ||
      value.maxProofBytes > value.maxFrameBytes || value.maxChallengeSeconds > 300) reject();
  return Object.freeze({ ...value });
}
function discriminators(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) reject();
  const pairs = Object.entries(value).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
  for (const [name, field] of pairs) {
    if (!/^[A-Za-z][A-Za-z0-9_]{0,31}$/.test(name)) reject();
    if (!Number.isSafeInteger(field) || field < 0 || field > 0xffffffff) reject();
  }
  return pairs;
}
function metadata(value) {
  if (value.version !== 1) reject();
  scope(value.communityId);
  for (const field of ['memberId', 'chatPublicKey', 'profileEpoch']) decode(value[field], 32);
  decode(value.nonce, 12); positive(value.sequence); positive(value.issuedAt); positive(value.expiresAt);
  if (value.expiresAt <= value.issuedAt) reject();
  return [value.communityId, value.memberId, value.chatPublicKey, value.profileEpoch,
    value.sequence, value.issuedAt, value.expiresAt, value.nonce];
}
/** Matches Rust profile_envelope_bytes exactly. Only ciphertext is digested. */
export function profileEnvelopeBytes(value) {
  exact(value, FIELDS); decode(value.profileDigest, 32);
  return json(['cfrm.cached-profile.v1', ...metadata(value), value.profileDigest, discriminators(value.discriminators)]);
}
export function profileAssociatedData(value) {
  return json(['cfrm.cached-profile.aad.v1', ...metadata(value), discriminators(value.discriminators)]);
}
function boundedCachedProfile(value, limits) {
  exact(value, ['admission', 'authorization', 'envelope']);
  if (json(value).length > limits.maxEnvelopeBytes) reject();
  profileEnvelopeBytes(value.envelope);
  const ciphertext = decode(value.envelope.ciphertext, undefined, limits.maxProfileBytes + 16);
  if (ciphertext.length < 16) reject();
  decode(value.envelope.signature, 64);
  return ciphertext;
}
export async function verifyCachedProfile(value, { trust, limits, now, expectedMemberId }) {
  const config = limitsCopy(limits), anchor = trustCopy(trust);
  const snapshot = structuredClone(value), ciphertext = boundedCachedProfile(snapshot, config);
  const authority = await verifyAuthority({ admission: snapshot.admission, authorization: snapshot.authorization }, anchor, now);
  const envelope = snapshot.envelope;
  decode(expectedMemberId, 32); fresh(envelope, now);
  if (envelope.communityId !== anchor.communityId || envelope.memberId !== expectedMemberId ||
      envelope.memberId !== authority.admission.memberId || envelope.chatPublicKey !== authority.admission.chatPublicKey ||
      envelope.issuedAt < Math.max(authority.admission.issuedAt, authority.authorization.issuedAt) ||
      envelope.expiresAt > authorityExpiry(authority) || envelope.expiresAt - envelope.issuedAt > config.maxProfileSeconds ||
      envelope.profileDigest !== await digest(ciphertext)) reject();
  await verifySignature(envelope.chatPublicKey, envelope.signature, profileEnvelopeBytes(envelope));
  return snapshot;
}
export async function encryptProfile({ text, identity, sequence, issuedAt, expiresAt, discriminators: publicFields }, config) {
  if (typeof text !== 'string' || !text.isWellFormed() || text.length > config.limits.maxProfileBytes) reject();
  const plaintext = utf8.encode(text);
  if (plaintext.length > config.limits.maxProfileBytes) reject();
  const authority = await verifyAuthority(identity.authority, config.trust, issuedAt);
  const envelope = { version: 1, communityId: config.trust.communityId, memberId: authority.admission.memberId,
    chatPublicKey: authority.admission.chatPublicKey, profileEpoch: encode(random(32)), sequence,
    issuedAt, expiresAt, nonce: encode(random(12)), discriminators: structuredClone(publicFields),
    profileDigest: '', ciphertext: '', signature: '' };
  fresh(envelope, issuedAt);
  if (expiresAt - issuedAt > config.limits.maxProfileSeconds || expiresAt > authorityExpiry(authority)) reject();
  const secret = random(32);
  try {
    const key = await crypto.subtle.importKey('raw', secret, 'AES-GCM', false, ['encrypt']);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: decode(envelope.nonce, 12),
      additionalData: profileAssociatedData(envelope) }, key, plaintext));
    envelope.ciphertext = encode(ciphertext); envelope.profileDigest = await digest(ciphertext);
    envelope.signature = await signing(identity, profileEnvelopeBytes(envelope));
    const publication = { ...authority, envelope };
    boundedCachedProfile(publication, config.limits);
    return { publication, secret };
  } catch (error) { secret.fill(0); throw error; }
  finally { plaintext.fill(0); }
}
export async function decryptProfile(publication, secret, config) {
  const verified = await verifyCachedProfile(publication, { ...config, now: config.clock(), expectedMemberId: publication.envelope.memberId });
  const key = await crypto.subtle.importKey('raw', secret, 'AES-GCM', false, ['decrypt']);
  const plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: decode(verified.envelope.nonce, 12),
    additionalData: profileAssociatedData(verified.envelope) }, key, decode(verified.envelope.ciphertext, undefined, config.limits.maxProfileBytes + 16)));
  try { fresh(verified.envelope, config.clock()); return textDecoder.decode(plaintext); }
  finally { plaintext.fill(0); }
}
