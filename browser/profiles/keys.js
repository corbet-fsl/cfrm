import { authorityExpiry, decode, digest, encode, exact, fresh, json, positive, reject,
  signing, unwrapSecret, verifyAuthority, verifySignature, wrapSecret, wrappingPublicKey } from './crypto.js';
import { profileEnvelopeBytes, verifyCachedProfile } from './envelope.js';

function holderKeyBytes(value) {
  exact(value, ['version', 'communityId', 'memberId', 'chatPublicKey', 'publicKey', 'issuedAt', 'expiresAt', 'signature']);
  if (value.version !== 1) reject();
  decode(value.memberId, 32); decode(value.chatPublicKey, 32); decode(value.publicKey, 65);
  positive(value.issuedAt); positive(value.expiresAt);
  return json(['cfrm.profile-holder-key.v1', value.communityId, value.memberId, value.chatPublicKey,
    value.publicKey, value.issuedAt, value.expiresAt]);
}
/** Advertise the wrapping key with a fresh authorized device signature. */
export async function createHolderKeyOffer({ identity, wrappingKeys, expiresAt }, config) {
  const authority = await verifyAuthority(identity.authority, config.trust, config.clock());
  const issuedAt = config.clock();
  if (expiresAt <= issuedAt || expiresAt > authorityExpiry(authority) || expiresAt - issuedAt > config.limits.maxKeySeconds) reject();
  const offer = { version: 1, communityId: config.trust.communityId, memberId: authority.admission.memberId,
    chatPublicKey: authority.admission.chatPublicKey, publicKey: await wrappingPublicKey(wrappingKeys), issuedAt, expiresAt, signature: '' };
  offer.signature = await signing(identity, holderKeyBytes(offer));
  fresh(offer, config.clock());
  return { authority, offer };
}

const DELEGATION = ['version', 'communityId', 'ownerMemberId', 'ownerChatPublicKey', 'holderMemberId',
  'holderChatPublicKey', 'holderWrappingKey', 'envelopeDigest', 'issuedAt', 'expiresAt', 'signature'];
export function holderDelegationBytes(value) {
  exact(value, DELEGATION);
  if (value.version !== 1) reject();
  for (const field of ['ownerMemberId', 'ownerChatPublicKey', 'holderMemberId', 'holderChatPublicKey', 'envelopeDigest']) decode(value[field], 32);
  decode(value.holderWrappingKey, 65); positive(value.issuedAt); positive(value.expiresAt);
  if (value.expiresAt <= value.issuedAt) reject();
  return json(['cfrm.profile-holder.v1', value.communityId, value.ownerMemberId, value.ownerChatPublicKey,
    value.holderMemberId, value.holderChatPublicKey, value.holderWrappingKey, value.envelopeDigest, value.issuedAt, value.expiresAt]);
}
export async function verifyHolderDelegation(delegation, publication, holderAuthority, config) {
  const bytes = holderDelegationBytes(delegation), now = config.clock();
  fresh(delegation, now);
  if (delegation.communityId !== config.trust.communityId || delegation.ownerMemberId !== publication.envelope.memberId ||
      delegation.ownerChatPublicKey !== publication.envelope.chatPublicKey ||
      delegation.holderMemberId !== holderAuthority.admission.memberId ||
      delegation.holderChatPublicKey !== holderAuthority.admission.chatPublicKey ||
      delegation.envelopeDigest !== await digest(profileEnvelopeBytes(publication.envelope)) ||
      delegation.issuedAt < Math.max(publication.envelope.issuedAt, holderAuthority.admission.issuedAt, holderAuthority.authorization.issuedAt) ||
      delegation.expiresAt > Math.min(publication.envelope.expiresAt, authorityExpiry(holderAuthority)) ||
      delegation.expiresAt - delegation.issuedAt > config.limits.maxKeySeconds) reject();
  await verifySignature(publication.envelope.chatPublicKey, delegation.signature, bytes);
  fresh(delegation, config.clock());
}
function seedBytes(seed) {
  exact(seed, ['publication', 'delegation', 'wrapped', 'signature']);
  exact(seed.wrapped, ['publicKey', 'nonce', 'ciphertext']);
  return json(['cfrm.profile-holder-seed.v1', encode(holderDelegationBytes(seed.delegation)),
    seed.delegation.signature, seed.wrapped.publicKey, seed.wrapped.nonce, seed.wrapped.ciphertext]);
}
/** Returned seed travels only over a member-owned private channel, never via
 * the profile cache. Holder selection and wrapping-key authentication are the
 * embedding's explicit policy; this function validates the member authority. */
export async function makeHolderSeed(state, identity, holderOffer, expiresAt, config) {
  exact(holderOffer, ['authority', 'offer']);
  const { offer } = holderOffer;
  const authority = await verifyAuthority(holderOffer.authority, config.trust, config.clock());
  const offerMessage = holderKeyBytes(offer);
  fresh(offer, config.clock());
  if (offer.communityId !== config.trust.communityId || offer.memberId !== authority.admission.memberId ||
      offer.chatPublicKey !== authority.admission.chatPublicKey || offer.expiresAt > authorityExpiry(authority) ||
      offer.issuedAt < Math.max(authority.admission.issuedAt, authority.authorization.issuedAt) ||
      offer.expiresAt - offer.issuedAt > config.limits.maxKeySeconds || expiresAt > offer.expiresAt) reject();
  await verifySignature(authority.admission.chatPublicKey, offer.signature, offerMessage);
  const holderWrappingKey = offer.publicKey;
  const issuedAt = config.clock();
  const delegation = { version: 1, communityId: config.trust.communityId,
    ownerMemberId: state.publication.envelope.memberId, ownerChatPublicKey: state.publication.envelope.chatPublicKey,
    holderMemberId: authority.admission.memberId, holderChatPublicKey: authority.admission.chatPublicKey,
    holderWrappingKey, envelopeDigest: await digest(profileEnvelopeBytes(state.publication.envelope)), issuedAt, expiresAt, signature: '' };
  delegation.signature = await signing(identity, holderDelegationBytes(delegation));
  await verifyHolderDelegation(delegation, state.publication, authority, config);
  const wrapped = await wrapSecret(state.secret, holderWrappingKey, holderDelegationBytes(delegation));
  const seed = { publication: structuredClone(state.publication), delegation, wrapped, signature: '' };
  seed.signature = await signing(identity, seedBytes(seed));
  await verifyHolderDelegation(delegation, state.publication, authority, config);
  return seed;
}
export async function openHolderSeed(seed, identity, wrappingKeys, config) {
  const snapshot = structuredClone(seed);
  if (json(snapshot).length > config.limits.maxFrameBytes) reject();
  const message = seedBytes(snapshot);
  const publication = await verifyCachedProfile(snapshot.publication, { ...config, now: config.clock(),
    expectedMemberId: snapshot.publication.envelope.memberId });
  const authority = await verifyAuthority(identity.authority, config.trust, config.clock());
  await verifyHolderDelegation(snapshot.delegation, publication, authority, config);
  if (snapshot.delegation.holderWrappingKey !== await wrappingPublicKey(wrappingKeys)) reject();
  await verifySignature(publication.envelope.chatPublicKey, snapshot.signature, message);
  const secret = await unwrapSecret(snapshot.wrapped, wrappingKeys.privateKey, holderDelegationBytes(snapshot.delegation));
  try {
    await verifyHolderDelegation(snapshot.delegation, publication, authority, config);
    return { publication, delegation: snapshot.delegation, secret };
  } catch (error) { secret.fill(0); throw error; }
}
