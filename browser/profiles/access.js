import { authorityExpiry, decode, digest, encode, exact, fresh, json, monotonicClock,
  positive, random, reject, signing, textDecoder, trustCopy, unwrapSecret,
  verifyAuthority, verifySignature, wrapSecret, wrappingKeyPair, wrappingPublicKey } from './crypto.js';
import { decryptProfile, limitsCopy, profileEnvelopeBytes, verifyCachedProfile } from './envelope.js';
import { profileEligibilityRequest, validateEligibilityPresentation } from './eligibility.js';
import { verifyHolderDelegation } from './keys.js';

const CHALLENGE = ['version', 'communityId', 'policyDigest', 'envelopeDigest', 'holderMemberId', 'holderChatPublicKey',
  'sessionId', 'readerNonce', 'readerPublicKey', 'holderNonce', 'issuedAt', 'expiresAt'];
export function keyChallengeBytes(value) {
  exact(value, CHALLENGE);
  if (value.version !== 1) reject();
  for (const field of ['policyDigest', 'envelopeDigest', 'holderMemberId', 'holderChatPublicKey', 'sessionId', 'readerNonce', 'holderNonce']) decode(value[field], 32);
  decode(value.readerPublicKey, 65); positive(value.issuedAt); positive(value.expiresAt);
  if (value.expiresAt <= value.issuedAt) reject();
  return json(['cfrm.profile-key-challenge.v1', value.communityId, value.policyDigest, value.envelopeDigest,
    value.holderMemberId, value.holderChatPublicKey, value.sessionId, value.readerNonce, value.readerPublicKey,
    value.holderNonce, value.issuedAt, value.expiresAt]);
}
function grantBytes(value) {
  exact(value, ['version', 'challengeDigest', 'expiresAt', 'wrapped', 'signature']);
  exact(value.wrapped, ['publicKey', 'nonce', 'ciphertext']);
  if (value.version !== 1) reject();
  decode(value.challengeDigest, 32); positive(value.expiresAt);
  decode(value.wrapped.publicKey, 65); decode(value.wrapped.nonce, 12); decode(value.wrapped.ciphertext, 48);
  return json(['cfrm.profile-key-grant.v1', value.challengeDigest, value.expiresAt,
    value.wrapped.publicKey, value.wrapped.nonce, value.wrapped.ciphertext]);
}
function grantAssociatedData(challengeDigest, expiresAt) { return json(['cfrm.profile-key-grant.aad.v1', challengeDigest, expiresAt]); }
export function configuration(options) {
  return { trust: trustCopy(options.trust), limits: limitsCopy(options.limits), clock: monotonicClock(options.clock),
    publicIssuer: structuredClone(options.publicIssuer) };
}
function identityCopy(identity) {
  if (typeof identity?.sign !== 'function') reject();
  return { authority: structuredClone(identity.authority), sign: identity.sign.bind(identity) };
}
export { identityCopy };
function frame(value, config) {
  const bytes = json(value); if (bytes.length > config.limits.maxFrameBytes) reject(); return bytes;
}
function parse(bytes, config) {
  if (!(bytes instanceof Uint8Array) || bytes.length > config.limits.maxFrameBytes) reject();
  return JSON.parse(textDecoder.decode(bytes));
}
function boundedAccessProof(value, config) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || json(value).length > config.limits.maxProofBytes) reject();
}
async function timed(operation, config, onLate) {
  let timer, expired = false;
  const work = Promise.resolve().then(operation);
  // An injected transport may not support cancellation. Late opens are closed
  // and every later cryptographic boundary still checks the signed expiry.
  work.then(value => { if (expired && onLate) Promise.resolve(onLate(value)).catch(() => {}); }, () => {});
  try {
    return await Promise.race([work, new Promise((_, rejectPromise) => {
      timer = setTimeout(() => { expired = true; rejectPromise(new Error('Profile operation timed out')); }, config.limits.maxChallengeSeconds * 1000);
    })]);
  } finally { clearTimeout(timer); }
}
function challengeFresh(value, config) {
  keyChallengeBytes(value); fresh(value, config.clock());
  if (value.expiresAt - value.issuedAt > config.limits.maxChallengeSeconds) reject();
}
async function validateHolder(state, identity, config) {
  const authority = await verifyAuthority(identity.authority, config.trust, config.clock());
  const publication = await verifyCachedProfile(state.publication, { ...config, now: config.clock(),
    expectedMemberId: state.publication.envelope.memberId });
  if (state.delegation) await verifyHolderDelegation(state.delegation, publication, authority, config);
  else if (authority.admission.memberId !== publication.envelope.memberId ||
    authority.admission.chatPublicKey !== publication.envelope.chatPublicKey) reject();
  return authority;
}
/** Local member handler. It has no operator/cache transport and no accounting
 * capability. verifyTicket must authenticate an anonymous single-use resource
 * ticket; authorizeAccess must enforce proven-attribute and block policy. */
export function createProfileKeyService(options) {
  const config = configuration(options), identity = identityCopy(options.identity);
  for (const name of ['currentState', 'verifyEligibilityProof', 'verifyTicket', 'authorizeAccess']) {
    if (typeof options[name] !== 'function') reject();
  }
  const stateProvider = options.currentState, verifyProof = options.verifyEligibilityProof,
    verifyTicket = options.verifyTicket, authorize = options.authorizeAccess;
  const sessionId = encode(random(32)), consumed = new Map();
  let closed = false, verifying = 0, windowStart = 0, requests = 0;
  function live(snapshot) {
    const state = stateProvider(), now = config.clock();
    if (closed || !state || (snapshot && state !== snapshot)) reject();
    fresh(state.publication.envelope, now);
    fresh(identity.authority.admission, now); fresh(identity.authority.authorization, now);
    if (state.delegation) fresh(state.delegation, now);
    return state;
  }
  function rate() {
    const now = config.clock();
    if (now >= windowStart + config.limits.requestWindowSeconds) { windowStart = now; requests = 0; }
    if (requests >= config.limits.maxRequestsPerWindow) reject();
    requests++;
    for (const [key, expiry] of consumed) if (expiry <= now) consumed.delete(key);
  }
  async function matches(value, snapshot) {
    live(snapshot); challengeFresh(value, config);
    if (value.communityId !== config.trust.communityId || value.policyDigest !== config.trust.policyDigest ||
        value.sessionId !== sessionId || value.holderMemberId !== identity.authority.admission.memberId ||
        value.holderChatPublicKey !== identity.authority.admission.chatPublicKey ||
        value.envelopeDigest !== await digest(profileEnvelopeBytes(snapshot.publication.envelope)) ||
        value.expiresAt > Math.min(snapshot.publication.envelope.expiresAt, authorityExpiry(identity.authority),
          snapshot.delegation?.expiresAt ?? Number.MAX_SAFE_INTEGER)) reject();
    live(snapshot); challengeFresh(value, config);
  }
  return Object.freeze({
    close() { closed = true; consumed.clear(); },
    async handle(bytes) {
      const snapshot = live(); rate();
      const input = parse(bytes, config);
      if (Object.hasOwn(input ?? {}, 'hello')) {
        exact(input, ['hello']); exact(input.hello, ['version', 'envelopeDigest', 'readerNonce', 'readerPublicKey']);
        if (input.hello.version !== 1) reject();
        decode(input.hello.readerNonce, 32); decode(input.hello.readerPublicKey, 65);
        const authority = await validateHolder(snapshot, identity, config); live(snapshot);
        const envelopeDigest = await digest(profileEnvelopeBytes(snapshot.publication.envelope));
        if (input.hello.envelopeDigest !== envelopeDigest) reject();
        const issuedAt = config.clock(), expiresAt = Math.min(issuedAt + config.limits.maxChallengeSeconds,
          snapshot.publication.envelope.expiresAt, authorityExpiry(authority), snapshot.delegation?.expiresAt ?? Number.MAX_SAFE_INTEGER);
        const value = { version: 1, communityId: config.trust.communityId, policyDigest: config.trust.policyDigest,
          envelopeDigest, holderMemberId: authority.admission.memberId, holderChatPublicKey: authority.admission.chatPublicKey,
          sessionId, readerNonce: input.hello.readerNonce, readerPublicKey: input.hello.readerPublicKey,
          holderNonce: encode(random(32)), issuedAt, expiresAt };
        const signature = await signing(identity, keyChallengeBytes(value));
        await matches(value, snapshot);
        return frame({ challenge: { authority, delegation: snapshot.delegation ?? null, value, signature } }, config);
      }
      exact(input, ['read']); exact(input.read, ['challenge', 'holderSignature', 'presentation', 'accessProof', 'ticket']);
      const { challenge: value, holderSignature, presentation, accessProof, ticket } = input.read;
      await matches(value, snapshot);
      await verifySignature(identity.authority.admission.chatPublicKey, holderSignature, keyChallengeBytes(value));
      await validateEligibilityPresentation(presentation, config.publicIssuer, value, config.limits.maxProofBytes);
      boundedAccessProof(accessProof, config);
      const challengeDigest = await digest(keyChallengeBytes(value));
      live(snapshot); challengeFresh(value, config);
      if (consumed.has(challengeDigest) || consumed.size >= config.limits.maxReplayEntries || verifying >= config.limits.maxConcurrentProofs) reject();
      // Reserve before awaiting verifiers: each signed challenge consumes bounded
      // work once, including failed proofs, and concurrent replay cannot win.
      consumed.set(challengeDigest, value.expiresAt); verifying++;
      try {
        const request = await profileEligibilityRequest(config.publicIssuer, keyChallengeBytes(value), value);
        if (await verifyProof(request, structuredClone(presentation)) !== true) reject();
        await matches(value, snapshot);
        if (await authorize({ publication: structuredClone(snapshot.publication), challenge: structuredClone(value),
          presentation: structuredClone(presentation), accessProof: structuredClone(accessProof) }) !== true) reject();
        await matches(value, snapshot);
        if (await verifyTicket({ ticket: structuredClone(ticket), challengeDigest,
          expiresAt: value.expiresAt, now: config.clock() }) !== true) reject();
        await matches(value, snapshot);
        const expiresAt = Math.min(value.expiresAt, value.issuedAt + config.limits.maxKeySeconds);
        if (expiresAt <= config.clock()) reject();
        const wrapped = await wrapSecret(snapshot.secret, value.readerPublicKey, grantAssociatedData(challengeDigest, expiresAt));
        const grant = { version: 1, challengeDigest, expiresAt, wrapped, signature: '' };
        grant.signature = await signing(identity, grantBytes(grant));
        await matches(value, snapshot);
        return frame({ grant }, config);
      } finally { verifying--; }
    },
  });
}

/** A reader receives encrypted cache bytes via a cache capability and obtains
 * keys only through the separately supplied member-owned P2P capability. */
export function createProfileReader(options) {
  const config = configuration(options);
  for (const name of ['proveEligibility', 'proveAccess', 'acquireTicket', 'acceptPublication']) if (typeof options[name] !== 'function') reject();
  if (typeof options.cache?.fetch !== 'function' || typeof options.memberTransport?.open !== 'function') reject();
  const fetch = options.cache.fetch.bind(options.cache), open = options.memberTransport.open.bind(options.memberTransport),
    prove = options.proveEligibility, proveAccess = options.proveAccess, acquire = options.acquireTicket, accept = options.acceptPublication;
  return Object.freeze({ async read({ memberId, holderMemberId }) {
    decode(memberId, 32); decode(holderMemberId, 32);
    const publication = await verifyCachedProfile(await fetch(memberId), { ...config, now: config.clock(), expectedMemberId: memberId });
    if (await accept(structuredClone(publication)) !== true) reject();
    fresh(publication.envelope, config.clock());
    const envelopeDigest = await digest(profileEnvelopeBytes(publication.envelope)), pair = await wrappingKeyPair(),
      readerPublicKey = await wrappingPublicKey(pair), readerNonce = encode(random(32));
    // The capability is supplied by the trusted embedding; no URL, direct-IP,
    // WebRTC fallback or operator relay is selected inside this module.
    const connection = await timed(() => open({ memberId: holderMemberId }), config, value => value?.close?.());
    try {
      if (typeof connection?.exchange !== 'function' || typeof connection.close !== 'function') reject();
      const first = parse(await timed(() => connection.exchange(frame({ hello: { version: 1, envelopeDigest, readerNonce, readerPublicKey } }, config)), config), config);
      exact(first, ['challenge']); exact(first.challenge, ['authority', 'delegation', 'value', 'signature']);
      const { authority, delegation, value, signature } = first.challenge;
      const holder = await verifyAuthority(authority, config.trust, config.clock());
      if (holder.admission.memberId !== holderMemberId) reject();
      if (delegation) await verifyHolderDelegation(delegation, publication, holder, config);
      else if (holder.admission.memberId !== memberId || holder.admission.chatPublicKey !== publication.envelope.chatPublicKey) reject();
      challengeFresh(value, config);
      if (value.communityId !== config.trust.communityId || value.policyDigest !== config.trust.policyDigest ||
          value.envelopeDigest !== envelopeDigest || value.readerNonce !== readerNonce || value.readerPublicKey !== readerPublicKey ||
          value.holderMemberId !== holder.admission.memberId || value.holderChatPublicKey !== holder.admission.chatPublicKey ||
          value.issuedAt < Math.max(holder.admission.issuedAt, holder.authorization.issuedAt) ||
          value.expiresAt > Math.min(publication.envelope.expiresAt, authorityExpiry(holder), delegation?.expiresAt ?? Number.MAX_SAFE_INTEGER)) reject();
      await verifySignature(holder.admission.chatPublicKey, signature, keyChallengeBytes(value));
      challengeFresh(value, config);
      const request = await profileEligibilityRequest(config.publicIssuer, keyChallengeBytes(value), value);
      const presentation = await prove(request);
      await validateEligibilityPresentation(presentation, config.publicIssuer, value, config.limits.maxProofBytes);
      challengeFresh(value, config);
      const accessProof = await proveAccess({ challenge: structuredClone(value), publication: structuredClone(publication) });
      boundedAccessProof(accessProof, config); challengeFresh(value, config);
      const challengeDigest = await digest(keyChallengeBytes(value));
      const ticket = await acquire({ challengeDigest, expiresAt: value.expiresAt });
      challengeFresh(value, config);
      const last = parse(await timed(() => connection.exchange(frame({ read: { challenge: value, holderSignature: signature, presentation, accessProof, ticket } }, config)), config), config);
      exact(last, ['grant']); const { grant } = last;
      const message = grantBytes(grant);
      if (grant.challengeDigest !== challengeDigest || grant.expiresAt > value.expiresAt ||
          grant.expiresAt > value.issuedAt + config.limits.maxKeySeconds || config.clock() >= grant.expiresAt) reject();
      await verifySignature(holder.admission.chatPublicKey, grant.signature, message);
      challengeFresh(value, config);
      const secret = await unwrapSecret(grant.wrapped, pair.privateKey, grantAssociatedData(challengeDigest, grant.expiresAt));
      try {
        challengeFresh(value, config);
        const text = await decryptProfile(publication, secret, config);
        if (config.clock() >= grant.expiresAt) reject();
        return { memberId, sequence: publication.envelope.sequence, profileEpoch: publication.envelope.profileEpoch,
          discriminators: structuredClone(publication.envelope.discriminators), text };
      } finally { secret.fill(0); }
    } finally { if (typeof connection?.close === 'function') await timed(() => connection.close(), config); }
  } });
}
