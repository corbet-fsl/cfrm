// Experimental member client only. The operator must not instantiate this
// handler or receive its frames/text. Transport is an explicit onion capability.
import { random32, sha256, sha3_256, verifyEd25519 } from './crypto-runtime.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const CHALLENGE_FIELDS = ['version', 'communityId', 'ownerMemberId', 'ownerChatPublicKey',
  'onionHost', 'onionPort', 'sessionId', 'readerNonce', 'ownerNonce', 'policyDigest', 'issuedAt', 'expiresAt'];
const GRANT_FIELDS = ['version', 'issuerKeyId', 'communityId', 'memberId', 'chatPublicKey',
  'policyDigest', 'issuedAt', 'expiresAt', 'signature'];
const LIMIT_FIELDS = ['maxProfileBytes', 'maxFrameBytes', 'maxProofBytes',
  'maxChallengeSeconds', 'maxReplayEntries', 'maxConcurrentProofs'];

function fail() { throw new Error('Profile request rejected'); }
function exact(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== fields.length || fields.some(field => !Object.hasOwn(value, field))) fail();
}
function positive(value) { if (!Number.isSafeInteger(value) || value < 1) fail(); return value; }
function scope(value) { if (typeof value !== 'string' || !/^[A-Za-z0-9._:/-]{1,256}$/.test(value)) fail(); return value; }
function encode(bytes) { return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', ''); }
function publicBytes(value, length = 32) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length !== Math.ceil(length * 4 / 3)) fail();
  const bytes = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), char => char.charCodeAt(0));
  if (bytes.length !== length || encode(bytes) !== value) fail();
  return bytes;
}
function textBytes(value, maxBytes) {
  if (typeof value !== 'string' || !value.isWellFormed()) fail();
  // UTF-16 length is a cheap lower bound before allocating encoded bytes.
  if (value.length > maxBytes) fail();
  const bytes = encoder.encode(value);
  if (bytes.length > maxBytes) fail();
  return bytes;
}
function jsonBytes(value) { return encoder.encode(JSON.stringify(value)); }
function decimalDigest(bytes) { return BigInt(`0x${Array.from(sha256(bytes), byte => byte.toString(16).padStart(2, '0')).join('')}`).toString(10); }
function encodedAttribute(raw) {
  // Existing AnonCreds raw-value encoding: signed int32 when representable,
  // otherwise the decimal SHA256 digest. The hash uses the native adapter.
  if (/^-?[0-9]+$/.test(raw)) {
    const number = BigInt(raw);
    if (number >= -2147483648n && number <= 2147483647n) return number.toString(10);
  }
  return decimalDigest(encoder.encode(raw));
}
function frame(value, limits) {
  const bytes = jsonBytes(value);
  if (bytes.length > limits.maxFrameBytes) fail();
  return bytes;
}
function parseFrame(bytes, limits) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength > limits.maxFrameBytes) fail();
  return JSON.parse(decoder.decode(bytes));
}
function endpoint(value) {
  exact(value, ['host', 'port']);
  if (typeof value.host !== 'string' || !/^[a-z2-7]{56}\.onion$/.test(value.host) ||
      positive(value.port) > 65535) fail();
  // Base32 is only an encoding. SHA3 is delegated to maintained native crypto.
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  const decoded = new Uint8Array(35);
  let accumulator = 0, bits = 0, offset = 0;
  for (const character of value.host.slice(0, 56)) {
    accumulator = (accumulator << 5) | alphabet.indexOf(character);
    bits += 5;
    if (bits >= 8) { bits -= 8; decoded[offset++] = (accumulator >>> bits) & 255; }
    accumulator &= (1 << bits) - 1;
  }
  const prefix = encoder.encode('.onion checksum');
  const input = new Uint8Array(prefix.length + 33);
  input.set(prefix); input.set(decoded.subarray(0, 32), prefix.length); input[input.length - 1] = 3;
  const checksum = sha3_256(input);
  if (decoded[34] !== 3 || decoded[32] !== checksum[0] || decoded[33] !== checksum[1]) fail();
  return { host: value.host, port: value.port };
}
function challenge(value) {
  exact(value, CHALLENGE_FIELDS);
  if (value.version !== 1) fail();
  scope(value.communityId);
  for (const key of ['ownerMemberId', 'ownerChatPublicKey', 'sessionId', 'readerNonce', 'ownerNonce', 'policyDigest']) publicBytes(value[key]);
  endpoint({ host: value.onionHost, port: value.onionPort });
  positive(value.issuedAt); positive(value.expiresAt);
  if (value.expiresAt <= value.issuedAt || value.expiresAt - value.issuedAt > 300) fail();
}
function fresh(value, now, limits) {
  positive(now);
  if (now < value.issuedAt || now >= value.expiresAt || value.expiresAt - value.issuedAt > limits.maxChallengeSeconds) fail();
}
function signed(bytes, signature, key) {
  if (!verifyEd25519(publicBytes(key), publicBytes(signature, 64), bytes)) fail();
}
function limitsCopy(limits) {
  exact(limits, LIMIT_FIELDS);
  for (const field of LIMIT_FIELDS) positive(limits[field]);
  if (limits.maxChallengeSeconds > 300 || limits.maxProofBytes > limits.maxFrameBytes || limits.maxProfileBytes > limits.maxFrameBytes) fail();
  return Object.freeze({ ...limits });
}
function configCopy(options) {
  if (!options || typeof options.clock !== 'function' || typeof options.verifyAdmission !== 'function' ||
      !(options.trustedPublicKey instanceof Uint8Array) || options.trustedPublicKey.length !== 32 ||
      typeof options.publicIssuer?.credentialDefinitionId !== 'string' || !options.publicIssuer.credentialDefinitionId ||
      typeof options.publicIssuer?.schemaId !== 'string' || !options.publicIssuer.schemaId) fail();
  scope(options.communityId); publicBytes(options.policyDigest);
  return { communityId: options.communityId, policyDigest: options.policyDigest,
    publicIssuer: structuredClone(options.publicIssuer), trustedPublicKey: new Uint8Array(options.trustedPublicKey),
    clock: options.clock, verifyAdmission: options.verifyAdmission, limits: limitsCopy(options.limits) };
}
async function admitted(grant, config) {
  exact(grant, GRANT_FIELDS);
  if (grant.version !== 1 || grant.communityId !== config.communityId || grant.policyDigest !== config.policyDigest) fail();
  for (const name of ['issuerKeyId', 'memberId', 'chatPublicKey', 'policyDigest']) publicBytes(grant[name]);
  publicBytes(grant.signature, 64); positive(grant.issuedAt); positive(grant.expiresAt);
  const now = positive(config.clock());
  if (!(await config.verifyAdmission({ grant, trustedPublicKey: config.trustedPublicKey,
    communityId: config.communityId, policyDigest: config.policyDigest, now }))) fail();
  if (config.clock() < grant.issuedAt || config.clock() >= grant.expiresAt) fail();
}

// Share the established route validation with transport adapters without
// exposing a second, weaker onion parser.
export function validateProfileEndpoint(value) { return endpoint(value); }

export function profileChallengeBytes(value) {
  challenge(value);
  return jsonBytes(['cfrm.profile.v1', 'challenge', value.communityId, value.ownerMemberId,
    value.ownerChatPublicKey, value.onionHost, value.onionPort, value.sessionId,
    value.readerNonce, value.ownerNonce, value.policyDigest, value.issuedAt, value.expiresAt]);
}
export function profileResponseBytes(value, profileDigest) {
  publicBytes(profileDigest);
  return jsonBytes(['cfrm.profile.v1', 'response', encode(sha256(profileChallengeBytes(value))), profileDigest]);
}
export function profileProofRequest(issuer, value) {
  const bytes = profileChallengeBytes(value);
  if (typeof issuer?.credentialDefinitionId !== 'string' || !issuer.credentialDefinitionId) fail();
  const restrictions = [{ cred_def_id: issuer.credentialDefinitionId }];
  // Intentionally full 256 bits. This protocol's compatibility prerequisite
  // must pass on the pinned AnonCreds runtime; truncation is not permitted.
  const nonce = decimalDigest(bytes);
  return { name: 'cfrm-profile-read', version: '1', nonce,
    requested_attributes: Object.fromEntries(['community_id', 'policy'].map(name => [name, { name, restrictions }])),
    requested_predicates: {
      eligible: { name: 'eligible', p_type: '>=', p_value: 1, restrictions },
      valid_until: { name: 'valid_until', p_type: '>=', p_value: value.expiresAt, restrictions },
    } };
}
function boundedProof(proof, config) {
  // Reject unsolicited stable disclosures even if a verifier accepts them.
  if (!proof || typeof proof !== 'object' || Array.isArray(proof) || jsonBytes(proof).length > config.limits.maxProofBytes) fail();
  exact(proof, ['proof', 'requested_proof', 'identifiers']);
  const requested = proof.requested_proof;
  exact(requested, ['revealed_attrs', 'self_attested_attrs', 'unrevealed_attrs', 'predicates']);
  exact(requested.revealed_attrs, ['community_id', 'policy']);
  exact(requested.self_attested_attrs, []); exact(requested.unrevealed_attrs, []);
  exact(requested.predicates, ['eligible', 'valid_until']);
  for (const [name, raw] of [['community_id', config.communityId], ['policy', config.policyDigest]]) {
    const value = requested.revealed_attrs[name];
    exact(value, ['sub_proof_index', 'raw', 'encoded']);
    if (value.sub_proof_index !== 0 || value.raw !== raw || value.encoded !== encodedAttribute(raw)) fail();
  }
  for (const value of Object.values(requested.predicates)) {
    exact(value, ['sub_proof_index']); if (value.sub_proof_index !== 0) fail();
  }
  if (!Array.isArray(proof.identifiers) || proof.identifiers.length !== 1) fail();
  const identifier = proof.identifiers[0];
  exact(identifier, ['schema_id', 'cred_def_id', 'rev_reg_id', 'timestamp']);
  if (identifier.schema_id !== config.publicIssuer.schemaId || identifier.cred_def_id !== config.publicIssuer.credentialDefinitionId ||
      identifier.rev_reg_id !== null || identifier.timestamp !== null) fail();
}

export function createProfileOwner(options) {
  const config = configCopy(options);
  if (typeof options.identity?.signProfileChallenge !== 'function' || typeof options.identity?.signProfileResponse !== 'function' ||
      typeof options.verifyEligibilityProof !== 'function') fail();
  const grant = structuredClone(options.identity.grant);
  exact(grant, GRANT_FIELDS);
  const signChallenge = options.identity.signProfileChallenge.bind(options.identity);
  const signResponse = options.identity.signProfileResponse.bind(options.identity);
  const verifyProof = options.verifyEligibilityProof;
  let text = '', active = null, verifying = 0;
  const consumed = new Map();
  function live(snapshot = active) {
    if (!active || snapshot !== active || config.clock() >= active.leaseExpiresAt || config.clock() >= grant.expiresAt) fail();
    positive(config.clock());
    return active;
  }
  function prune() {
    const now = positive(config.clock());
    for (const [key, expiry] of consumed) if (expiry <= now) consumed.delete(key);
  }
  function matches(value, snapshot) {
    challenge(value); live(snapshot); fresh(value, config.clock(), config.limits);
    if (value.communityId !== config.communityId || value.policyDigest !== config.policyDigest ||
        value.ownerMemberId !== grant.memberId || value.ownerChatPublicKey !== grant.chatPublicKey ||
        value.onionHost !== snapshot.endpoint.host || value.onionPort !== snapshot.endpoint.port ||
        value.sessionId !== snapshot.sessionId || value.expiresAt > snapshot.leaseExpiresAt ||
        value.expiresAt > grant.expiresAt || value.issuedAt < grant.issuedAt) fail();
  }
  return Object.freeze({
    setText(value) { textBytes(value, config.limits.maxProfileBytes); text = value; },
    activate({ endpoint: destination, leaseExpiresAt }) {
      const route = endpoint(destination); positive(leaseExpiresAt);
      const now = positive(config.clock());
      if (leaseExpiresAt <= now || now < grant.issuedAt || now >= grant.expiresAt) fail();
      active = { endpoint: route, leaseExpiresAt: Math.min(leaseExpiresAt, grant.expiresAt), sessionId: encode(random32()) };
      consumed.clear();
    },
    disconnect() { active = null; consumed.clear(); },
    async handle(bytes) {
      const snapshot = live();
      const input = parseFrame(bytes, config.limits);
      if (Object.hasOwn(input ?? {}, 'hello')) {
        exact(input, ['hello']); exact(input.hello, ['version', 'readerNonce']);
        if (input.hello.version !== 1) fail(); publicBytes(input.hello.readerNonce);
        await admitted(grant, config); live(snapshot);
        const issuedAt = positive(config.clock());
        const value = { version: 1, communityId: config.communityId, ownerMemberId: grant.memberId,
          ownerChatPublicKey: grant.chatPublicKey, onionHost: snapshot.endpoint.host, onionPort: snapshot.endpoint.port,
          sessionId: snapshot.sessionId, readerNonce: input.hello.readerNonce, ownerNonce: encode(random32()),
          policyDigest: config.policyDigest, issuedAt,
          expiresAt: Math.min(issuedAt + config.limits.maxChallengeSeconds, snapshot.leaseExpiresAt, grant.expiresAt) };
        const signature = await signChallenge(structuredClone(value));
        matches(value, snapshot); signed(profileChallengeBytes(value), signature, grant.chatPublicKey);
        return frame({ challenge: { ownerGrant: structuredClone(grant), value, signature } }, config.limits);
      }
      exact(input, ['read']); exact(input.read, ['challenge', 'ownerSignature', 'presentation']);
      const { challenge: value, ownerSignature, presentation } = input.read;
      matches(value, snapshot);
      signed(profileChallengeBytes(value), ownerSignature, grant.chatPublicKey);
      boundedProof(presentation, config);
      prune();
      const challengeDigest = encode(sha256(profileChallengeBytes(value)));
      if (consumed.has(challengeDigest) || consumed.size >= config.limits.maxReplayEntries || verifying >= config.limits.maxConcurrentProofs) fail();
      verifying++;
      try {
        const request = profileProofRequest(config.publicIssuer, value);
        if (await verifyProof(request, presentation) !== true) fail();
        matches(value, snapshot); prune();
        if (consumed.has(challengeDigest) || consumed.size >= config.limits.maxReplayEntries) fail();
        // Synchronous claim before signing/returning, so concurrent replay wins once.
        consumed.set(challengeDigest, value.expiresAt);
        const responseText = text;
        const profileDigest = encode(sha256(textBytes(responseText, config.limits.maxProfileBytes)));
        const signature = await signResponse(structuredClone(value), profileDigest);
        matches(value, snapshot); signed(profileResponseBytes(value, profileDigest), signature, grant.chatPublicKey);
        return frame({ profile: { version: 1, challengeDigest, profileDigest, text: responseText, signature } }, config.limits);
      } finally { verifying--; }
    },
  });
}

export function createProfileReader(options) {
  const config = configCopy(options);
  if (typeof options.onionTransport?.open !== 'function' || typeof options.proveEligibility !== 'function') fail();
  exact(options.expectedOwner, ['memberId', 'endpoint']); publicBytes(options.expectedOwner.memberId);
  const expected = { memberId: options.expectedOwner.memberId, endpoint: endpoint(options.expectedOwner.endpoint) };
  const open = options.onionTransport.open.bind(options.onionTransport);
  const prove = options.proveEligibility;
  return Object.freeze({ async read() {
    const readerNonce = encode(random32());
    const connection = await open({ ...expected.endpoint });
    try {
      if (typeof connection?.exchange !== 'function' || typeof connection.close !== 'function') fail();
      const hello = frame({ hello: { version: 1, readerNonce } }, config.limits);
      const response = parseFrame(await connection.exchange(hello), config.limits);
      exact(response, ['challenge']); exact(response.challenge, ['ownerGrant', 'value', 'signature']);
      const { ownerGrant, value, signature } = response.challenge;
      await admitted(ownerGrant, config);
      challenge(value); fresh(value, config.clock(), config.limits);
      if (ownerGrant.memberId !== expected.memberId || value.ownerMemberId !== expected.memberId ||
          value.ownerChatPublicKey !== ownerGrant.chatPublicKey || value.communityId !== config.communityId ||
          value.policyDigest !== config.policyDigest || value.readerNonce !== readerNonce ||
          value.onionHost !== expected.endpoint.host || value.onionPort !== expected.endpoint.port ||
          value.issuedAt < ownerGrant.issuedAt || value.expiresAt > ownerGrant.expiresAt) fail();
      signed(profileChallengeBytes(value), signature, ownerGrant.chatPublicKey);
      // The wallet never consumes an arbitrary owner-supplied presentation request.
      const presentation = await prove(profileProofRequest(config.publicIssuer, value));
      fresh(value, config.clock(), config.limits); boundedProof(presentation, config);
      const input = frame({ read: { challenge: value, ownerSignature: signature, presentation } }, config.limits);
      const reply = parseFrame(await connection.exchange(input), config.limits);
      exact(reply, ['profile']);
      exact(reply.profile, ['version', 'challengeDigest', 'profileDigest', 'text', 'signature']);
      const profile = reply.profile;
      const profileDigest = encode(sha256(textBytes(profile.text, config.limits.maxProfileBytes)));
      if (profile.version !== 1 || profile.challengeDigest !== encode(sha256(profileChallengeBytes(value))) ||
          profile.profileDigest !== profileDigest) fail();
      signed(profileResponseBytes(value, profileDigest), profile.signature, ownerGrant.chatPublicKey);
      fresh(value, config.clock(), config.limits);
      return { ownerMemberId: expected.memberId, text: profile.text };
    } finally { if (typeof connection?.close === 'function') await connection.close(); }
  } });
}
