import { createHash, createHmac, createPublicKey, randomBytes, timingSafeEqual, verify } from 'node:crypto';

const b64 = bytes => Buffer.from(bytes).toString('base64url');
const hash = bytes => createHash('sha256').update(bytes).digest('base64url');
const integer = value => Number.isSafeInteger(value) && value > 0;
const scope = value => typeof value === 'string' && /^[A-Za-z0-9._:/-]{1,256}$/.test(value);
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join(',') === [...keys].sort().join(',');

function bytes(value, length) {
  if (typeof value !== 'string' || value.length !== Math.ceil(length * 4 / 3) ||
    !/^[A-Za-z0-9_-]+$/.test(value)) throw new TypeError('Invalid public encoding');
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.length !== length || b64(decoded) !== value) throw new TypeError('Invalid public encoding');
  return decoded;
}

function endpoint(value) {
  if (!exact(value, ['host', 'port']) || typeof value.host !== 'string' ||
    !/^[a-z2-7]{56}\.onion$/.test(value.host) || !integer(value.port) || value.port > 65535) {
    throw new TypeError('A canonical v3 onion host and explicit port are required');
  }
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  const decoded = [];
  let pending = 0;
  let width = 0;
  for (const character of value.host.slice(0, 56)) {
    pending = (pending << 5) | alphabet.indexOf(character);
    width += 5;
    if (width >= 8) { width -= 8; decoded.push((pending >>> width) & 255); }
    pending &= (1 << width) - 1;
  }
  const data = Buffer.from(decoded);
  const checksum = createHash('sha3-256').update('.onion checksum').update(data.subarray(0, 32)).update(Buffer.from([3])).digest();
  if (data.length !== 35 || data[34] !== 3 || !timingSafeEqual(data.subarray(32, 34), checksum.subarray(0, 2))) {
    throw new TypeError('Invalid onion version or checksum');
  }
  return { host: value.host, port: value.port };
}

/** Portable fixed-order bytes also signed by cmsg's certified Ed25519 chat key. */
export function rendezvousBytes(challenge) {
  if (!exact(challenge, ['communityId', 'memberId', 'chatPublicKey', 'endpoint',
    'challengeId', 'issuedAt', 'expiresAt']) || !scope(challenge.communityId) ||
    !integer(challenge.issuedAt) || !integer(challenge.expiresAt) || challenge.expiresAt <= challenge.issuedAt) {
    throw new TypeError('Invalid rendezvous challenge');
  }
  for (const field of ['memberId', 'chatPublicKey', 'challengeId']) bytes(challenge[field], 32);
  const route = endpoint(challenge.endpoint);
  return Buffer.from(JSON.stringify(['cfrm.rendezvous.v1', 'register', challenge.communityId,
    challenge.memberId, challenge.chatPublicKey, route.host, route.port,
    challenge.challengeId, challenge.issuedAt, challenge.expiresAt]));
}

function grantShape(grant) {
  if (!exact(grant, ['version', 'issuerKeyId', 'communityId', 'memberId', 'chatPublicKey',
    'policyDigest', 'issuedAt', 'expiresAt', 'signature']) || grant.version !== 1 ||
    !scope(grant.communityId) || !integer(grant.issuedAt) || !integer(grant.expiresAt) ||
    grant.expiresAt <= grant.issuedAt) throw new TypeError('Invalid admission grant');
  for (const field of ['issuerKeyId', 'memberId', 'chatPublicKey', 'policyDigest']) bytes(grant[field], 32);
  bytes(grant.signature, 64);
}

/**
 * Real ephemeral rendezvous, separate from the omniscient rules simulator.
 * verifyAdmission is a trusted host dependency, normally cvld/admission.
 * No request may supply or replace that verifier or its trust configuration.
 */
export function createRendezvous(options) {
  const { communityId, policyDigest, verifyAdmission, clock, leaseSeconds, challengeSeconds,
    maxMembers, maxReplayEntries } = options;
  if (!scope(communityId) || typeof verifyAdmission !== 'function' || typeof clock !== 'function' ||
    !(options.trustedPublicKey instanceof Uint8Array) || options.trustedPublicKey.length !== 32) {
    throw new TypeError('Explicit trusted admission configuration required');
  }
  bytes(policyDigest, 32);
  for (const [value, maximum] of [[leaseSeconds, 86400], [challengeSeconds, 300],
    [maxMembers, 100000], [maxReplayEntries, 1000000]]) {
    if (!integer(value) || value > maximum) throw new RangeError('Invalid explicit rendezvous bound');
  }
  const setTimer = options.setTimer ?? setTimeout;
  const clearTimer = options.clearTimer ?? clearTimeout;
  if (typeof setTimer !== 'function' || typeof clearTimer !== 'function') throw new TypeError('Invalid scheduler');
  const trustedPublicKey = Uint8Array.from(options.trustedPublicKey);
  const secret = randomBytes(32);
  const members = new Map(); // Stable ID -> active token hash, never a historical directory.
  const sessions = new Map(); // Token hash -> live ID, route and expiry only.
  const used = new Map(); // Opaque nonce hash -> short challenge expiry; no member IDs.
  let lastNow = 0;
  let timer;
  let closed = false;
  const authenticate = challenge => createHmac('sha256', secret).update(rendezvousBytes(challenge)).digest();

  function time() {
    if (closed) throw new Error('Rendezvous is closed');
    const now = clock();
    if (!integer(now) || now < lastNow) throw new Error('Clock must advance monotonically');
    lastNow = now;
    return now;
  }
  function erase(tokenHash) {
    const session = sessions.get(tokenHash);
    if (session) members.delete(session.memberId);
    sessions.delete(tokenHash);
  }
  function pruneAt(now) {
    for (const [tokenHash, session] of sessions) if (session.expiresAt <= now) erase(tokenHash);
    for (const [nonce, expiresAt] of used) if (expiresAt <= now) used.delete(nonce);
  }
  function schedule() {
    if (timer !== undefined) clearTimer(timer);
    timer = undefined;
    if (closed || (!sessions.size && !used.size)) return;
    let next = Infinity;
    for (const session of sessions.values()) next = Math.min(next, session.expiresAt);
    for (const expiresAt of used.values()) next = Math.min(next, expiresAt);
    timer = setTimer(() => {
      timer = undefined;
      try { pruneAt(time()); schedule(); } catch { close(); }
    }, Math.max(0, (next - lastNow) * 1000));
    timer?.unref?.();
  }
  function current() { const now = time(); pruneAt(now); return now; }
  function active(token) {
    current();
    const tokenHash = hash(bytes(token, 32));
    const session = sessions.get(tokenHash);
    if (!session) throw new Error('An active session is required');
    return { session, tokenHash };
  }
  async function admitted(grant, now) {
    grantShape(grant);
    return (await verifyAdmission({ grant: structuredClone(grant), trustedPublicKey: Uint8Array.from(trustedPublicKey),
      communityId, policyDigest, now })) === true;
  }
  function close() {
    closed = true;
    if (timer !== undefined) clearTimer(timer);
    timer = undefined;
    members.clear(); sessions.clear(); used.clear(); secret.fill(0);
  }

  return {
    async begin(grantInput, routeInput) {
      grantShape(grantInput);
      const grant = structuredClone(grantInput);
      const route = endpoint(routeInput);
      if (!(await admitted(grant, current()))) throw new Error('Admission rejected');
      const now = current();
      if (now < grant.issuedAt || now >= grant.expiresAt) throw new Error('Admission expired');
      const challenge = { communityId, memberId: grant.memberId, chatPublicKey: grant.chatPublicKey,
        endpoint: route, challengeId: b64(randomBytes(32)), issuedAt: now,
        expiresAt: Math.min(now + challengeSeconds, grant.expiresAt) };
      return { challenge, authenticator: b64(authenticate(challenge)) };
    },
    async register(input) {
      try {
        if (!exact(input, ['grant', 'challenge', 'authenticator', 'signature'])) return null;
        grantShape(input.grant);
        rendezvousBytes(input.challenge);
        bytes(input.authenticator, 32);
        bytes(input.signature, 64);
        const { grant, challenge, authenticator, signature } = structuredClone(input);
        const payload = rendezvousBytes(challenge);
        const now = current();
        if (now < challenge.issuedAt || now >= challenge.expiresAt ||
          challenge.expiresAt - challenge.issuedAt > challengeSeconds ||
          !timingSafeEqual(bytes(authenticator, 32), authenticate(challenge))) return null;
        if (!(await admitted(grant, now))) return null;
        if (grant.memberId !== challenge.memberId || grant.chatPublicKey !== challenge.chatPublicKey ||
          grant.communityId !== challenge.communityId || grant.expiresAt < challenge.expiresAt) return null;
        const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: grant.chatPublicKey }, format: 'jwk' });
        if (!verify(null, payload, key, bytes(signature, 64))) return null;
        // Recheck expiry/capacity after every asynchronous trust operation. From
        // here through insertion the single-instance transaction is synchronous.
        const commitNow = current();
        if (commitNow >= challenge.expiresAt || commitNow >= grant.expiresAt) return null;
        const nonce = hash(bytes(challenge.challengeId, 32));
        if (used.has(nonce) || used.size >= maxReplayEntries ||
          (!members.has(grant.memberId) && members.size >= maxMembers)) return null;
        const token = b64(randomBytes(32));
        const tokenHash = hash(bytes(token, 32));
        const expiresAt = Math.min(commitNow + leaseSeconds, grant.expiresAt);
        const old = members.get(grant.memberId);
        if (old) erase(old);
        used.set(nonce, challenge.expiresAt);
        members.set(grant.memberId, tokenHash);
        sessions.set(tokenHash, { memberId: grant.memberId, endpoint: { ...challenge.endpoint }, expiresAt });
        schedule();
        return { token, expiresAt };
      } catch { return null; }
    },
    list(token) {
      active(token);
      return [...sessions.values()].map(session => ({ memberId: session.memberId, endpoint: { ...session.endpoint } }))
        .sort((a, b) => a.memberId < b.memberId ? -1 : a.memberId > b.memberId ? 1 : 0);
    },
    disconnect(token) {
      try { const { tokenHash } = active(token); erase(tokenHash); schedule(); return true; }
      catch { return false; }
    },
    prune() { const now = current(); schedule(); return now; },
    counts() { return { members: members.size, sessions: sessions.size, replayMarkers: used.size }; },
    close,
  };
}
