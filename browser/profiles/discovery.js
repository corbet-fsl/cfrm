import { authorityExpiry, decode, encode, exact, fresh, json, monotonicClock, positive,
  random, reject, signing, trustCopy, verifyAuthority, verifySignature } from './crypto.js';
import { identityCopy } from './access.js';

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, sorted(value[key])]));
  return value;
}
/** Canonical request bytes match Rust discovery::request_signing_bytes. */
export function discoveryRequestBytes(value) {
  exact(value, ['version', 'admission', 'authorization', 'sessionId', 'requestId', 'issuedAt', 'expiresAt', 'operation', 'signature']);
  if (value.version !== 1 || value.expiresAt <= value.issuedAt) reject();
  positive(value.issuedAt); positive(value.expiresAt); decode(value.sessionId, 32); decode(value.requestId, 32);
  return json(['cfrm.discovery-request.v1', value.admission.communityId, value.admission.policyDigest,
    value.admission.memberId, value.admission.chatPublicKey, value.sessionId, value.requestId,
    value.issuedAt, value.expiresAt, sorted(value.operation)]);
}
/** send receives the signed public request only. An HTTP adapter posts it to
 * /v1/discovery as application/json and must bound bytes before JSON parsing.
 * The caller owns URLs/authenticated transport; no endpoint is guessed here. */
export function createDiscoveryClient(options) {
  const trust = trustCopy(options.trust), identity = identityCopy(options.identity), clock = monotonicClock(options.clock);
  const requestSeconds = positive(options.requestSeconds), maxResponseBytes = positive(options.maxResponseBytes);
  decode(options.sessionId, 32);
  if (typeof options.send !== 'function' || typeof options.lease !== 'function' || typeof options.savePending !== 'function') reject();
  const send = options.send, lease = options.lease, save = options.savePending, sessionId = options.sessionId;
  let pending = options.pendingRequest === undefined ? null : structuredClone(options.pendingRequest), writing = false;
  async function prepare(operation) {
    const authority = await verifyAuthority(identity.authority, trust, clock());
    const issuedAt = clock(), expiresAt = Math.min(issuedAt + requestSeconds, authorityExpiry(authority));
    const value = { version: 1, ...authority, sessionId, requestId: encode(random(32)), issuedAt, expiresAt,
      operation: structuredClone(operation), signature: '' };
    value.signature = await signing(identity, discoveryRequestBytes(value));
    fresh(value, clock());
    return value;
  }
  async function transmit(value) {
    fresh(value, clock());
    const response = await send(value);
    if (!response || typeof response !== 'object' || json(response).length > maxResponseBytes) reject();
    return response;
  }
  async function request(operation) { return transmit(await prepare(operation)); }
  const same = (left, right) => JSON.stringify(sorted(left)) === JSON.stringify(sorted(right));
  async function write(kind, build, matches, retain = false) {
    if (writing) reject(); writing = true;
    try {
      if (pending) {
        const message = discoveryRequestBytes(pending);
        if (pending.sessionId !== sessionId ||
            pending.admission.memberId !== identity.authority.admission.memberId ||
            pending.admission.chatPublicKey !== identity.authority.admission.chatPublicKey ||
            pending.admission.communityId !== trust.communityId || pending.admission.policyDigest !== trust.policyDigest) reject();
        await verifySignature(identity.authority.admission.chatPublicKey, pending.signature, message);
        if (pending.operation.kind === 'publish' && pending.operation.publication.envelope.expiresAt <= clock()) {
          await save(null); pending = null;
        }
      }
      if (pending) {
        if (pending.operation.kind !== kind || !matches(pending.operation)) reject();
        // After request expiry, recovery signs the same publication with a new
        // lease. The store treats an identical publication as quota-neutral;
        // this is not authorization to change its sequence, filters or bytes.
        if (pending.expiresAt <= clock()) pending = await prepare(await build());
      } else pending = await prepare(await build());
      await save(structuredClone(pending));
      const response = await transmit(structuredClone(pending));
      exact(response, ['kind']); if (response.kind !== 'updated') reject();
      if (!retain) { await save(null); pending = null; }
      return response;
    } finally { writing = false; }
  }
  return Object.freeze({
    async publish(publication) {
      const snapshot = structuredClone(publication);
      await write('publish', async () => ({ kind: 'publish', publication: snapshot, lease: await lease() }),
        operation => same(operation.publication, snapshot), true);
    },
    // Called only after the publisher durably commits the matching active DEK.
    // Until then, another write cannot discard the uncertain outer request.
    async confirmPublication(publication) {
      if (writing) reject(); writing = true;
      try {
        if (!pending) return;
        if (pending.operation.kind !== 'publish' || !same(pending.operation.publication, publication)) reject();
        await save(null); pending = null;
      } finally { writing = false; }
    },
    async fetch(memberId) {
      decode(memberId, 32);
      const response = await request({ kind: 'fetch', memberId });
      exact(response, ['kind', 'publication']); if (response.kind !== 'profile' || !response.publication) reject();
      return response.publication;
    },
    async query({ filters, limit, after = null }) {
      positive(limit);
      const response = await request({ kind: 'query', filters: structuredClone(filters), limit, after });
      exact(response, ['kind', 'entries', 'nextCursor']); if (response.kind !== 'page' || !Array.isArray(response.entries)) reject();
      return response;
    },
    async heartbeat() {
      await write('heartbeat', async () => ({ kind: 'heartbeat', lease: await lease() }), () => true);
    },
    async disconnect(sequence) {
      positive(sequence);
      await write('disconnect', async () => ({ kind: 'disconnect', leaseId: sessionId, sequence }),
        operation => operation.sequence === sequence);
    },
  });
}
