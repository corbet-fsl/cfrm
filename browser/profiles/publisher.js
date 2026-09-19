import { decode, encode, exact, fresh, positive, reject, verifyAuthority } from './crypto.js';
import { configuration, createProfileKeyService, identityCopy } from './access.js';
import { encryptProfile, verifyCachedProfile } from './envelope.js';
import { makeHolderSeed, openHolderSeed } from './keys.js';

/** Checkpoints contain private DEKs. saveCheckpoint MUST use the member's
 * encrypted local wallet; it must never point at the operator profile cache. */
export async function createProfilePublisher(options) {
  const config = configuration(options), identity = identityCopy(options.identity);
  if (typeof options.saveCheckpoint !== 'function' || typeof options.reserveSequence !== 'function' ||
      typeof options.cache?.publish !== 'function') reject();
  const save = options.saveCheckpoint, reserve = options.reserveSequence, publishCache = options.cache.publish.bind(options.cache);
  await verifyAuthority(identity.authority, config.trust, config.clock());
  let active = null, pending = null, sequence = 0, busy = false, closed = false;
  function stateWire(state) { return state ? { publication: structuredClone(state.publication), secret: encode(state.secret) } : null; }
  function checkpoint() { return { version: 1, sequence, active: stateWire(active), pending: stateWire(pending) }; }
  function live() { if (closed) reject(); return active; }
  async function restoreState(state) {
    if (state === null) return null;
    exact(state, ['publication', 'secret']);
    const secret = decode(state.secret, 32);
    try {
      // Expiry erases key usefulness in honest wallets; retain only the sequence
      // floor. No expired publication can be reactivated by restoration.
      if (state.publication.envelope.expiresAt <= config.clock()) { secret.fill(0); return null; }
      const publication = await verifyCachedProfile(state.publication, { ...config, now: config.clock(),
        expectedMemberId: identity.authority.admission.memberId });
      if (publication.envelope.chatPublicKey !== identity.authority.admission.chatPublicKey || publication.envelope.sequence > sequence) reject();
      return { publication, secret };
    } catch (error) { secret.fill(0); throw error; }
  }
  if (options.checkpoint !== undefined) {
    const value = structuredClone(options.checkpoint);
    exact(value, ['version', 'sequence', 'active', 'pending']);
    if (value.version !== 1 || !Number.isSafeInteger(value.sequence) || value.sequence < 0) reject();
    sequence = value.sequence;
    try {
      active = await restoreState(value.active); pending = await restoreState(value.pending);
      if (pending && active && pending.publication.envelope.sequence <= active.publication.envelope.sequence) reject();
    } catch (error) { active?.secret.fill(0); pending?.secret.fill(0); throw error; }
  }
  async function commitPending() {
    if (!pending) reject();
    fresh(pending.publication.envelope, config.clock());
    // A response may be lost after the cache committed. Persist the exact key
    // and signed bytes before I/O and retry exactly; never generate a new DEK
    // for an uncertain publication.
    await save(checkpoint()); live();
    fresh(pending.publication.envelope, config.clock());
    const candidate = pending;
    await publishCache(structuredClone(candidate.publication)); live();
    fresh(candidate.publication.envelope, config.clock());
    const previous = active;
    active = candidate; pending = null;
    previous?.secret.fill(0);
    await save(checkpoint()); live();
    if (typeof options.cache.confirmPublication === 'function') await options.cache.confirmPublication(structuredClone(active.publication));
    live();
    return structuredClone(active.publication);
  }
  return Object.freeze({
    async publish({ text, discriminators, expiresAt }) {
      live(); if (busy || pending) reject(); busy = true;
      try {
        const next = positive(await reserve({ memberId: identity.authority.admission.memberId, after: sequence }));
        live(); if (next <= sequence) reject(); sequence = next;
        const candidate = await encryptProfile({ text, identity, sequence, issuedAt: config.clock(), expiresAt, discriminators }, config);
        if (closed) { candidate.secret.fill(0); reject(); }
        pending = candidate;
        return await commitPending();
      } finally { busy = false; }
    },
    async retryPending() {
      live(); if (busy) reject(); busy = true;
      try {
        if (!pending) {
          if (!active) reject(); await save(checkpoint());
          if (typeof options.cache.confirmPublication === 'function') await options.cache.confirmPublication(structuredClone(active.publication));
          return structuredClone(active.publication);
        }
        return await commitPending();
      } finally { busy = false; }
    },
    async expire() {
      live(); if (busy) reject(); busy = true;
      try {
        const now = config.clock();
        if (active && active.publication.envelope.expiresAt <= now) { active.secret.fill(0); active = null; }
        if (pending && pending.publication.envelope.expiresAt <= now) { pending.secret.fill(0); pending = null; }
        await save(checkpoint()); live();
      } finally { busy = false; }
    },
    currentPublication() { live(); return active ? structuredClone(active.publication) : null; },
    async seedHolder({ holderOffer, expiresAt }) {
      const snapshot = live(); if (!snapshot) reject();
      const result = await makeHolderSeed(snapshot, identity, structuredClone(holderOffer), expiresAt, config);
      if (live() !== snapshot) reject();
      fresh(snapshot.publication.envelope, config.clock()); return result;
    },
    createKeyService(accessOptions) {
      live();
      return createProfileKeyService({ ...accessOptions, ...config, identity, currentState: () => closed ? null : active });
    },
    close() { closed = true; active?.secret.fill(0); pending?.secret.fill(0); active = null; pending = null; },
  });
}

/** An explicitly chosen eligible peer imports an owner-signed, publication-bound
 * seed using its own private ECDH key. No key discovery or holder selection is
 * silently chosen by this library. */
export async function createSeededProfileHolder(options) {
  const config = configuration(options), identity = identityCopy(options.identity);
  let state = await openHolderSeed(options.seed, identity, options.wrappingKeys, config);
  const service = createProfileKeyService({ ...options, ...config, identity, currentState: () => state });
  return Object.freeze({
    handle: service.handle,
    close() { service.close(); state?.secret.fill(0); state = null; },
  });
}
