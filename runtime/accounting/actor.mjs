import { AccountWitness } from './witness.mjs';
import { AccountClient, accountRequestBytes, verifyAccountAcceptance } from './client.mjs';
import { copyEnrollmentCheckpoint, enrollmentRoot, verifyEnrollmentPath } from './enrollment.mjs';
import { STATEMENT_KEYS } from './peer-witness.mjs';
import { fieldBytes } from './primitives.mjs';
import { hex, unhex, random, sha } from './encoding.mjs';
import { scopedAccountSigner } from './actor-signing.mjs';
import { accountActorStorage } from './actor-storage.mjs';

const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const equal = (a, b) => Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((value, index) => value === b[index]);
const byte32 = value => {
  if (!(value instanceof Uint8Array) || value.length !== 32) throw new Error('Account actor bytes32');
  return new Uint8Array(value);
};
const decode = value => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) throw new Error('Account actor identity');
  const bytes = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), char => char.charCodeAt(0));
  if (bytes.length !== 32) throw new Error('Account actor identity'); return bytes;
};

/** One serialized holder-side account, backed by encrypted local CAS storage.
 * All enrollment/authority/policy inputs come from independently verified host
 * configuration. Peer evidence and private event handles never enter transport. */
export async function createAccountActor(options) {
  const { runtime, transport, authority, authorizeRequest, authorizeStatus, clock } = options;
  if (!runtime || !['prove', 'provePeer', 'verifyPeer'].every(key => typeof runtime[key] === 'function')
      || ![transport, authority, authorizeRequest, authorizeStatus, clock].every(value => typeof value === 'function')) {
    throw new Error('Account actor runtime and typed callbacks required');
  }
  const community = byte32(options.community), ownerSecret = byte32(options.ownerSecret);
  const operatorPublicKey = byte32(options.operatorPublicKey), policy = structuredClone(options.policy);
  let enrollment = copyEnrollmentCheckpoint(options.enrollment), root = byte32(options.expectedEnrollmentRoot);
  let ownerIndex = options.ownerIndex;
  const checkpointLimits = structuredClone(options.checkpointLimits), scope = structuredClone(runtime.scope);
  if (enrollment.root !== enrollmentRoot(root) || !Number.isSafeInteger(options.ownerIndex)
      || !enrollment.entries[options.ownerIndex]
      || !exact(checkpointLimits, ['maxBytes', 'maxMapEntries', 'maxSlots'])
      || Object.entries({ maxBytes: 16 * 1024 * 1024, maxMapEntries: 65536, maxSlots: 65535 })
        .some(([key, limit]) => !Number.isSafeInteger(checkpointLimits[key]) || checkpointLimits[key] < 1 || checkpointLimits[key] > limit)) {
    throw new Error('Account actor enrollment/limits');
  }
  const owner = new Uint8Array(enrollment.entries[options.ownerIndex].member);
  const store = accountActorStorage(options);
  let signingAuthority, journal, state = null, busy = false, blocked = false, closed = false;
  const client = new AccountClient({ transport, operatorPublicKey,
    sign: scopedAccountSigner({ authorizeRequest, authorizeStatus, authority: () => signingAuthority }) });
  const empty = () => ({ version: 1, revision: 0, community: Array.from(community), owner: Array.from(owner), accepted: null, pending: null });
  const now = () => {
    const value = clock();
    if (!Number.isSafeInteger(value) || value <= 0) throw new Error('Account actor clock'); return value;
  };
  async function identity() {
    const value = structuredClone(await authority());
    if (!exact(value, ['grant', 'authorization']) || value.grant.memberId !== value.authorization.memberId
        || hex(decode(value.grant.memberId)) !== hex(owner)
        || value.grant.communityId !== value.authorization.communityId
        || hex(await sha(new TextEncoder().encode(value.grant.communityId))) !== hex(community)) throw new Error('Account actor authority');
    signingAuthority = value; return value;
  }
  function scoped(statement, proofScope) {
    if (!equal(statement.community, Array.from(community)) || !equal(statement.owner, Array.from(owner))
        || !equal(proofScope.circuitDigest, scope.circuitDigest)
        || !equal(proofScope.verifyingKeyDigest, scope.verifyingKeyDigest)) throw new Error('Account actor state scope');
  }
  async function restore(checkpoint, statement) {
    if (typeof checkpoint !== 'string' || checkpoint.length > checkpointLimits.maxBytes * 2) throw new Error('Account actor checkpoint bound');
    return AccountWitness.restoreCheckpoint({ checkpointBytes: unhex(checkpoint), hashes: runtime.hashes,
      enrollment, expectedEnrollmentRoot: root, ownerSecret, expectedStatement: statement, limits: checkpointLimits });
  }
  async function reload() {
    blocked = true;
    const loaded = await store.load() ?? empty();
    if (!exact(loaded, ['version', 'revision', 'community', 'owner', 'accepted', 'pending']) || loaded.version !== 1
        || !equal(loaded.community, Array.from(community)) || !equal(loaded.owner, Array.from(owner))) throw new Error('Account actor journal');
    let restored = null;
    if (loaded.accepted !== null) {
      if (!exact(loaded.accepted, ['acceptance', 'checkpoint'])) throw new Error('Account actor accepted record');
      const accepted = loaded.accepted.acceptance;
      scoped(accepted.statement, accepted.proofScope);
      await verifyAccountAcceptance(accepted, operatorPublicKey);
      restored = await restore(loaded.accepted.checkpoint, accepted.statement);
    }
    if (loaded.pending !== null) {
      if (!exact(loaded.pending, ['request', 'checkpoint', 'event'])
          || (loaded.pending.event !== null && !/^[1-9][0-9]{0,77}$/.test(loaded.pending.event))) throw new Error('Account actor pending record');
      const request = loaded.pending.request;
      scoped(request.statement, request.proofScope);
      await accountRequestBytes(request);
      await restore(loaded.pending.checkpoint, request.statement);
      if (restored ? request.statement.genesis || request.statement.previousVersion !== Number(restored.version)
          || !equal(request.statement.previousState, Array.from(unhex(restored.commitment.toString(16).padStart(64, '0'))))
        : !request.statement.genesis) throw new Error('Account actor pending predecessor');
    }
    journal = loaded; state = restored; blocked = false;
  }
  async function save(next) {
    try { journal = await store.save(next); }
    catch (error) { if (store.uncertain) blocked = true; throw error; }
  }
  async function exclusive(run) {
    if (busy || closed) throw new Error('Account actor busy or closed');
    busy = true; try { return await run(); } finally { busy = false; }
  }
  function available() {
    if (blocked || store.uncertain) throw new Error('Account actor reload required');
    if (journal.pending) throw new Error('Account actor has an unresolved signed request');
  }
  const receipt = event => ({ acceptance: structuredClone(journal.accepted?.acceptance ?? null), event });
  async function install(acceptance) {
    const pending = journal.pending;
    if (!pending) throw new Error('Account actor has no pending successor');
    await verifyAccountAcceptance(acceptance, operatorPublicKey, pending.request);
    const next = await restore(pending.checkpoint, acceptance.statement);
    await save({ ...journal, accepted: { acceptance: structuredClone(acceptance), checkpoint: pending.checkpoint }, pending: null });
    state = next; return receipt(pending.event);
  }
  async function applyPending() {
    const current = await identity();
    return install(await client.apply({ ...current, request: journal.pending.request }));
  }
  async function status(requestId, expiresAt) {
    const current = await identity(), issuedAt = now();
    const request = await client.prepareStatus({ community, owner, chatPublicKey: current.grant.chatPublicKey,
      issuedAt, expiresAt, requestId, challenge: random() });
    return client.status({ ...current, request });
  }
  function matchesCurrent(acceptance) {
    if (!journal.accepted) return acceptance === null;
    if (!acceptance) return false;
    const retained = journal.accepted.acceptance;
    return equal(acceptance.requestDigest, retained.requestDigest)
      && equal(acceptance.statement.nextState, retained.statement.nextState)
      && acceptance.statement.nextVersion === retained.statement.nextVersion;
  }
  async function current(expiresAt) {
    available();
    const observed = await status(null, expiresAt);
    if (!matchesCurrent(observed.acceptance)) {
      blocked = true; throw new Error('Account actor lacks the current accepted private opening');
    }
    return structuredClone(observed.acceptance);
  }
  async function transition(action, input, expiresAt) {
    available();
    const observed = now();
    // Outgoing lease time was agreed through the authenticated cmsg context
    // before network/prover latency. The ledger still requires this original
    // statement's live slot, proof horizon and request authorization at commit.
    const at = action === 'reserve' && input.role === 0 && input.openedAt !== undefined
      ? Number(input.openedAt) : observed;
    if (!Number.isSafeInteger(at) || at <= 0 || at > observed) throw new Error('Account actor proof time');
    let candidate;
    if (action === 'genesis') {
      if (state) throw new Error('Account actor already has accepted genesis');
      candidate = await AccountWitness.genesis({ hashes: runtime.hashes, community, policy, checkpoint: enrollment,
        ownerIndex, ownerSecret, now: at });
    } else {
      if (!state) throw new Error('Account actor requires accepted genesis');
      const witness = await state.withPolicy(policy);
      if (action === 'reserve') candidate = await witness.reserve({ ...input, now: at });
      else if (action === 'settle') candidate = await witness.settle(input.event, input.resolution,
        input.acknowledgment, at, input.peerEnrollment, input.receiptOwnerEnrollment);
      else if (action === 'refill') candidate = await witness.refill(at);
      else candidate = await witness[action](input.event, at);
    }
    const record = await runtime.prove(candidate), currentIdentity = await identity();
    const request = await client.prepareApply({ record, chatPublicKey: currentIdentity.grant.chatPublicKey, expiresAt });
    const event = candidate.event?.toString() ?? input.event?.toString() ?? null;
    const checkpoint = hex(candidate.next.exportCheckpoint(checkpointLimits));
    await save({ ...journal, pending: { request, checkpoint, event } });
    return applyPending();
  }
  await reload();
  const actor = {
    accepted: () => structuredClone(journal?.accepted?.acceptance ?? null),
    slots: () => state ? Array.from(state.slots, ([event, slot]) => ({ event, peer: Array.from(slot.peer),
      role: slot.role, phase: slot.phase, openedAt: Number(slot.admittedAt), expiresAt: Number(slot.expiresAt) })) : [],
    reservation: input => {
      available();
      const peer = byte32(input.peer), nonce = byte32(input.nonce), group = byte32(input.group), contactPolicy = byte32(input.contactPolicy);
      if (![0, 1].includes(input.role) || !Number.isSafeInteger(input.openedAt) || !Number.isSafeInteger(input.expiresAt)) {
        throw new Error('Account reservation lookup');
      }
      for (const [event, slot] of state?.slots ?? []) {
        if (hex(slot.peer) !== hex(peer) || hex(slot.nonce) !== hex(nonce)) continue;
        if (slot.role !== input.role || hex(slot.group) !== hex(group) || hex(slot.contactPolicy) !== hex(contactPolicy)
            || slot.admittedAt !== BigInt(input.openedAt) || slot.expiresAt !== BigInt(input.expiresAt)) {
          throw new Error('Retained account reservation context differs');
        }
        // These are retained reservation authorities, not a lookup into the
        // current enrollment. A renewed roster may change both leaves while
        // an accepted obligation must continue to bind its original slot.
        return { event, phase: slot.phase,
          ownerAuthority: Array.from(fieldBytes(slot.ownerAuthority)),
          peerAuthority: Array.from(fieldBytes(slot.peerAuthority)) };
      }
      return null;
    },
    settlementAuthorities: event => {
      const slot = state?.slots.get(BigInt(event).toString());
      if (!slot) throw new Error('Unknown private account event');
      return { role: slot.role, owner: Array.from(owner), peer: Array.from(slot.peer),
        ownerDelegationDigest: Array.from(slot.ownerEnrollment.delegationDigest),
        peerDelegationDigest: Array.from(slot.peerEnrollment.delegationDigest) };
    },
    peerIndex: member => {
      const id = typeof member === 'string' ? decode(member) : byte32(member);
      const index = enrollment.entries.findIndex(entry => hex(entry.member) === hex(id));
      if (index < 0) throw new Error('Peer is absent from verified enrollment'); return index;
    },
    genesis: ({ expiresAt }) => exclusive(() => transition('genesis', {}, expiresAt)),
    reserve: (input, { expiresAt }) => { const value = structuredClone(input); return exclusive(() => transition('reserve', value, expiresAt)); },
    settle: (input, { expiresAt }) => { const value = structuredClone(input); return exclusive(() => transition('settle', value, expiresAt)); },
    refill: ({ expiresAt }) => exclusive(() => transition('refill', {}, expiresAt)),
    current: ({ expiresAt }) => exclusive(() => current(expiresAt)),
    withEnrollment: (checkpoint, expectedRoot) => {
      const nextEnrollment = copyEnrollmentCheckpoint(checkpoint), nextRoot = byte32(expectedRoot);
      return exclusive(async () => {
        if (blocked || store.uncertain || nextEnrollment.root !== enrollmentRoot(nextRoot)) throw new Error('Account enrollment refresh');
        const index = nextEnrollment.entries.findIndex(entry => hex(entry.member) === hex(owner));
        if (index < 0 || hex(await runtime.hashes.secretHash(community, ownerSecret)) !== hex(nextEnrollment.entries[index].secretHash)) {
          throw new Error('Account enrollment changed registered owner secret');
        }
        await verifyEnrollmentPath(nextEnrollment.entries[index], community, nextEnrollment.root, runtime.hashes);
        const refreshed = state ? await state.withEnrollment({ enrollment: nextEnrollment, expectedRoot: nextRoot }) : null;
        const accepted = refreshed ? { acceptance: journal.accepted.acceptance,
          checkpoint: hex(refreshed.exportCheckpoint(checkpointLimits)) } : null;
        // Pending signed bytes retain their original root and are recovered
        // exactly; refreshing membership never invents an accepted successor.
        await save({ ...journal, accepted });
        enrollment = nextEnrollment; root = nextRoot; ownerIndex = index; state = refreshed;
      });
    },
    recover: ({ expiresAt }) => exclusive(async () => {
      await reload();
      if (!journal.pending) return { acceptance: await current(expiresAt), event: null };
      try { return await applyPending(); }
      catch (error) { if (blocked || store.uncertain) throw error; }
      const pending = journal.pending;
      const observed = await status(Uint8Array.from(pending.request.requestId), expiresAt);
      if (observed.acceptance) return install(observed.acceptance);
      if (observed.observedAt < pending.request.expiresAt) throw new Error('Account request may still commit; retain exact pending state');
      const latest = await status(null, expiresAt);
      if (!matchesCurrent(latest.acceptance)) {
        blocked = true; throw new Error('Account actor lacks the current accepted private opening');
      }
      await save({ ...journal, pending: null });
      return receipt(null);
    }),
    provePeer: (event, context, { expiresAt }) => {
      const trusted = structuredClone(context), selected = BigInt(event);
      return exclusive(async () => {
        await current(expiresAt);
        if (!state) throw new Error('Account actor requires accepted state');
        return runtime.provePeer({ state, event: selected, accountAcceptance: journal.accepted.acceptance, context: trusted });
      });
    },
    verifyPeer: (record, context, { own, expiresAt }) => {
      const presentation = structuredClone(record), trusted = structuredClone(context);
      return exclusive(async () => {
        available();
        if (typeof own !== 'boolean') throw new Error('Explicit peer verification role required');
        if (!exact(trusted, ['now', 'expected', 'accountPolicy', 'enrollmentRoot', 'authorityExpiresAt'])
            || !Number.isSafeInteger(trusted.authorityExpiresAt) || trusted.authorityExpiresAt <= trusted.now
            || !equal(trusted.enrollmentRoot, Array.from(root))) throw new Error('Independently verified peer authority context required');
        if (own) {
          await current(expiresAt);
          if (!state || presentation.statement.stateVersion !== Number(state.version)
              || hex(Uint8Array.from(presentation.statement.stateCommitment)) !== state.commitment.toString(16).padStart(64, '0')
              || !equal(presentation.statement.owner, Array.from(owner))) throw new Error('Peer presentation is not current own state');
        }
        const verified = await runtime.verifyPeer(presentation, trusted);
        const validUntil = Math.min(trusted.accountPolicy.policyValidUntil,
          trusted.expected.expiresAt, trusted.authorityExpiresAt);
        if (now() >= validUntil) throw new Error('Peer release authority expired during verification');
        // cmsg VerifiedReservation is an exact struct: never forward metadata,
        // the account certificate, or arbitrary presentation envelope fields.
        const result = Object.fromEntries(STATEMENT_KEYS.map(key => [key, verified.statement[key]]));
        result.validUntil = validUntil;
        return JSON.stringify(result);
      });
    },
    close: () => exclusive(async () => {
      closed = true; blocked = true; ownerSecret.fill(0); state = null; journal = null;
    }),
  };
  for (const action of ['activate', 'cancel', 'expire']) {
    actor[action] = (event, { expiresAt }) => { const value = BigInt(event); return exclusive(() => transition(action, { event: value }, expiresAt)); };
  }
  return Object.freeze(actor);
}
