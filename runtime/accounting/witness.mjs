import { fieldBytes, fieldValue } from './primitives.mjs';
import { cat, be, random, zeros } from './encoding.mjs';
import { IndexedMap, policyDigest, statePolicyDigest, integer, SAFE, POLICY_KEYS } from './hashes.mjs';
import { exportWitnessCheckpoint, restoreWitnessCheckpoint } from './checkpoint.mjs';
import { refreshEnrollment, verifyEnrollmentPath, verifyReceiptEnrollment } from './enrollment.mjs';

const POLICY_WIRE = [
  ['initialCredit','initial_credit',32], ['maximumAvailable','maximum_available',32],
  ['outgoingReservation','outgoing_reservation',32], ['incomingReservation','incoming_reservation',32],
  ['policyRevision','policy_revision',64], ['policyValidFrom','policy_valid_from',64], ['policyValidUntil','policy_valid_until',64],
  ['newcomerPeriod','newcomer_period',64], ['rateWindow','rate_window',64],
  ['newcomerAdmissions','newcomer_admissions',32], ['maximumAdmissions','maximum_admissions',32],
  ['refillPeriod','refill_period',64], ['refillUnits','refill_units',32], ['abandonAfter','abandon_after',64],
];
export const PUBLIC_INPUT_COUNT = 243;
export function validityHorizon(now, policy) {
  const at = BigInt(now), window = BigInt(policy.rateWindow), end = (at / window + 1n) * window;
  return end < BigInt(policy.policyValidUntil) ? end : BigInt(policy.policyValidUntil);
}

const emptyMapWitness = () => ({ leaf: [0n, 0n, 0n, 0n], index: 0n,
  path: Array(32).fill(0n), append_path: Array(32).fill(0n) });
const enrollmentInput = entry => ({ key: entry.key, secret_hash: entry.secretHash, start: entry.start,
  end: entry.end, delegation_digest: entry.delegationDigest, path: entry.path, index: entry.index });
const openingInput = s => ({ available: s.available, reserved: s.reserved,
  outgoing_root: s.outgoingRoot, outgoing_count: s.outgoingCount,
  incoming_root: s.incomingRoot, incoming_count: s.incomingCount,
  pair_root: s.pairRoot, pair_count: s.pairCount, frontier: s.frontier,
  created_at: s.createdAt, admission_epoch: s.admissionEpoch, admissions: s.admissions, blind: s.blind });
const slotInput = s => ({ role: s.role, peer: s.peer, nonce: s.nonce, group: s.group,
  contact_policy: s.contactPolicy, amount: s.amount, phase: s.phase,
  admitted_at: s.admittedAt, expires_at: s.expiresAt, peer_authority: s.peerAuthority, owner_authority: s.ownerAuthority });
const resolutionInput = r => ({ kind: r.kind, issued_at: r.issuedAt, history_digest: r.historyDigest,
  ed25519_receipt_digest: r.ed25519ReceiptDigest, signature: r.signature });
const emptyResolution = now => ({ kind: 2, issuedAt: now, historyDigest: zeros(), ed25519ReceiptDigest: zeros(), signature: new Uint8Array(64) });
const policyInput = p => Object.fromEntries(POLICY_WIRE.map(([key, wire]) => [wire, p[key]]));

export function statementFromInput(input) {
  return { protocolVersion: 2, community: Array.from(input.community), owner: Array.from(input.owner),
    policyDigest: Array.from(input.policy_digest), enrollmentRoot: Array.from(input.enrollment_root), now: Number(input.now), validUntil: Number(input.valid_until),
    genesis: input.genesis, previousVersion: Number(input.previous_version), nextVersion: Number(input.next_version),
    previousState: Array.from(input.previous_state), nextState: Array.from(input.next_state), settlementMarker: Array.from(input.settlement_marker),
    policy: Object.fromEntries(POLICY_WIRE.map(([key, wire]) => [key, Number(input[wire])])) };
}

export function publicInputValues(statement) {
  const bytes = value => {
    if (!Array.isArray(value) || value.length !== 32 || value.some(v => !Number.isInteger(v) || v < 0 || v > 255)) throw new Error('Noncanonical statement bytes');
    return value.map(BigInt);
  };
  const safe = value => { const n = integer(value, 64); if (n > SAFE) throw new Error('Statement integer'); return n; };
  if (statement.protocolVersion !== 2 || typeof statement.genesis !== 'boolean') throw new Error('Statement version/boolean');
  const p = statement.policy;
  if (!p || Object.keys(p).length !== POLICY_KEYS.length || !POLICY_KEYS.every(key => Object.hasOwn(p, key))) throw new Error('Exact v2 policy required');
  return [...bytes(statement.community), ...bytes(statement.owner), ...bytes(statement.policyDigest), ...bytes(statement.enrollmentRoot),
    safe(statement.now), safe(statement.validUntil), statement.genesis ? 1n : 0n, safe(statement.previousVersion), safe(statement.nextVersion),
    ...bytes(statement.previousState), ...bytes(statement.nextState), ...bytes(statement.settlementMarker),
    ...POLICY_WIRE.map(([key, , bits]) => bits === 64 ? safe(p[key]) : integer(p[key], bits))];
}

export function statementBytes(statement) {
  publicInputValues(statement); // Validate fixed byte/integer widths first.
  const s = statement, p = s.policy;
  return cat(new TextEncoder().encode('cfrm.account.statement.v2\0'), be(s.protocolVersion, 4),
    ...[s.community, s.owner, s.policyDigest, s.enrollmentRoot].map(value => Uint8Array.from(value)),
    be(s.now, 8), be(s.validUntil, 8), new Uint8Array([s.genesis ? 1 : 0]), be(s.previousVersion, 8), be(s.nextVersion, 8),
    ...[s.previousState, s.nextState, s.settlementMarker].map(value => Uint8Array.from(value)),
    ...POLICY_WIRE.map(([key, , bits]) => be(p[key], bits / 8)));
}

export async function validateStatement(statement) {
  const keys = ['protocolVersion','community','owner','policyDigest','enrollmentRoot','now','validUntil','genesis',
    'previousVersion','nextVersion','previousState','nextState','settlementMarker','policy'];
  const exact = (value, names) => value && !Array.isArray(value) && Object.keys(value).length === names.length
    && names.every(key => Object.hasOwn(value, key));
  const equal = (a, b) => a.length === b.length && a.every((value, index) => value === b[index]);
  if (!exact(statement, keys) || !exact(statement.policy, POLICY_KEYS)) throw new Error('Exact account statement required');
  const inputs = publicInputValues(statement), s = statement;
  if (inputs.length !== PUBLIC_INPUT_COUNT || BigInt(s.validUntil) !== validityHorizon(s.now, s.policy)
      || s.now <= 0 || s.now < s.policy.policyValidFrom || s.now >= s.policy.policyValidUntil
      || !equal(s.policyDigest, await policyDigest(Uint8Array.from(s.community), s.policy))) throw new Error('Account policy/time encoding');
  for (const key of ['enrollmentRoot','previousState','nextState','settlementMarker']) fieldValue(Uint8Array.from(s[key]));
  if (!s.enrollmentRoot.some(Boolean) || !s.nextState.some(Boolean)
      || (s.genesis ? s.previousVersion !== 0 || s.nextVersion !== 0 || s.previousState.some(Boolean) || s.settlementMarker.some(Boolean)
        : s.nextVersion !== s.previousVersion + 1 || !s.previousState.some(Boolean))) throw new Error('Account state/version shape');
  return inputs;
}

// Local witness state. It is never accepted by an operator without a real proof
// plus a durable accepted-state comparison. Returned candidates do not mutate it.
export class AccountWitness {
  /** Private UTF-8 JSON bytes for the member's encrypted wallet, never a server. */
  exportCheckpoint(limits) { return exportWitnessCheckpoint(this, limits); }

  /** The embedding independently authenticates expectedStatement and enrollment. */
  static async restoreCheckpoint(options) {
    const value = Object.assign(new AccountWitness(), await restoreWitnessCheckpoint(options, validateStatement));
    value.at(value.now);
    return value;
  }

  static async genesis({ hashes, community, policy, checkpoint, ownerIndex, ownerSecret, now }) {
    const value = new AccountWitness();
    Object.assign(value, { hashes, community, policy, checkpoint, ownerIndex, ownerSecret, now: BigInt(now), version: 0n });
    value.owner = checkpoint.entries[ownerIndex];
    value.policyHash = await policyDigest(community, policy);
    value.statePolicyHash = await statePolicyDigest(community, policy);
    if (fieldValue(await hashes.secretHash(community, ownerSecret)) !== fieldValue(value.owner.secretHash)) throw new Error('Owner secret differs from verified enrollment');
    const empty = await IndexedMap.create(hashes);
    value.outgoing = empty; value.incoming = empty.clone(); value.pairs = empty.clone();
    value.slots = new Map();
    value.opening = { available: BigInt(policy.initialCredit), reserved: 0n,
      outgoingRoot: empty.root, outgoingCount: 1n, incomingRoot: empty.root, incomingCount: 1n,
      pairRoot: empty.root, pairCount: 1n, frontier: validityHorizon(now, policy), createdAt: validityHorizon(now, policy),
      admissionEpoch: BigInt(now) / BigInt(policy.rateWindow), admissions: 0n, blind: random() };
    value.commitment = await value.commit(value.opening, 0n);
    const input = value.input(value.opening.blind, now);
    Object.assign(input, { genesis: true, previous_state: zeros(), next_state: fieldBytes(value.commitment),
      previous_version: 0n, next_version: 0n });
    return { input, statement: statementFromInput(input), next: value };
  }
  async commit(opening, version) {
    return this.hashes.state(this.community, this.owner.member, this.statePolicyHash, this.owner.secretHash, version, opening);
  }
  async withPolicy(policy) {
    const stable = await statePolicyDigest(this.community, policy);
    if (!stable.every((value, index) => value === this.statePolicyHash[index])) throw new Error('Immutable account policy changed');
    const copy = this.clone(); copy.policy = structuredClone(policy);
    copy.policyHash = await policyDigest(this.community, policy);
    // This only prepares a witness. The host independently requires its exact
    // current durable policy; a browser cannot authorize its own tuning.
    return copy;
  }
  /** Current independently admitted roster; preserves the accepted private state. */
  async withEnrollment(options) {
    const current = await refreshEnrollment(this, options), copy = this.clone();
    Object.assign(copy, current);
    return copy;
  }
  clone() {
    const copy = new AccountWitness(); Object.assign(copy, this);
    copy.slots = new Map(Array.from(this.slots, ([k, v]) => [k, structuredClone(v)]));
    copy.opening = structuredClone(this.opening); return copy;
  }
  input(newBlind, now) {
    return { community: this.community, owner: this.owner.member, policy_digest: this.policyHash,
      enrollment_root: fieldBytes(this.checkpoint.root), now: BigInt(now), valid_until: validityHorizon(now, this.policy), genesis: false,
      previous_version: this.version, next_version: this.version + 1n,
      previous_state: fieldBytes(this.commitment), next_state: zeros(), settlement_marker: zeros(), ...policyInput(this.policy),
      owner_secret: this.ownerSecret, owner_enrollment: enrollmentInput(this.owner), peer_enrollment: enrollmentInput(this.owner),
      receipt_owner_enrollment: enrollmentInput(this.owner),
      old: openingInput(this.opening), new_blind: newBlind, action: 1,
      slot: slotInput({ role: 0, peer: zeros(), nonce: zeros(), group: zeros(), contactPolicy: zeros(), amount: 0,
        phase: 1, admittedAt: BigInt(now), expiresAt: BigInt(now), peerAuthority: 0n, ownerAuthority: 0n }),
      own_map: emptyMapWitness(), opposite_map: emptyMapWitness(), pair_map: emptyMapWitness(), pair_exists: false,
      resolution: resolutionInput(emptyResolution(now)), acknowledgment: { issued_at: BigInt(now), signature: new Uint8Array(64) } };
  }
  async finish(next, input) {
    next.now = BigInt(input.now);
    next.version = this.version + 1n;
    next.opening.outgoingRoot = next.outgoing.root; next.opening.outgoingCount = next.outgoing.count;
    next.opening.incomingRoot = next.incoming.root; next.opening.incomingCount = next.incoming.count;
    next.opening.pairRoot = next.pairs.root; next.opening.pairCount = next.pairs.count;
    next.opening.blind = input.new_blind;
    next.commitment = await next.commit(next.opening, next.version);
    input.next_state = fieldBytes(next.commitment);
    return { input, statement: statementFromInput(input), next };
  }
  at(now) {
    const at = integer(now, 64), p = this.policy, o = this.opening;
    if (at > SAFE || o.createdAt === 0n || o.createdAt > o.frontier || o.frontier > validityHorizon(now, p)
        || at < BigInt(p.policyValidFrom) || at >= BigInt(p.policyValidUntil)) throw new Error('Account time/policy');
    const mature = at >= o.createdAt && at - o.createdAt >= BigInt(p.newcomerPeriod);
    const capacity = BigInt(mature ? p.maximumAvailable : p.initialCredit);
    if (o.available + o.reserved > capacity) throw new Error('Account total capacity');
    return { now: at, capacity, admissionLimit: BigInt(mature ? p.maximumAdmissions : p.newcomerAdmissions),
      epoch: at / BigInt(p.rateWindow) };
  }
  async reserve({ peerIndex, role, nonce, group, contactPolicy, openedAt, expiresAt, now = this.now }) {
    if (role !== 0 && role !== 1) throw new Error('Reservation role');
    const at = this.at(now);
    if (role === 1 && (openedAt === undefined || expiresAt === undefined)) throw new Error('Incoming reservation requires the authenticated common lease');
    const opened = integer(openedAt ?? at.now, 64);
    const expiry = integer(expiresAt ?? (at.now + BigInt(this.policy.abandonAfter)), 64);
    if (opened === 0n || opened > at.now || expiry <= at.now || expiry >= BigInt(this.policy.policyValidUntil)
        || validityHorizon(now, this.policy) > expiry
        || (role === 0 && (opened !== at.now || expiry !== at.now + BigInt(this.policy.abandonAfter)))) throw new Error('Reservation lease');
    const admissions = this.opening.admissionEpoch === at.epoch ? this.opening.admissions + 1n : 1n;
    if (admissions > at.admissionLimit) throw new Error('Shared admission rate exhausted');
    const peer = this.checkpoint.entries[peerIndex];
    if (!peer || peer === this.owner) throw new Error('Current peer enrollment required');
    await verifyEnrollmentPath(peer, this.community, this.checkpoint.root, this.hashes);
    const event = await this.hashes.marker(this.community, this.ownerSecret, this.owner.member, peer.member, nonce);
    const pair = await this.hashes.pairKey(this.community, this.owner.member, this.ownerSecret, peer.member);
    const amount = BigInt(role === 0 ? this.policy.outgoingReservation : this.policy.incomingReservation);
    if (this.opening.available < amount) throw new Error('Insufficient shared available capacity');
    const slot = { role, peer: peer.member, nonce, group, contactPolicy, amount, phase: 1,
      admittedAt: opened, expiresAt: expiry, peerAuthority: peer.leaf, ownerAuthority: this.owner.leaf,
      peerEnrollment: structuredClone(peer), ownerEnrollment: structuredClone(this.owner) };
    const own = role === 0 ? this.outgoing : this.incoming, opposite = role === 0 ? this.incoming : this.outgoing;
    const inserted = await own.insert(event, await this.hashes.obligation(event, slot, 1));
    const input = this.input(random(), now), next = this.clone();
    Object.assign(input, { action: 1, slot: slotInput(slot), peer_enrollment: enrollmentInput(peer),
      own_map: inserted.witness, opposite_map: opposite.absence(event) });
    const existing = this.pairs.find(pair);
    if (existing) { input.pair_exists = true; input.pair_map = this.pairs.witness(existing[0]); }
    else { const added = await this.pairs.insert(pair, 1n); input.pair_map = added.witness; next.pairs = added.next; }
    if (role === 0) next.outgoing = inserted.next; else next.incoming = inserted.next;
    next.opening.available -= amount; next.opening.reserved += amount;
    next.opening.admissionEpoch = at.epoch; next.opening.admissions = admissions;
    next.slots.set(event.toString(), slot);
    const result = await this.finish(next, input); result.event = event; return result;
  }
  async change(event, action, resolution, acknowledgment, now = this.now, peerEnrollment, receiptOwnerEnrollment) {
    const at = this.at(now);
    const oldSlot = this.slots.get(event.toString()); if (!oldSlot) throw new Error('Unknown private obligation');
    if (![2, 3, 4, 5].includes(action) || oldSlot.phase !== ([2, 4].includes(action) ? 1 : 2)) throw new Error('Invalid obligation phase');
    if (at.now < oldSlot.admittedAt) throw new Error('Future obligation');
    const expired = at.now >= oldSlot.expiresAt;
    const withinHorizon = validityHorizon(now, this.policy) <= oldSlot.expiresAt;
    if (action === 2 && (expired || !withinHorizon)) throw new Error('Activation lease expired');
    if (action === 5 && (oldSlot.role !== 0 || !expired)) throw new Error('Only expired outgoing obligations may retire');
    if (action === 3 && oldSlot.role === 0 && Number(resolution?.kind) !== 1) throw new Error('Outgoing Close cannot alter the fixed refund date');
    if (action === 3 && Number(resolution?.kind) === 1 && (expired || !withinHorizon)) throw new Error('Answer arrived after the common lease');
    const slot = structuredClone(oldSlot), next = this.clone(), input = this.input(random(), now);
    const peer = structuredClone(peerEnrollment ?? slot.peerEnrollment),
      receiptOwner = structuredClone(receiptOwnerEnrollment ?? slot.ownerEnrollment);
    if (action === 3) {
      if (slot.role === 0 || Number(resolution?.kind) === 1) {
        await verifyReceiptEnrollment(peer, this, slot.peer, slot.peerAuthority);
      }
      if (slot.role === 1) await verifyReceiptEnrollment(receiptOwner, this, this.owner.member, slot.ownerAuthority, true);
    }
    Object.assign(input, { action, slot: slotInput(slot),
      peer_enrollment: enrollmentInput(peer) });
    input.receipt_owner_enrollment = enrollmentInput(receiptOwner);
    const phase = action === 2 ? 2 : action === 4 ? 4 : action === 5 ? 5 : 3;
    const changed = await (slot.role === 0 ? this.outgoing : this.incoming).update(event,
      await this.hashes.obligation(event, slot, phase));
    input.own_map = changed.witness;
    if (slot.role === 0) next.outgoing = changed.next; else next.incoming = changed.next;
    slot.phase = phase; next.slots.set(event.toString(), slot);
    if (action === 3) {
      if (!resolution) throw new Error('Authenticated receipt required');
      input.resolution = resolutionInput(resolution);
      if (acknowledgment) input.acknowledgment = { issued_at: acknowledgment.issuedAt, signature: acknowledgment.signature };
      next.opening.available += slot.amount;
      next.opening.reserved -= slot.amount;
      input.settlement_marker = fieldBytes(event);
    } else if (action === 4 || action === 5) {
      next.opening.available += slot.amount;
      next.opening.reserved -= slot.amount;
      input.settlement_marker = fieldBytes(event);
    }
    return this.finish(next, input);
  }
  activate(event, now) { return this.change(event, 2, undefined, undefined, now); }
  settle(event, resolution, acknowledgment, now, peerEnrollment, receiptOwnerEnrollment) {
    return this.change(event, 3, resolution, acknowledgment, now, peerEnrollment, receiptOwnerEnrollment);
  }
  cancel(event, now) { return this.change(event, 4, undefined, undefined, now); }
  expire(event, now) { return this.change(event, 5, undefined, undefined, now); }
  async refill(now = this.now) {
    const at = this.at(now);
    if (at.now < this.opening.frontier || at.now - this.opening.frontier < BigInt(this.policy.refillPeriod)) throw new Error('Refill not due');
    const headroom = at.capacity - this.opening.available - this.opening.reserved;
    const units = BigInt(this.policy.refillUnits), issued = headroom < units ? headroom : units;
    const input = this.input(random(), now), next = this.clone(); input.action = 6;
    next.opening.available += issued; next.opening.frontier = validityHorizon(now, this.policy);
    return this.finish(next, input);
  }
}
