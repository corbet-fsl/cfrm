// Encoding and authenticated-map witnesses around pinned BB Poseidon2.
// No permutation, sponge, signature or proof verifier is implemented here.
import { be, cat, hex, unhex, sha, memberBytes } from '../common.mjs';
import { fieldBytes, fieldValue, limbs32, hashesFor, POSEIDON_SCHEME } from '../hashes.mjs';

export const ACCOUNT_MODE = 'account-state-v2';
export const ACCOUNT_DOMAIN = 0x6366726d2e6163636f756e742d73746174652e7632n;
export const POLICY_KEYS = ['initialCredit','maximumAvailable','outgoingReservation','incomingReservation',
  'policyRevision','policyValidFrom','policyValidUntil','newcomerPeriod','rateWindow','newcomerAdmissions',
  'maximumAdmissions','refillPeriod','refillUnits','abandonAfter'];
export const DEPTH = 32;
export const LIMIT = 1n << 32n;
export const SAFE = 9007199254740991n;
const utf8 = text => new TextEncoder().encode(text);
export const integer = (value, bits) => {
  if (typeof value === 'number' && !Number.isSafeInteger(value)) throw new Error('Unsafe integer');
  const n = BigInt(value);
  if (n < 0n || n >= 1n << BigInt(bits)) throw new Error('Integer bound');
  return n;
};
const time = value => { const n = integer(value, 64); if (n > SAFE) throw new Error('Unsafe time/version'); return n; };
const bytes32 = value => {
  if (!(value instanceof Uint8Array) || value.length !== 32) throw new Error('Expected bytes32');
  return value;
};

export function policyBytes(community, policy) {
  const p = policy;
  const initial = integer(p.initialCredit, 32), maximum = integer(p.maximumAvailable, 32);
  const outgoing = integer(p.outgoingReservation, 32), incoming = integer(p.incomingReservation, 32);
  const revision = time(p.policyRevision), from = time(p.policyValidFrom), until = time(p.policyValidUntil);
  const newcomer = time(p.newcomerPeriod), window = time(p.rateWindow), refill = time(p.refillPeriod), abandon = time(p.abandonAfter);
  const newcomerAdmissions = integer(p.newcomerAdmissions, 32), maximumAdmissions = integer(p.maximumAdmissions, 32);
  const units = integer(p.refillUnits, 32);
  if (maximum === 0n || initial > maximum || outgoing === 0n || incoming === 0n
      || outgoing > initial || incoming > initial || revision === 0n || from === 0n || until <= from
      || newcomer === 0n || window === 0n || refill === 0n || abandon < window
      || newcomerAdmissions === 0n || newcomerAdmissions > maximumAdmissions || units === 0n || units > initial) throw new Error('Invalid explicit account policy');
  return cat(utf8('cfrm.account-policy.v2\0'), bytes32(community),
    ...[initial, maximum, outgoing, incoming].map(n => be(n, 4)),
    ...[revision, from, until, newcomer, window].map(n => be(n, 8)),
    be(newcomerAdmissions, 4), be(maximumAdmissions, 4), be(refill, 8), be(units, 4), be(abandon, 8), new Uint8Array([DEPTH]));
}
export const policyDigest = (community, policy) => sha(policyBytes(community, policy));
export const statePolicyDigest = (community, policy) => {
  const full = policyBytes(community, policy);
  return sha(cat(utf8('cfrm.account-state-policy.v1\0'), bytes32(community), full.slice(55, 131), new Uint8Array([DEPTH])));
};

export function accountHashes(api) {
  const legacy = hashesFor(POSEIDON_SCHEME, async () => api);
  const hash = async (tag, values) => fieldValue((await api.poseidon2Hash({
    inputs: [ACCOUNT_DOMAIN, BigInt(tag), ...values].map(fieldBytes),
  })).hash);
  return {
    hash,
    secretHash: legacy.secretHash,
    marker: async (...args) => fieldValue(await legacy.marker(...args)),
    enrollmentNode: async (left, right) => fieldValue(await legacy.node(fieldBytes(left), fieldBytes(right))),
    node: (left, right) => hash(13, [left, right]),
    mapLeaf: value => { if (value.length !== 4) throw new Error('Map leaf arity'); return hash(12, value); },
    pairKey: (community, owner, secret, peer) => hash(5,
      [...limbs32(community), ...limbs32(secret), ...limbs32(owner), ...limbs32(peer)]),
    enrollment: (community, member, entry) => hash(1,
      [...limbs32(community), ...limbs32(member), ...limbs32(entry.key.slice(0, 32)),
        ...limbs32(entry.key.slice(32)), fieldValue(entry.secretHash), time(entry.start), time(entry.end),
        ...limbs32(entry.delegationDigest)]),
    state: (community, owner, policy, secretHash, version, state) => hash(3,
      [...limbs32(community), ...limbs32(owner), ...limbs32(policy), fieldValue(secretHash), time(version),
        integer(state.available, 32), integer(state.reserved, 128),
        state.outgoingRoot, integer(state.outgoingCount, 64), state.incomingRoot, integer(state.incomingCount, 64),
        state.pairRoot, integer(state.pairCount, 64), time(state.frontier), time(state.createdAt),
        time(state.admissionEpoch), integer(state.admissions, 32), ...limbs32(state.blind)]),
    obligation: (event, slot, phase) => hash(4,
      [event, integer(slot.role, 8), ...limbs32(slot.peer), ...limbs32(slot.nonce), ...limbs32(slot.group),
        ...limbs32(slot.contactPolicy), integer(slot.amount, 32), integer(phase, 8),
        time(slot.admittedAt), time(slot.expiresAt), slot.peerAuthority, slot.ownerAuthority]),
  };
}

// Sparse backing store for fixed-position Merkle paths. Missing leaf = zero;
// internal empty hashes depend on level. Never allocate 2^32 leaves.
export class SparseTree {
  constructor(node, empty) { this.node = node; this.empty = empty; this.nodes = new Map(); }
  static async create(node) {
    const empty = [0n];
    for (let level = 0; level < DEPTH; level++) empty.push(await node(empty[level], empty[level]));
    return new SparseTree(node, empty);
  }
  clone() { const copy = new SparseTree(this.node, this.empty); copy.nodes = new Map(this.nodes); return copy; }
  at(level, index) { return this.nodes.get(`${level}:${index}`) ?? this.empty[level]; }
  get root() { return this.at(DEPTH, 0n); }
  path(index) {
    let position = integer(index, 32); const result = [];
    for (let level = 0; level < DEPTH; level++) { result.push(this.at(level, position ^ 1n)); position >>= 1n; }
    return result;
  }
  async set(index, value) {
    let position = integer(index, 32); fieldBytes(value);
    this.nodes.set(`0:${position}`, value);
    for (let level = 0; level < DEPTH; level++) {
      const left = position & ~1n;
      const parent = await this.node(this.at(level, left), this.at(level, left + 1n));
      position >>= 1n; this.nodes.set(`${level + 1}:${position}`, parent);
    }
  }
}

export class IndexedMap {
  constructor(hashes, tree) { this.hashes = hashes; this.tree = tree; this.leaves = new Map(); this.count = 1n; }
  static async create(hashes) {
    const value = new IndexedMap(hashes, await SparseTree.create(hashes.node));
    value.leaves.set(0n, [0n, 0n, 0n, 0n]);
    await value.tree.set(0n, await hashes.mapLeaf([0n, 0n, 0n, 0n]));
    return value;
  }
  clone() {
    const copy = new IndexedMap(this.hashes, this.tree.clone());
    copy.leaves = new Map(Array.from(this.leaves, ([i, leaf]) => [i, [...leaf]]));
    copy.count = this.count; return copy;
  }
  get root() { return this.tree.root; }
  find(key) { return Array.from(this.leaves).find(([, leaf]) => leaf[0] === key); }
  witness(index) {
    const leaf = this.leaves.get(index); if (!leaf) throw new Error('Missing map leaf');
    return { leaf: [...leaf], index, path: this.tree.path(index), append_path: Array(DEPTH).fill(0n) };
  }
  absence(key) {
    fieldBytes(key); if (key === 0n || this.find(key)) throw new Error('Map key already present or sentinel');
    const selected = Array.from(this.leaves).find(([, leaf]) => leaf[0] < key && (leaf[3] === 0n || key < leaf[3]));
    if (!selected) throw new Error('No authenticated ordered gap');
    return this.witness(selected[0]);
  }
  async insert(key, payload) {
    if (this.count >= LIMIT) throw new Error('Indexed map exhausted');
    const witness = this.absence(key), next = this.clone(), low = witness.leaf;
    const updated = [low[0], low[1], this.count, key];
    next.leaves.set(witness.index, updated);
    await next.tree.set(witness.index, await this.hashes.mapLeaf(updated));
    witness.append_path = next.tree.path(this.count); // AFTER predecessor update.
    const added = [key, payload, low[2], low[3]];
    next.leaves.set(this.count, added);
    await next.tree.set(this.count, await this.hashes.mapLeaf(added));
    next.count += 1n;
    return { witness, next };
  }
  async update(key, payload) {
    const found = this.find(key); if (!found || key === 0n) throw new Error('Unknown map key');
    const witness = this.witness(found[0]), next = this.clone();
    const updated = [key, payload, witness.leaf[2], witness.leaf[3]];
    next.leaves.set(found[0], updated);
    await next.tree.set(found[0], await this.hashes.mapLeaf(updated));
    return { witness, next };
  }
}

export async function checkpointFromVerified(community, entries, hashes) {
  if (!Array.isArray(entries) || entries.length === 0 || entries.length > 65536) throw new Error('Enrollment checkpoint bound');
  const seen = new Set(), normalized = [], tree = await SparseTree.create(hashes.enrollmentNode);
  for (let index = 0; index < entries.length; index++) {
    const entry = entries[index];
    if (seen.has(entry.memberId)) throw new Error('Duplicate permanent enrollment'); seen.add(entry.memberId);
    const value = { member: memberBytes(entry.memberId), key: unhex(entry.accountKey), secretHash: unhex(entry.secretHash),
      start: time(entry.issuedAt), end: time(entry.expiresAt), delegationDigest: unhex(entry.delegationDigest), index: BigInt(index) };
    if (value.key.length !== 64 || value.start === 0n || value.end <= value.start) throw new Error('Enrollment key/time');
    fieldValue(value.secretHash); bytes32(value.delegationDigest);
    if (hex(value.delegationDigest) === '00'.repeat(32)) throw new Error('Missing verified delegation digest');
    value.leaf = await hashes.enrollment(community, value.member, value);
    normalized.push(value); await tree.set(BigInt(index), value.leaf);
  }
  for (const value of normalized) value.path = tree.path(value.index);
  // Caller must obtain entries from its independent Rust verification boundary.
  return { root: tree.root, entries: normalized };
}

export const receiptBytes = (community, responder, peer, slot, delegation, resolution) => cat(
  utf8('cmsg.accounting-receipt.v1\0'), community, responder, peer, peer, slot.nonce, slot.group,
  delegation, slot.contactPolicy, resolution.historyDigest, resolution.ed25519ReceiptDigest,
  new Uint8Array([Number(resolution.kind), 1]), be(time(resolution.issuedAt), 8));
export const receiptDigest = (message, signature) => sha(cat(utf8('cmsg.accounting-receipt-digest.v1\0'), message, signature));
export const ackBytes = (community, initiator, recipient, slot, answerDigest, delegation, issuedAt) => cat(
  utf8('cmsg.accounting-ack.v1\0'), community, initiator, recipient, slot.nonce, slot.group,
  answerDigest, delegation, be(time(issuedAt), 8));

// Recursive conversion retains every byte array and checked integer exactly.
export function noirInput(value) {
  if (value instanceof Uint8Array) return Array.from(value);
  if (typeof value === 'bigint' || typeof value === 'number') return String(value);
  if (Array.isArray(value)) return value.map(noirInput);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, noirInput(v)]));
  return value;
}
