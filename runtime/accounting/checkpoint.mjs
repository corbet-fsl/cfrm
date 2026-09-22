// Persistence of existing witnesses, not a new account or proof protocol.
// Only an encrypted member wallet may store these private checkpoint bytes.
import { hex, unhex } from './encoding.mjs';
import { fieldBytes, fieldValue } from './primitives.mjs';
import { IndexedMap, SparseTree, integer, policyDigest, statePolicyDigest, SAFE } from './hashes.mjs';
import { checkEnrollmentShape, copyEnrollmentCheckpoint, enrollmentRoot, verifyEnrollmentLeaf, verifyEnrollmentPath } from './enrollment.mjs';

const TOP = ['version','community','owner','policyDigest','enrollmentRoot','now','accountVersion','commitment','opening','maps','slots'];
const OPENING = ['available','reserved','frontier','createdAt','admissionEpoch','admissions','blind'];
const SLOT = ['peer','nonce','group','contactPolicy','role','phase','amount','admittedAt','expiresAt','peerAuthority','ownerAuthority','peerEnrollment','ownerEnrollment'];
const ENROLLMENT = ['member','key','secretHash','start','end','delegationDigest','index','leaf','path'];
const MAPS = ['outgoing','incoming','pairs'];
const CEILINGS = { maxBytes: 16 * 1024 * 1024, maxMapEntries: 65536, maxSlots: 65535 };
const fail = () => { throw new Error('Invalid account checkpoint'); };
const exact = (value, keys) => {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== keys.length
      || !keys.every(key => Object.hasOwn(value, key))) fail();
};
function bounds(value) {
  exact(value, Object.keys(CEILINGS));
  for (const [key, maximum] of Object.entries(CEILINGS)) {
    if (!Number.isSafeInteger(value[key]) || value[key] < 1 || value[key] > maximum) fail();
  }
  return { ...value };
}
function bytes(value, length = 32) {
  if (!(value instanceof Uint8Array) || value.length !== length) fail();
  return hex(value);
}
function readBytes(value, length = 32) {
  if (typeof value !== 'string' || value.length !== length * 2 || !/^[0-9a-f]+$/.test(value)) fail();
  return unhex(value);
}
function decimal(value, bits) {
  if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]{0,77})$/.test(value)) fail();
  const result = BigInt(value);
  if (bits === undefined) fieldBytes(result); else integer(result, bits);
  return result;
}
function writeDecimal(value, bits) {
  if (typeof value !== 'bigint') fail();
  const result = value.toString(); decimal(result, bits); return result;
}
function readTime(value) {
  const result = decimal(value, 64); if (result > SAFE) fail(); return result;
}
function wireOpening(value) {
  return { available: writeDecimal(value.available, 32), reserved: writeDecimal(value.reserved, 128),
    frontier: writeDecimal(value.frontier, 64), createdAt: writeDecimal(value.createdAt, 64),
    admissionEpoch: writeDecimal(value.admissionEpoch, 64), admissions: writeDecimal(value.admissions, 32), blind: bytes(value.blind) };
}
function wireSlot(value) {
  return { peer: bytes(value.peer), nonce: bytes(value.nonce), group: bytes(value.group), contactPolicy: bytes(value.contactPolicy),
    role: value.role, phase: value.phase, amount: writeDecimal(value.amount, 32),
    admittedAt: writeDecimal(value.admittedAt, 64), expiresAt: writeDecimal(value.expiresAt, 64),
    peerAuthority: writeDecimal(value.peerAuthority), ownerAuthority: writeDecimal(value.ownerAuthority),
    peerEnrollment: wireEnrollment(value.peerEnrollment), ownerEnrollment: wireEnrollment(value.ownerEnrollment) };
}
function wireEnrollment(value) {
  checkEnrollmentShape(value);
  return { member: bytes(value.member), key: bytes(value.key, 64), secretHash: bytes(value.secretHash),
    start: writeDecimal(value.start, 64), end: writeDecimal(value.end, 64), delegationDigest: bytes(value.delegationDigest),
    index: writeDecimal(value.index, 32), leaf: writeDecimal(value.leaf), path: value.path.map(n => writeDecimal(n)) };
}
function readEnrollment(value) {
  exact(value, ENROLLMENT);
  if (!Array.isArray(value.path) || value.path.length !== 32) fail();
  const entry = { member: readBytes(value.member), key: readBytes(value.key, 64), secretHash: readBytes(value.secretHash),
    start: readTime(value.start), end: readTime(value.end), delegationDigest: readBytes(value.delegationDigest),
    index: decimal(value.index, 32), leaf: decimal(value.leaf), path: value.path.map(n => decimal(n)) };
  checkEnrollmentShape(entry); return entry;
}
function wireMap(value, limit) {
  if (!(value.leaves instanceof Map) || value.leaves.size < 1 || value.leaves.size > limit
      || value.count !== BigInt(value.leaves.size)) fail();
  return Array.from({ length: value.leaves.size }, (_, index) => {
    const leaf = value.leaves.get(BigInt(index));
    if (!Array.isArray(leaf) || leaf.length !== 4) fail();
    return leaf.map((entry, position) => writeDecimal(entry, position === 2 ? 32 : undefined));
  });
}

export function exportWitnessCheckpoint(value, limits) {
  const bound = bounds(limits);
  if (!(value.slots instanceof Map) || value.slots.size > bound.maxSlots) fail();
  const snapshot = { version: 1, community: bytes(value.community), owner: bytes(value.owner.member),
    policyDigest: bytes(value.policyHash), enrollmentRoot: bytes(fieldBytes(value.checkpoint.root)),
    now: writeDecimal(value.now, 64), accountVersion: writeDecimal(value.version, 64), commitment: bytes(fieldBytes(value.commitment)),
    opening: wireOpening(value.opening), maps: Object.fromEntries(MAPS.map(name => [name, wireMap(value[name], bound.maxMapEntries)])),
    slots: Array.from(value.slots, ([event, slot]) => { decimal(event); return [event, wireSlot(slot)]; }) };
  const encoded = new TextEncoder().encode(JSON.stringify(snapshot));
  if (encoded.length > bound.maxBytes) fail();
  return encoded;
}

// Validate the full ordered linked list before hashing. The array index is the
// authenticated leaf position; reconstructing by insertion would change roots.
function mapLeaves(value, limit) {
  if (!Array.isArray(value) || value.length < 1 || value.length > limit) fail();
  const leaves = value.map(leaf => {
    if (!Array.isArray(leaf) || leaf.length !== 4) fail();
    return leaf.map((entry, position) => decimal(entry, position === 2 ? 32 : undefined));
  });
  if (leaves[0][0] !== 0n || leaves[0][1] !== 0n) fail();
  const sorted = leaves.map((leaf, index) => ({ leaf, index })).sort((a, b) => a.leaf[0] < b.leaf[0] ? -1 : a.leaf[0] > b.leaf[0] ? 1 : 0);
  for (let index = 0; index < sorted.length; index++) {
    const { leaf } = sorted[index], next = sorted[index + 1];
    if ((index > 0 && leaf[0] <= sorted[index - 1].leaf[0])
        || leaf[2] !== BigInt(next?.index ?? 0) || leaf[3] !== (next?.leaf[0] ?? 0n)) fail();
  }
  return leaves;
}
async function restoreMap(leaves, hashes) {
  const value = new IndexedMap(hashes, await SparseTree.create(hashes.node));
  for (let index = 0; index < leaves.length; index++) {
    value.leaves.set(BigInt(index), leaves[index]);
    await value.tree.set(BigInt(index), await hashes.mapLeaf(leaves[index]));
  }
  value.count = BigInt(leaves.length);
  return value;
}

export async function restoreWitnessCheckpoint(options, validateStatement) {
  const bound = bounds(options.limits);
  if (!(options.checkpointBytes instanceof Uint8Array) || options.checkpointBytes.length > bound.maxBytes) fail();
  // Copy every caller-owned input before the first await. Neither hash callbacks
  // nor concurrent wallet activity can change bytes after validation.
  const snapshot = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(options.checkpointBytes)));
  const statement = structuredClone(options.expectedStatement), ownerSecret = new Uint8Array(readBytes(bytes(options.ownerSecret)));
  const checkpoint = copyEnrollmentCheckpoint(options.enrollment), hashes = options.hashes,
    expectedRoot = enrollmentRoot(options.expectedEnrollmentRoot ?? statement.enrollmentRoot);
  exact(snapshot, TOP); exact(snapshot.opening, OPENING); exact(snapshot.maps, MAPS);
  if (snapshot.version !== 1 || !Array.isArray(snapshot.slots) || snapshot.slots.length > bound.maxSlots) fail();
  const community = readBytes(snapshot.community), ownerId = bytes(readBytes(snapshot.owner)),
    policyHash = readBytes(snapshot.policyDigest), root = fieldValue(readBytes(snapshot.enrollmentRoot)),
    commitment = fieldValue(readBytes(snapshot.commitment)), now = readTime(snapshot.now), version = readTime(snapshot.accountVersion);
  const o = snapshot.opening;
  const opening = { available: decimal(o.available, 32), reserved: decimal(o.reserved, 128), frontier: readTime(o.frontier),
    createdAt: readTime(o.createdAt), admissionEpoch: readTime(o.admissionEpoch), admissions: decimal(o.admissions, 32), blind: readBytes(o.blind) };
  const leaves = Object.fromEntries(MAPS.map(name => [name, mapLeaves(snapshot.maps[name], bound.maxMapEntries)]));
  const entries = new Map();
  for (let index = 0; index < checkpoint.entries.length; index++) {
    const entry = checkpoint.entries[index], member = bytes(entry.member);
    if (entries.has(member) || entry.index !== BigInt(index)) fail();
    entries.set(member, index);
  }
  const ownerIndex = entries.get(ownerId), owner = checkpoint.entries[ownerIndex];
  if (!owner || checkpoint.root !== expectedRoot) fail();
  const slots = new Map();
  for (const item of snapshot.slots) {
    if (!Array.isArray(item) || item.length !== 2) fail();
    const event = decimal(item[0]), s = item[1]; exact(s, SLOT);
    const peer = readBytes(s.peer);
    if (event === 0n || slots.has(item[0]) || ![0, 1].includes(s.role)
        || ![1, 2, 3, 4, 5].includes(s.phase) || (s.role === 1 && s.phase === 5)) fail();
    const slot = { peer, nonce: readBytes(s.nonce), group: readBytes(s.group), contactPolicy: readBytes(s.contactPolicy),
      role: s.role, phase: s.phase, amount: decimal(s.amount, 32), admittedAt: readTime(s.admittedAt), expiresAt: readTime(s.expiresAt),
      peerAuthority: decimal(s.peerAuthority), ownerAuthority: decimal(s.ownerAuthority),
      peerEnrollment: readEnrollment(s.peerEnrollment), ownerEnrollment: readEnrollment(s.ownerEnrollment) };
    if (slot.admittedAt === 0n || slot.expiresAt <= slot.admittedAt || slot.admittedAt > now) fail();
    slots.set(item[0], slot);
  }
  // All schema, numeric, list and byte bounds precede expensive hashing.
  await validateStatement(statement);
  if (hex(Uint8Array.from(statement.community)) !== snapshot.community || hex(Uint8Array.from(statement.owner)) !== ownerId
      || hex(Uint8Array.from(statement.policyDigest)) !== snapshot.policyDigest
      || (root !== expectedRoot && root !== fieldValue(Uint8Array.from(statement.enrollmentRoot)))
      || fieldValue(Uint8Array.from(statement.nextState)) !== commitment
      || BigInt(statement.now) !== now || BigInt(statement.nextVersion) !== version) fail();
  const policy = statement.policy;
  if (hex(await policyDigest(community, policy)) !== hex(policyHash)
      || fieldValue(await hashes.secretHash(community, ownerSecret)) !== fieldValue(owner.secretHash)) fail();
  // Current membership is required for the owner. Historical peers may have
  // left the roster; their saved headers bind to the immutable slot authority.
  await verifyEnrollmentPath(owner, community, expectedRoot, hashes);
  const payloads = Object.fromEntries(MAPS.map(name => [name, new Map(leaves[name].slice(1).map(leaf => [leaf[0], leaf[1]]))]));
  const pairs = new Set(); let reserved = 0n;
  for (const [key, slot] of slots) {
    await verifyEnrollmentLeaf(slot.peerEnrollment, community, slot.peer, slot.peerAuthority, hashes);
    await verifyEnrollmentLeaf(slot.ownerEnrollment, community, owner.member, slot.ownerAuthority, hashes);
    const event = BigInt(key), own = slot.role === 0 ? payloads.outgoing : payloads.incoming,
      opposite = slot.role === 0 ? payloads.incoming : payloads.outgoing;
    if (event !== await hashes.marker(community, ownerSecret, owner.member, slot.peer, slot.nonce)
        || opposite.has(event) || own.get(event) !== await hashes.obligation(event, slot, slot.phase)
        || slot.amount !== BigInt(slot.role === 0 ? policy.outgoingReservation : policy.incomingReservation)) fail();
    own.delete(event);
    const pair = await hashes.pairKey(community, owner.member, ownerSecret, slot.peer);
    if (payloads.pairs.get(pair) !== 1n) fail();
    pairs.add(pair);
    if (slot.phase === 1 || slot.phase === 2) reserved += slot.amount;
  }
  if (payloads.outgoing.size || payloads.incoming.size || pairs.size !== payloads.pairs.size || reserved !== opening.reserved) fail();
  const maps = {};
  for (const name of MAPS) maps[name] = await restoreMap(leaves[name], hashes);
  Object.assign(opening, { outgoingRoot: maps.outgoing.root, outgoingCount: maps.outgoing.count,
    incomingRoot: maps.incoming.root, incomingCount: maps.incoming.count, pairRoot: maps.pairs.root, pairCount: maps.pairs.count });
  const statePolicyHash = await statePolicyDigest(community, policy);
  if (await hashes.state(community, owner.member, statePolicyHash, owner.secretHash, version, opening) !== commitment) fail();
  return { hashes, community, policy, checkpoint, ownerIndex, ownerSecret, owner, policyHash, statePolicyHash,
    now, version, commitment, opening, slots, ...maps };
}
