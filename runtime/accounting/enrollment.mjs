// Membership paths and historical authority use the existing account relation.
import { hex } from './encoding.mjs';
import { fieldBytes, fieldValue } from './primitives.mjs';
import { integer, SAFE } from './hashes.mjs';

const KEYS = ['member','key','secretHash','start','end','delegationDigest','index','leaf','path'];
const fail = () => { throw new Error('Invalid account enrollment'); };
function bytes(value, length) {
  if (!(value instanceof Uint8Array) || value.length !== length) fail();
}
export function enrollmentRoot(value) {
  if (!(value instanceof Uint8Array) && !Array.isArray(value)) fail();
  if (value.length !== 32 || Array.from(value).some(n => !Number.isInteger(n) || n < 0 || n > 255)) fail();
  const root = fieldValue(Uint8Array.from(value)); if (root === 0n) fail(); return root;
}
export function checkEnrollmentShape(entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry) || Object.keys(entry).length !== KEYS.length
      || !KEYS.every(key => Object.hasOwn(entry, key))) fail();
  bytes(entry.member, 32); bytes(entry.key, 64); bytes(entry.secretHash, 32); bytes(entry.delegationDigest, 32);
  fieldValue(entry.secretHash); fieldBytes(entry.leaf);
  if (!entry.member.some(Boolean) || !entry.delegationDigest.some(Boolean)
      || typeof entry.start !== 'bigint' || typeof entry.end !== 'bigint'
      || entry.start <= 0n || entry.end <= entry.start || entry.end > SAFE
      || typeof entry.index !== 'bigint' || typeof entry.leaf !== 'bigint' || !Array.isArray(entry.path) || entry.path.length !== 32) fail();
  integer(entry.index, 32);
  for (const sibling of entry.path) { if (typeof sibling !== 'bigint') fail(); fieldBytes(sibling); }
}
export function copyEnrollmentCheckpoint(value) {
  if (!value || !Array.isArray(value.entries) || value.entries.length < 1 || value.entries.length > 65536
      || typeof value.root !== 'bigint') fail();
  fieldBytes(value.root);
  const members = new Set();
  for (let index = 0; index < value.entries.length; index++) {
    const entry = value.entries[index]; checkEnrollmentShape(entry);
    const member = hex(entry.member);
    if (entry.index !== BigInt(index) || members.has(member)) fail();
    members.add(member);
  }
  return { root: value.root, entries: structuredClone(value.entries) };
}
export async function verifyEnrollmentLeaf(entry, community, member, expectedLeaf, hashes) {
  checkEnrollmentShape(entry);
  if (hex(entry.member) !== hex(member) || entry.leaf !== expectedLeaf
      || await hashes.enrollment(community, member, entry) !== expectedLeaf) fail();
}
export async function verifyEnrollmentPath(entry, community, expectedRoot, hashes) {
  await verifyEnrollmentLeaf(entry, community, entry.member, entry.leaf, hashes);
  let node = entry.leaf, position = entry.index;
  for (const sibling of entry.path) {
    node = position & 1n ? await hashes.enrollmentNode(sibling, node) : await hashes.enrollmentNode(node, sibling);
    position >>= 1n;
  }
  if (node !== expectedRoot) fail();
}
export async function refreshEnrollment(value, { enrollment, expectedRoot }) {
  const checkpoint = copyEnrollmentCheckpoint(enrollment), root = enrollmentRoot(expectedRoot);
  if (checkpoint.root !== root) fail();
  const ownerIndex = checkpoint.entries.findIndex(entry => hex(entry.member) === hex(value.owner.member));
  if (ownerIndex < 0) fail();
  const owner = checkpoint.entries[ownerIndex];
  if (hex(owner.secretHash) !== hex(value.owner.secretHash)
      || fieldValue(await value.hashes.secretHash(value.community, value.ownerSecret)) !== fieldValue(owner.secretHash)) fail();
  await verifyEnrollmentPath(owner, value.community, root, value.hashes);
  return { checkpoint, owner, ownerIndex };
}

// A replacement receipt/ACK authority needs the current common root; the exact
// reservation-time leaf needs no current membership, including after removal.
export async function verifyReceiptEnrollment(entry, value, member, originalLeaf, owner = false) {
  await verifyEnrollmentLeaf(entry, value.community, member, entry.leaf, value.hashes);
  if (entry.leaf === originalLeaf) return;
  if (owner && entry.leaf !== value.owner.leaf) fail();
  await verifyEnrollmentPath(entry, value.community, value.checkpoint.root, value.hashes);
}
