// Experiment encodings around existing hashes; no permutation/sponge implementation.
import * as bytes from './common.mjs';

export const SHA_SCHEME = 'sha256-v1';
export const POSEIDON_SCHEME = 'poseidon2-bn254-fixed-128-v1';
export const POSEIDON_SOURCE = 'f249446e6e01f7b607ad35351cebe0cc20068cb7';
export const FR_MODULUS = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;
// ASCII cfrm.accounting.poseidon2.v1: an injective constant below the field modulus.
export const POSEIDON_DOMAIN = 0x6366726d2e6163636f756e74696e672e706f736569646f6e322e7631n;

export function checkScheme(value) {
  if (value !== SHA_SCHEME && value !== POSEIDON_SCHEME) throw new Error('Unsupported accounting hash scheme');
  return value;
}
export function fieldValue(value) {
  if (!(value instanceof Uint8Array) || value.length !== 32) throw new Error('Expected canonical field bytes');
  const number = BigInt('0x' + bytes.hex(value));
  if (number >= FR_MODULUS) throw new Error('Noncanonical BN254 scalar field');
  return number;
}
export function fieldBytes(value) {
  const number = BigInt(value);
  if (number < 0n || number >= FR_MODULUS) throw new Error('BN254 scalar range');
  return bytes.be(number, 32);
}
export function limbs32(value) {
  if (!(value instanceof Uint8Array) || value.length !== 32) throw new Error('Expected bytes32');
  // Both limbs are at most 2^128-1. No full identifier is reduced modulo Fr.
  return [BigInt('0x' + bytes.hex(value.slice(0, 16))), BigInt('0x' + bytes.hex(value.slice(16)))];
}
const integer = (value, bits) => {
  if (typeof value === 'number' && !Number.isSafeInteger(value)) throw new Error('Unsafe integer');
  const number = BigInt(value);
  if (number < 0n || number >= 1n << BigInt(bits)) throw new Error('Integer range');
  return number;
};

export function hashesFor(scheme, getApi) {
  checkScheme(scheme);
  if (scheme === SHA_SCHEME) return { scheme, secretHash: bytes.secretHash, leaf: bytes.leaf,
    node: bytes.node, state: bytes.state, marker: bytes.marker };
  const hash = async (tag, fields) => {
    const { hash: result } = await (await getApi()).poseidon2Hash({
      inputs: [POSEIDON_DOMAIN, BigInt(tag), ...fields].map(fieldBytes),
    });
    fieldValue(result); // Reject reductions/noncanonical external encodings.
    return result;
  };
  return {
    scheme,
    secretHash: (community, secret) => hash(2, [...limbs32(community), ...limbs32(secret)]),
    leaf: (community, member, key, secret, start, end) => {
      if (!(key instanceof Uint8Array) || key.length !== 64) throw new Error('Expected P-256 public key');
      return hash(1, [...limbs32(community), ...limbs32(member), ...limbs32(key.slice(0, 32)),
        ...limbs32(key.slice(32)), fieldValue(secret), integer(start, 64), integer(end, 64)]);
    },
    node: (a, b) => hash(6, [fieldValue(a), fieldValue(b)]),
    state: (community, owner, secret, balance, role, peer, nonce, group, reserve, blind) => hash(3,
      [...limbs32(community), ...limbs32(owner), fieldValue(secret), integer(balance, 32), integer(role, 8),
        ...limbs32(peer), ...limbs32(nonce), ...limbs32(group), integer(reserve, 32), ...limbs32(blind)]),
    marker: (community, secret, owner, peer, nonce) => hash(5,
      [...limbs32(community), ...limbs32(secret), ...limbs32(owner), ...limbs32(peer), ...limbs32(nonce)]),
  };
}

// Call only with the native fixture's independently verified original entries.
// The browser and Node verifier each derive this root; neither forwards an
// authoritative root chosen by the browser to the independent verifier.
export async function deriveCheckpoint(verified, hashes) {
  if (verified.hashScheme !== hashes.scheme || verified.entries?.length !== 4) throw new Error('Checkpoint scheme/size mismatch');
  const community = bytes.unhex(verified.community);
  if (community.length !== 32) throw new Error('Checkpoint community');
  const leaves = await Promise.all(verified.entries.map(entry => {
    if (entry.hashScheme !== hashes.scheme) throw new Error('Enrollment hash scheme mismatch');
    return hashes.leaf(community, bytes.memberBytes(entry.admission.memberId), bytes.unhex(entry.accountKey),
      bytes.unhex(entry.secretHash), entry.issuedAt, entry.expiresAt);
  }));
  const branches = [await hashes.node(leaves[0], leaves[1]), await hashes.node(leaves[2], leaves[3])];
  const root = await hashes.node(branches[0], branches[1]);
  // The SHA baseline additionally retains the original native root calculation.
  if (hashes.scheme === SHA_SCHEME && verified.root !== bytes.hex(root)) throw new Error('Native SHA checkpoint mismatch');
  return { community, root, leaves, branches };
}
