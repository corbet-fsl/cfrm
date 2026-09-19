// Shared byte encodings only. The verifier never receives these private openings.
export const OPTIONS = Object.freeze({ verifierTarget: 'noir-recursive' }); // ZK enabled in pinned bb.js5.0.0.
export const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
export const unhex = text => {
  if (typeof text !== 'string' || text.length % 2 || !/^[0-9a-f]*$/.test(text)) throw new Error('Noncanonical hex');
  return Uint8Array.from(text.match(/../g) ?? [], s => parseInt(s, 16));
};
export const cat = (...parts) => Uint8Array.from(parts.flatMap(p => Array.from(p)));
export const zeros = () => new Uint8Array(32);
export const random = () => crypto.getRandomValues(new Uint8Array(32));
export const sha = async bytes => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
export const be = (value, bytes) => {
  let n = BigInt(value); if (n < 0n || n >= 1n << BigInt(bytes * 8)) throw new Error('Integer range');
  const out = new Uint8Array(bytes); for (let i = bytes - 1; i >= 0; i--) { out[i] = Number(n & 255n); n >>= 8n; } return out;
};
export const memberBytes = value => Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));
export const secretHash = (community, secret) => sha(cat([2], community, secret));
export const leaf = (community, member, key, secret, start, end) => sha(cat([1], community, member, key, secret, be(start, 8), be(end, 8)));
export const node = (a, b) => sha(cat([6], a, b));
export const state = (community, owner, secret, balance, role, peer, nonce, group, reserve, blind) =>
  sha(cat([3], community, owner, secret, be(balance, 4), [role], peer, nonce, group, be(reserve, 4), blind));
export const receiptBytes = (community, responder, peer, nonce, group, kind, issued) =>
  cat([4], community, responder, peer, nonce, group, [kind], be(issued, 8));
export const marker = (community, secret, owner, peer, nonce) => sha(cat([5], community, secret, owner, peer, nonce));
export function canonicalSignature(raw) {
  const sig = new Uint8Array(raw);
  if (sig.length !== 64) throw new Error('Expected WebCrypto P1363 signature');
  // Standard ECDSA low-S normalization required by Noir's built-in verifier.
  const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  const s = BigInt('0x' + hex(sig.slice(32)));
  if (s > order / 2n) sig.set(be(order - s, 32), 32);
  return sig;
}
