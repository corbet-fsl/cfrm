// Portable WebCrypto primitives; this module owns no network or persistent store.
export const utf8 = new TextEncoder();
export const textDecoder = new TextDecoder('utf-8', { fatal: true });
export function reject() { throw new Error('Profile operation rejected'); }
export function exact(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== fields.length || fields.some(field => !Object.hasOwn(value, field))) reject();
}
export function positive(value) {
  if (!Number.isSafeInteger(value) || value <= 0) reject();
  return value;
}
export function scope(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9._:/-]{1,256}$/.test(value)) reject();
  return value;
}
export function encode(bytes) {
  let value = '';
  for (let offset = 0; offset < bytes.length; offset += 8192) {
    value += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
  }
  return btoa(value).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}
export function decode(value, size, maximum = size) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) ||
      value.length > Math.ceil(maximum * 4 / 3) || (size !== undefined && value.length !== Math.ceil(size * 4 / 3))) reject();
  let bytes;
  try { bytes = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), character => character.charCodeAt(0)); }
  catch { reject(); }
  if (bytes.length > maximum || (size !== undefined && bytes.length !== size) || encode(bytes) !== value) reject();
  return bytes;
}
export function json(value) { return utf8.encode(JSON.stringify(value)); }
export function random(size) { return globalThis.crypto.getRandomValues(new Uint8Array(size)); }
export async function digest(value) { return encode(new Uint8Array(await crypto.subtle.digest('SHA-256', value))); }
export function fresh(value, now) {
  positive(now); positive(value.issuedAt); positive(value.expiresAt);
  if (value.issuedAt > now || value.expiresAt <= now || value.expiresAt <= value.issuedAt) reject();
}
export function monotonicClock(clock) {
  if (typeof clock !== 'function') reject();
  let floor = 0;
  return () => { const now = positive(clock()); if (now < floor) reject(); floor = now; return now; };
}
const SMALL_ORDER_Y = new Set([
  '00'.repeat(32), `01${'00'.repeat(31)}`,
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  `ec${'ff'.repeat(30)}7f`,
]);
const hex = bytes => Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
const littleInteger = bytes => BigInt(`0x${hex(new Uint8Array(bytes).reverse())}`);
function strongPoint(bytes) {
  const y = new Uint8Array(bytes); y[31] &= 127;
  // Encoding checks only; all curve operations remain in WebCrypto. The five
  // sign-independent small-order encodings are the Ed25519 ref10 constants:
  // https://github.com/jedisct1/libsodium/blob/1.0.18/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L966
  if (littleInteger(y) >= (1n << 255n) - 19n || SMALL_ORDER_Y.has(hex(y))) reject();
}
export async function verifySignature(key, signature, bytes) {
  const keyBytes = decode(key, 32), signatureBytes = decode(signature, 64);
  strongPoint(keyBytes); strongPoint(signatureBytes.subarray(0, 32));
  if (littleInteger(signatureBytes.subarray(32)) >= (1n << 252n) + 27742317777372353535851937790883648493n) reject();
  const publicKey = await crypto.subtle.importKey('raw', keyBytes, 'Ed25519', false, ['verify']);
  if (await crypto.subtle.verify('Ed25519', publicKey, signatureBytes, bytes) !== true) reject();
}
const ADMISSION = ['version', 'issuerKeyId', 'communityId', 'memberId', 'chatPublicKey', 'policyDigest', 'issuedAt', 'expiresAt', 'signature'];
const AUTHORIZATION = ['version', 'communityId', 'memberId', 'rootPublicKey', 'devicePublicKey', 'issuedAt', 'expiresAt', 'signature'];
export function admissionBytes(value) {
  exact(value, ADMISSION);
  if (value.version !== 1) reject();
  scope(value.communityId); positive(value.issuedAt); positive(value.expiresAt);
  if (value.expiresAt <= value.issuedAt) reject();
  for (const field of ['issuerKeyId', 'memberId', 'chatPublicKey', 'policyDigest']) decode(value[field], 32);
  return json(['cvld.admission.v1', value.issuerKeyId, value.communityId, value.memberId,
    value.chatPublicKey, value.policyDigest, value.issuedAt, value.expiresAt]);
}
export function authorizationBytes(value) {
  exact(value, AUTHORIZATION);
  if (value.version !== 1) reject();
  scope(value.communityId); positive(value.issuedAt); positive(value.expiresAt);
  if (value.expiresAt <= value.issuedAt) reject();
  for (const field of ['memberId', 'rootPublicKey', 'devicePublicKey']) decode(value[field], 32);
  return json(['cmsg.device.v1', value.communityId, value.memberId, value.rootPublicKey,
    value.devicePublicKey, value.issuedAt, value.expiresAt]);
}
export function trustCopy(trust) {
  exact(trust, ['communityId', 'policyDigest', 'issuerPublicKey']);
  scope(trust.communityId); decode(trust.policyDigest, 32); decode(trust.issuerPublicKey, 32);
  return Object.freeze({ ...trust });
}
export async function verifyAuthority(value, trust, now) {
  exact(value, ['admission', 'authorization']);
  const { admission, authorization } = structuredClone(value);
  const admissionMessage = admissionBytes(admission), authorizationMessage = authorizationBytes(authorization);
  fresh(admission, now); fresh(authorization, now);
  if (admission.communityId !== trust.communityId || admission.policyDigest !== trust.policyDigest ||
      authorization.communityId !== admission.communityId || authorization.memberId !== admission.memberId ||
      authorization.devicePublicKey !== admission.chatPublicKey ||
      admission.issuerKeyId !== await digest(decode(trust.issuerPublicKey, 32)) ||
      admission.memberId !== await digest(json(['cmsg.member.v1', admission.communityId, authorization.rootPublicKey]))) reject();
  await verifySignature(trust.issuerPublicKey, admission.signature, admissionMessage);
  await verifySignature(authorization.rootPublicKey, authorization.signature, authorizationMessage);
  return { admission, authorization };
}
export function authorityExpiry(authority) { return Math.min(authority.admission.expiresAt, authority.authorization.expiresAt); }
export async function signing(identity, bytes) {
  if (typeof identity?.sign !== 'function') reject();
  const signature = await identity.sign(new Uint8Array(bytes));
  await verifySignature(identity.authority.admission.chatPublicKey, signature, bytes);
  return signature;
}
export async function wrappingKeyPair() {
  return crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
}
export async function wrappingPublicKey(pair) {
  return encode(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)));
}
async function derived(privateKey, publicKey, aad) {
  const peer = await crypto.subtle.importKey('raw', decode(publicKey, 65), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  // Every wrapping operation generates a new sender ECDH key and nonce. Its
  // transcript is authenticated both by AES-GCM AAD and an Ed25519 signature.
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: peer }, privateKey, 256));
  try {
    const material = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
    return await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: decode(await digest(aad), 32),
      info: utf8.encode('cfrm.profile-key-wrap.v1') }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  } finally { shared.fill(0); }
}
export async function wrapSecret(secret, recipientPublicKey, aad) {
  const pair = await wrappingKeyPair(), nonce = random(12);
  const key = await derived(pair.privateKey, recipientPublicKey, aad);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, key, secret);
  return { publicKey: await wrappingPublicKey(pair), nonce: encode(nonce), ciphertext: encode(new Uint8Array(ciphertext)) };
}
export async function unwrapSecret(wrapped, recipientPrivateKey, aad) {
  exact(wrapped, ['publicKey', 'nonce', 'ciphertext']);
  const key = await derived(recipientPrivateKey, wrapped.publicKey, aad);
  const plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: decode(wrapped.nonce, 12), additionalData: aad },
    key, decode(wrapped.ciphertext, 48)));
  if (plaintext.length !== 32) reject();
  return plaintext;
}
