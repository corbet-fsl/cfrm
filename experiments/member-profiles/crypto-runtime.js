// Explicit Node adapter for the experimental client protocol. A native/mobile
// build must provide these byte operations using its maintained crypto runtime.
// No key generation, secret persistence, transport, or fallback lives here.
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';

export const random32 = () => new Uint8Array(randomBytes(32));
export const sha256 = bytes => new Uint8Array(createHash('sha256').update(bytes).digest());
export const sha3_256 = bytes => new Uint8Array(createHash('sha3-256').update(bytes).digest());
export function verifyEd25519(publicKey, signature, bytes) {
  const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519',
    x: Buffer.from(publicKey).toString('base64url') }, format: 'jwk' });
  return verify(null, bytes, key, signature);
}
