// Portable publication schema and transcript.  Node signing and SQLite live
// in the server modules; this file is safe to import in a browser.

export const ENROLLMENT_DOMAIN = 'cfrm.account.enrollment.v1';
export const ACCOUNT_HASH_SCHEME = 'poseidon2-bn254-fixed-128-v1';
export const PUBLICATION_KEYS = ['version', 'domain', 'communityId', 'policyDigest',
  'slot', 'notBefore', 'expiresAt', 'root', 'delegations', 'signature'];
export const PUBLIC_ENTRY_KEYS = ['memberId', 'accountKey', 'secretHash',
  'issuedAt', 'expiresAt', 'delegationDigest'];

const memberIdPattern = /^[A-Za-z0-9_-]{43}$/;
const hex32 = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const hex64 = value => typeof value === 'string' && /^[0-9a-f]{128}$/.test(value);
const positive = value => Number.isSafeInteger(value) && value > 0;
const nonnegative = value => Number.isSafeInteger(value) && value >= 0;
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const clone = value => structuredClone(value);

export function publicEntry(value) {
  if (!exact(value, PUBLIC_ENTRY_KEYS) || !memberIdPattern.test(value.memberId)
      || !hex64(value.accountKey) || !hex32(value.secretHash) || !hex32(value.delegationDigest)
      || !positive(value.issuedAt) || !positive(value.expiresAt) || value.expiresAt <= value.issuedAt) {
    throw new TypeError('Invalid enrollment entry');
  }
  return clone(value);
}

export function delegationShape(value) {
  const keys = ['version', 'hashScheme', 'admission', 'authorization',
    'accountPublicKey', 'stateSecretCommitment', 'issuedAt', 'expiresAt', 'signature'];
  if (!exact(value, keys) || value.version !== 1 || value.hashScheme !== ACCOUNT_HASH_SCHEME
      || !value.admission || !value.authorization
      || typeof value.admission.communityId !== 'string' || typeof value.admission.memberId !== 'string'
      || typeof value.admission.policyDigest !== 'string' || !memberIdPattern.test(value.admission.memberId)
      || !hex64(value.accountPublicKey) || !hex32(value.stateSecretCommitment)
      || !positive(value.issuedAt) || !positive(value.expiresAt) || value.expiresAt <= value.issuedAt
      || typeof value.signature !== 'string') throw new TypeError('Invalid accounting delegation');
  return clone(value);
}

function publicationDelegation(value) {
  const keys = ['delegation', 'entry'];
  if (!exact(value, keys) || !value.delegation || typeof value.delegation !== 'object') {
    throw new TypeError('Invalid enrollment delegation');
  }
  return { delegation: clone(value.delegation), entry: publicEntry(value.entry) };
}

export function sortPublicationDelegations(values) {
  if (!Array.isArray(values) || values.length === 0 || values.length > 65536) {
    throw new TypeError('Enrollment publication bound');
  }
  const result = values.map(publicationDelegation).sort((a, b) => a.entry.memberId < b.entry.memberId ? -1 : a.entry.memberId > b.entry.memberId ? 1 : 0);
  for (let index = 1; index < result.length; index++) {
    if (result[index - 1].entry.memberId === result[index].entry.memberId) throw new TypeError('Duplicate enrollment member');
  }
  return result;
}

function rootBytes(value) {
  if (!Array.isArray(value) || value.length !== 32 || value.some(byte => !Number.isInteger(byte) || byte < 0 || byte > 255)) {
    throw new TypeError('Invalid enrollment root');
  }
  return value.slice();
}

function signature(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(value)) throw new TypeError('Invalid enrollment signature');
  return value;
}

export function publicationShape(value, { signed = true } = {}) {
  const keys = signed ? PUBLICATION_KEYS : PUBLICATION_KEYS.filter(key => key !== 'signature');
  if (!exact(value, keys) || value.version !== 1 || value.domain !== ENROLLMENT_DOMAIN
      || typeof value.communityId !== 'string' || value.communityId.length === 0
      || typeof value.policyDigest !== 'string' || value.policyDigest.length === 0
      || !nonnegative(value.slot) || !nonnegative(value.notBefore) || !positive(value.expiresAt)
      || value.expiresAt <= value.notBefore || !Array.isArray(value.delegations)) {
    throw new TypeError('Invalid enrollment publication');
  }
  rootBytes(value.root);
  const delegations = sortPublicationDelegations(value.delegations);
  if (signed) signature(value.signature);
  return { ...clone(value), root: rootBytes(value.root), delegations };
}

// The ordered array is the versioned transcript.  All publication fields are
// included, and no caller-controlled object-key order affects a signature.
export function publicationSigningBytes(value) {
  // Verify a supplied signature's shape, then remove it from the transcript.
  // This lets WebCrypto verify the exact signed publication as well as lets
  // the Node signer encode its unsigned candidate without special casing.
  const normalized = publicationShape(value, { signed: Object.hasOwn(value, 'signature') });
  const { signature: ignored, ...publication } = normalized;
  return new TextEncoder().encode(JSON.stringify([
    ENROLLMENT_DOMAIN, publication.version, publication.communityId, publication.policyDigest,
    publication.slot, publication.notBefore, publication.expiresAt, publication.root,
    publication.delegations,
  ]));
}

export async function verifyPublicationSignature(value, operatorPublicKey) {
  const publication = publicationShape(value);
  if (!(operatorPublicKey instanceof Uint8Array) || operatorPublicKey.length !== 32) throw new TypeError('Invalid operator public key');
  const encoded = publication.signature.replaceAll('-', '+').replaceAll('_', '/');
  const padded = encoded + '='.repeat((4 - encoded.length % 4) % 4);
  const signatureBytes = Uint8Array.from(atob(padded), character => character.charCodeAt(0));
  if (signatureBytes.length !== 64) throw new TypeError('Invalid enrollment signature');
  const canonical = btoa(String.fromCharCode(...signatureBytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
  if (canonical !== publication.signature) return false;
  const key = await crypto.subtle.importKey('raw', operatorPublicKey, 'Ed25519', false, ['verify']);
  return crypto.subtle.verify('Ed25519', key, signatureBytes, publicationSigningBytes(publication));
}

export function publicationEntries(value) {
  return publicationShape(value).delegations.map(({ entry }) => clone(entry));
}

export function sameEntry(left, right) {
  return JSON.stringify(publicEntry(left)) === JSON.stringify(publicEntry(right));
}
