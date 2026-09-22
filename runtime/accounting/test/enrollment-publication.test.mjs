import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { createEnrollmentClient } from '../enrollment-client.mjs';
import {
  ENROLLMENT_DOMAIN, publicationSigningBytes, verifyPublicationSignature,
} from '../enrollment-publication.mjs';

const memberId = Buffer.alloc(32, 7).toString('base64url');
const delegation = {
  version: 1, hashScheme: 'poseidon2-bn254-fixed-128-v1',
  admission: { communityId: 'community', memberId, policyDigest: 'policy' },
  authorization: { communityId: 'community', memberId },
  accountPublicKey: '11'.repeat(64), stateSecretCommitment: `${'00'.repeat(31)}02`,
  issuedAt: 100, expiresAt: 300, signature: 'sig',
};
const entry = {
  memberId, accountKey: delegation.accountPublicKey, secretHash: delegation.stateSecretCommitment,
  issuedAt: 100, expiresAt: 300, delegationDigest: '33'.repeat(32),
};
const community = new Uint8Array(32).fill(4);
const unsigned = {
  version: 1, domain: ENROLLMENT_DOMAIN, communityId: 'community', policyDigest: 'policy',
  slot: 1, notBefore: 100, expiresAt: 200, root: [...new Uint8Array(31), 1],
  delegations: [{ delegation, entry }],
};
const key = generateKeyPairSync('ed25519');
const operatorPublicKey = new Uint8Array(key.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32));
const publication = {
  ...unsigned,
  signature: sign(null, publicationSigningBytes(unsigned), key.privateKey).toString('base64url'),
};
const hashes = { enrollment: async () => 1n, enrollmentNode: async () => 1n };
const verifyDelegation = async () => new Uint8Array(32).fill(0x33);

test('Node Ed25519 publication signing verifies in WebCrypto and rejects bit flips', async () => {
  assert.equal(await verifyPublicationSignature(publication, operatorPublicKey), true);
  const altered = structuredClone(publication);
  const bytes = Buffer.from(altered.signature, 'base64url');
  bytes[0] ^= 1;
  altered.signature = bytes.toString('base64url');
  assert.equal(await verifyPublicationSignature(altered, operatorPublicKey), false);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const noncanonical = { ...publication, signature: publication.signature.slice(0, -1)
    + alphabet[alphabet.indexOf(publication.signature.at(-1)) | 1] };
  assert.deepEqual(Buffer.from(noncanonical.signature, 'base64url'), Buffer.from(publication.signature, 'base64url'));
  assert.equal(await verifyPublicationSignature(noncanonical, operatorPublicKey), false);
});

test('client rejects wrong scope and stale signed publications', async () => {
  const client = now => createEnrollmentClient({
    communityId: 'community', policyDigest: 'policy', community, hashes,
    checkpointPeriodSeconds: 100, clock: () => now,
    transport: async () => ({ action: 'enroll', publication }), verifyDelegation,
    verifyPublication: async value => verifyPublicationSignature(value, operatorPublicKey),
  });
  assert.equal((await client(150).acquire(delegation)).status, 'eligible');
  const scoped = structuredClone(publication); scoped.communityId = 'other';
  await assert.rejects(createEnrollmentClient({
    communityId: 'community', policyDigest: 'policy', community, hashes,
    checkpointPeriodSeconds: 100, clock: () => 150,
    transport: async () => ({ action: 'enroll', publication: scoped }), verifyDelegation,
    verifyPublication: async value => verifyPublicationSignature(value, operatorPublicKey),
  }).acquire(delegation), /publication rejected/);
  await assert.rejects(client(250).acquire(delegation), /stale/);
});
