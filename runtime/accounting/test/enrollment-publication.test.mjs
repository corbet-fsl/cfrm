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
// Hash/delegation callbacks are deterministic boundary fixtures. Operator
// publication signatures use actual Ed25519; real cmsg/Poseidon composition is
// covered by the browser accounting contract, not these isolated parser tests.

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

test('historical publication authenticates its acceptance slot without reviving current eligibility', async () => {
  const requests = [], observed = [];
  let time = 250;
  const client = createEnrollmentClient({ communityId: 'community', policyDigest: 'policy', community, hashes,
    checkpointPeriodSeconds: 100, clock: () => time,
    transport: async request => {
      requests.push(structuredClone(request));
      return request.action === 'checkpoint' ? { action: 'checkpoint', slot: request.slot, publication }
        : { action: request.action, publication };
    },
    verifyDelegation: async input => { observed.push(input.now); return verifyDelegation(input); },
    verifyPublication: value => verifyPublicationSignature(value, operatorPublicKey),
  });
  const result = await client.historical({ slot: 1, at: 150, expectedRoot: Uint8Array.from(publication.root) });
  assert.equal(result.status, 'historical');
  assert.deepEqual(result.acceptanceCheckpoint, { slot: 1, notBefore: 100, expiresAt: 200, root: publication.root });
  assert.deepEqual(requests, [{ action: 'checkpoint', slot: 1 }]);
  assert.deepEqual(observed, [150]);
  const originalAuthority = await client.historical({ slot: 1, at: 150 });
  assert.deepEqual(originalAuthority.acceptanceCheckpoint, result.acceptanceCheckpoint);
  assert.deepEqual(originalAuthority.entries, [entry]);
  await assert.rejects(client.current(), /stale/);
  time = 249;
  await assert.rejects(client.historical({ slot: 1, at: 150, expectedRoot: Uint8Array.from(publication.root) }), /clock/);
});

test('historical lookup rejects missing, substituted, wrongly signed and mismatched checkpoints', async () => {
  let response = { action: 'checkpoint', slot: 1, publication };
  const client = createEnrollmentClient({ communityId: 'community', policyDigest: 'policy', community, hashes,
    checkpointPeriodSeconds: 100, clock: () => 250, transport: async () => response, verifyDelegation,
    verifyPublication: value => verifyPublicationSignature(value, operatorPublicKey) });
  const options = { slot: 1, at: 150, expectedRoot: Uint8Array.from(publication.root) };
  for (const replacement of [null, { action: 'checkpoint', slot: 1, publication: null },
    { action: 'checkpoint', slot: 2, publication },
    { action: 'checkpoint', slot: 1, publication: { ...publication, signature: Buffer.alloc(64).toString('base64url') } },
    { action: 'checkpoint', slot: 1, publication: { ...publication, communityId: 'other' } }]) {
    response = replacement;
    await assert.rejects(client.historical(options));
    await assert.rejects(client.historical({ slot: 1, at: 150 }));
  }
  response = { action: 'checkpoint', slot: 1, publication };
  await assert.rejects(client.historical({ ...options, expectedRoot: new Uint8Array(32).fill(2) }), /root mismatch/);
  await assert.rejects(client.historical({ ...options, at: 200 }), /checkpoint/);
  await assert.rejects(client.historical({ ...options, at: 350, slot: 3 }), /checkpoint/);
  await assert.rejects(client.historical({ ...options, expectedRoot: null }), /checkpoint/);
  // Even a valid operator signature cannot substitute a nonmatching tree.
  const wrongRoot = { ...unsigned, root: [...new Uint8Array(31), 2] };
  response = { action: 'checkpoint', slot: 1, publication: { ...wrongRoot,
    signature: sign(null, publicationSigningBytes(wrongRoot), key.privateKey).toString('base64url') } };
  await assert.rejects(client.historical({ ...options, expectedRoot: Uint8Array.from(wrongRoot.root) }), /publication rejected/);
  await assert.rejects(client.historical({ slot: 1, at: 150 }), /publication rejected/);
});

test('historical lookup captures its expected root before asynchronous transport', async () => {
  const expectedRoot = Uint8Array.from(publication.root);
  const client = createEnrollmentClient({ communityId: 'community', policyDigest: 'policy', community, hashes,
    checkpointPeriodSeconds: 100, clock: () => 250,
    transport: async () => {
      expectedRoot.fill(9);
      return { action: 'checkpoint', slot: 1, publication };
    }, verifyDelegation, verifyPublication: value => verifyPublicationSignature(value, operatorPublicKey) });
  const result = await client.historical({ slot: 1, at: 150, expectedRoot });
  assert.deepEqual(result.acceptanceCheckpoint.root, publication.root);
  result.publication.root[31] = 8;
  assert.equal(result.acceptanceCheckpoint.root[31], 1);
});
