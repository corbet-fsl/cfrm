// Real SQLite retention and Ed25519-signed publication records. Delegation
// bodies are synthetic storage fixtures; historical lookup must not reissue or
// rebuild them. Actual delegation/proof composition remains a browser contract.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createEnrollmentService } from '../enrollment-service.mjs';
import { createEnrollmentStore } from '../enrollment-store.mjs';
import { ENROLLMENT_DOMAIN, publicationSigningBytes } from '../enrollment-publication.mjs';

test('historical lookup returns only exact installed publications and fails closed after pruning or corruption', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'cfrm-enrollment-history-'));
  const options = { path: join(directory, 'enrollment.sqlite'), maxMembers: 2,
    maxRetainedSlots: 2, maxPublicationBytes: 16384, busyTimeoutMs: 5000 };
  const { privateKey } = generateKeyPairSync('ed25519');
  const signed = slot => {
    const publication = { version: 1, domain: ENROLLMENT_DOMAIN, communityId: 'community', policyDigest: 'policy',
      slot, notBefore: slot * 100, expiresAt: (slot + 1) * 100, root: [...new Uint8Array(31), slot],
      delegations: [{ delegation: { fixture: 'retained signed record' }, entry: {
        memberId: Buffer.alloc(32, 7).toString('base64url'), accountKey: '11'.repeat(64), secretHash: '22'.repeat(32),
        issuedAt: 1, expiresAt: 1000, delegationDigest: '33'.repeat(32),
      } }] };
    return { ...publication, signature: sign(null, publicationSigningBytes(publication), privateKey).toString('base64url') };
  };
  const forbidden = async () => { throw new Error('Historical lookup rebuilt or installed a checkpoint'); };
  let store = createEnrollmentStore(options), service;
  const open = () => createEnrollmentService({ communityId: 'community', policyDigest: 'policy',
    community: new Uint8Array(32).fill(4), hashes: { enrollment: forbidden, enrollmentNode: forbidden },
    clock: () => 450, verifyDelegation: forbidden, store, checkpointPeriodSeconds: 100, maxMembers: 2,
    operatorPrivateKey: privateKey, installCheckpoint: forbidden });
  try {
    service = open();
    assert.equal(await service.checkpoint(1), null);
    const original = signed(1);
    await store.putPending('community', 1, original);
    assert.equal(await service.checkpoint(1), null);
    await store.markInstalled('community', 1);
    assert.deepEqual(await service.checkpoint(1), original);
    service.close(); store.close(); store = createEnrollmentStore(options); service = open();
    assert.deepEqual(await service.checkpoint(1), original);
    await assert.rejects(service.checkpoint(5), /slot/);
    await assert.rejects(service.checkpoint(-1), /slot/);
    await store.putPending('community', 2, signed(2));
    await store.putPending('community', 3, signed(3));
    assert.equal(await service.checkpoint(1), null);
    await store.putPending('community', 4, signed(3));
    await store.markInstalled('community', 4);
    await assert.rejects(service.checkpoint(4), /mismatch/);
  } finally { service?.close(); store.close(); await rm(directory, { recursive: true, force: true }); }
});
