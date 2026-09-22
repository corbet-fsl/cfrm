import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { AccountClient, AccountWitness, accountAcceptanceBytes, accountRequestBytes } from '../index.mjs';
import { accountHashes, checkpointFromVerified } from '../hashes.mjs';
import { fieldBytes, FR_MODULUS } from '../primitives.mjs';
import { cat, hex, sha } from '../encoding.mjs';

// Storage and reconstruction contracts only. This deterministic synthetic hash
// backend is not Poseidon2 and produces no valid account proof or acceptance.
function storageHashes() {
  return accountHashes({ async poseidon2Hash({ inputs }) {
    const digest = createHash('sha256');
    for (const input of inputs) digest.update(input);
    return { hash: fieldBytes(BigInt(`0x${digest.digest('hex')}`) % FR_MODULUS) };
  } });
}
const bytes = n => new Uint8Array(32).fill(n);
const limits = { maxBytes: 65536, maxMapEntries: 16, maxSlots: 8 };
const policy = { initialCredit: 3, maximumAvailable: 4, outgoingReservation: 1, incomingReservation: 1,
  policyRevision: 1, policyValidFrom: 1, policyValidUntil: 10000, newcomerPeriod: 100, rateWindow: 100,
  newcomerAdmissions: 2, maximumAdmissions: 4, refillPeriod: 100, refillUnits: 1, abandonAfter: 500 };
const encode = value => new TextEncoder().encode(JSON.stringify(value));
const decode = value => JSON.parse(new TextDecoder().decode(value));

async function fixture() {
  const hashes = storageHashes(), community = bytes(1), ownerSecret = bytes(10), entries = [];
  for (let index = 0; index < 3; index++) {
    entries.push({ memberId: Buffer.from(bytes(index + 2)).toString('base64url'), accountKey: hex(new Uint8Array(64).fill(index + 20)),
      secretHash: hex(await hashes.secretHash(community, bytes(index + 10))), issuedAt: 1, expiresAt: 10000,
      delegationDigest: hex(bytes(index + 30)) });
  }
  const enrollment = await checkpointFromVerified(community, entries, hashes);
  const genesis = await AccountWitness.genesis({ hashes, community, policy, checkpoint: enrollment, ownerIndex: 0, ownerSecret, now: 110 });
  return { hashes, community, ownerSecret, enrollment, genesis, entries };
}
function restoreOptions(f, candidate) {
  return { hashes: f.hashes, enrollment: f.enrollment, ownerSecret: f.ownerSecret, expectedStatement: candidate.statement,
    checkpointBytes: candidate.next.exportCheckpoint(limits), limits };
}
async function occupied(f) {
  const outgoing = await f.genesis.next.reserve({ peerIndex: 1, role: 0, nonce: bytes(50), group: bytes(51), contactPolicy: bytes(52), now: 111 });
  const incoming = await outgoing.next.reserve({ peerIndex: 2, role: 1, nonce: bytes(60), group: bytes(51), contactPolicy: bytes(52),
    openedAt: 110, expiresAt: 600, now: 112 });
  const active = await incoming.next.activate(outgoing.event, 113);
  return { candidate: await active.next.cancel(incoming.event, 114), outgoing, incoming };
}

test('genesis and occupied checkpoints survive JSON wallet bytes and recreate usable witnesses', async () => {
  const f = await fixture();
  const genesis = await AccountWitness.restoreCheckpoint(restoreOptions(f, f.genesis));
  assert(genesis instanceof AccountWitness);
  assert.equal(genesis.commitment, f.genesis.next.commitment);
  assert.deepEqual(genesis.exportCheckpoint(limits), f.genesis.next.exportCheckpoint(limits));

  const { candidate, outgoing, incoming } = await occupied(f), options = restoreOptions(f, candidate);
  const encoded = decode(options.checkpointBytes);
  assert.equal(encoded.version, 1);
  assert.equal(Object.hasOwn(encoded, 'ownerSecret'), false);
  assert.equal(Object.hasOwn(encoded, 'hashes'), false);
  const restored = await AccountWitness.restoreCheckpoint({ ...options, hashes: storageHashes(), checkpointBytes: encode(encoded) });
  assert.equal(restored.commitment, candidate.next.commitment);
  assert.equal(restored.version, 4n);
  assert.equal(restored.opening.reserved, 1n);
  assert.equal(restored.slots.get(outgoing.event.toString()).phase, 2);
  assert.equal(restored.slots.get(incoming.event.toString()).phase, 4);
  for (const name of ['outgoing', 'incoming', 'pairs']) {
    assert.equal(restored[name].root, candidate.next[name].root);
    assert.deepEqual(restored[name].leaves, candidate.next[name].leaves);
  }
  // The restored historical slot can complete a real witness transition; no
  // custom class/prototype repair is required in the embedding application.
  const expired = await restored.expire(outgoing.event, 700);
  assert.equal(expired.next.opening.reserved, 0n);
  assert.deepEqual(expired.input.old, candidate.next.input(bytes(70), 700).old);
  const after = await AccountWitness.restoreCheckpoint(restoreOptions(f, expired));
  assert.equal(after.commitment, expired.next.commitment);
});

test('schema, integer and collection bounds reject malformed wallet bytes before hashing', async () => {
  const f = await fixture(), { candidate } = await occupied(f), options = restoreOptions(f, candidate);
  let calls = 0;
  const hashes = Object.fromEntries(Object.entries(f.hashes).map(([name, method]) => [name, (...args) => { calls++; return method(...args); }]));
  for (const change of [
    value => { value.extra = 'private'; },
    value => { value.version = 2; },
    value => { value.opening.extra = 1; },
    value => { value.opening.available = '01'; },
    value => { value.opening.reserved = 0; },
    value => { value.opening.blind = '00'; },
    value => { value.now = '9007199254740992'; },
    value => { value.accountVersion = '-1'; },
    value => { value.maps.outgoing[1][0] = value.maps.outgoing[0][0]; },
    value => { value.maps.outgoing[0][2] = '0'; },
    value => { value.maps.outgoing[0][1] = '1'; },
    value => { value.slots[0][1].phase = 0; },
    value => { value.slots[0][1].extra = 1; },
    value => { value.slots.push(value.slots[0]); },
  ]) {
    const changed = decode(options.checkpointBytes); change(changed);
    await assert.rejects(AccountWitness.restoreCheckpoint({ ...options, hashes, checkpointBytes: encode(changed) }));
    assert.equal(calls, 0);
  }
  for (const changed of [{ maxBytes: 1 }, { maxMapEntries: 1 }, { maxSlots: 1 }]) {
    await assert.rejects(AccountWitness.restoreCheckpoint({ ...options, hashes, limits: { ...limits, ...changed } }));
    assert.equal(calls, 0);
  }
  assert.throws(() => candidate.next.exportCheckpoint({ ...limits, maxBytes: 1 }));
  assert.throws(() => candidate.next.exportCheckpoint({ ...limits, maxSlots: 1 }));
  assert.throws(() => candidate.next.exportCheckpoint({ ...limits, maxMapEntries: 1 }));
  assert.throws(() => candidate.next.exportCheckpoint());
  await assert.rejects(AccountWitness.restoreCheckpoint({ ...options, checkpointBytes: new Uint8Array([255]) }));
});

test('restoration binds owner, secret, enrollment, policy, version, time and commitment to expected state', async () => {
  const f = await fixture(), { candidate } = await occupied(f), options = restoreOptions(f, candidate);
  for (const change of [
    value => { value.expectedStatement.owner[0] ^= 1; },
    value => { value.expectedStatement.community[0] ^= 1; },
    value => { value.expectedStatement.nextVersion++; value.expectedStatement.previousVersion++; },
    value => { value.expectedStatement.now++; },
    value => { value.expectedStatement.nextState[31] ^= 1; },
    value => { value.expectedStatement.enrollmentRoot[31] ^= 1; },
    value => { value.expectedStatement.policy.refillUnits++; },
    value => { value.ownerSecret[0] ^= 1; },
    value => { value.enrollment.root ^= 1n; },
    value => { value.enrollment.entries[0].path[0] ^= 1n; },
  ]) {
    const changed = { ...structuredClone({ ...options, hashes: undefined }), hashes: f.hashes };
    change(changed); await assert.rejects(AccountWitness.restoreCheckpoint(changed));
  }
  await assert.rejects(AccountWitness.restoreCheckpoint({ ...options, expectedStatement: f.genesis.statement }));
});

test('validly encoded but altered openings, map payloads and historical slots cannot be restored', async () => {
  const f = await fixture(), { candidate } = await occupied(f), options = restoreOptions(f, candidate);
  for (const change of [
    value => { value.opening.available = '0'; },
    value => { value.opening.blind = '01'.repeat(32); },
    value => { value.opening.reserved = '0'; },
    value => { value.maps.outgoing[1][1] = '1'; },
    value => { value.maps.pairs[1][1] = '2'; },
    value => { value.slots[0][1].nonce = '01'.repeat(32); },
    value => { value.slots[0][1].peerAuthority = '1'; },
    value => { value.slots[0][1].ownerAuthority = '1'; },
    value => { value.slots[0][1].peerEnrollment.key = '01'.repeat(64); },
    value => { value.slots[0][1].ownerEnrollment.end = '9000'; },
    value => { value.slots[0][1].amount = '2'; },
    value => { value.slots[0][1].phase = 3; },
    value => { value.slots.pop(); },
  ]) {
    const changed = decode(options.checkpointBytes); change(changed);
    await assert.rejects(AccountWitness.restoreCheckpoint({ ...options, checkpointBytes: encode(changed) }));
  }
});

async function refreshedEnrollment(f) {
  const owner = { ...f.entries[0], accountKey: '44'.repeat(64), issuedAt: 200, delegationDigest: '45'.repeat(32) };
  const joined = { memberId: Buffer.from(bytes(80)).toString('base64url'), accountKey: '46'.repeat(64),
    secretHash: hex(await f.hashes.secretHash(f.community, bytes(81))), issuedAt: 200, expiresAt: 10000, delegationDigest: '47'.repeat(32) };
  // Reorder current members, renew the owner, remove the original outgoing peer,
  // and admit a new peer. Historical slots retain their original authority.
  return checkpointFromVerified(f.community, [f.entries[2], owner, joined], f.hashes);
}

test('refresh changes the current roster without resetting state or requiring removed historical peers', async () => {
  const f = await fixture(), { candidate, outgoing } = await occupied(f), enrollment = await refreshedEnrollment(f);
  const refreshed = await candidate.next.withEnrollment({ enrollment, expectedRoot: fieldBytes(enrollment.root) });
  assert.equal(refreshed.ownerIndex, 1);
  assert.equal(refreshed.commitment, candidate.next.commitment);
  assert.equal(refreshed.version, candidate.next.version);
  assert.deepEqual(refreshed.opening, candidate.next.opening);
  assert.deepEqual(refreshed.slots, candidate.next.slots);
  assert.notEqual(refreshed.owner.leaf, candidate.next.owner.leaf);
  const historical = refreshed.slots.get(outgoing.event.toString());
  assert.equal(historical.ownerAuthority, candidate.next.owner.leaf);
  assert.notEqual(historical.ownerAuthority, refreshed.owner.leaf);
  assert.equal(historical.peerAuthority, f.enrollment.entries[1].leaf);
  assert.equal(candidate.next.checkpoint.root, f.enrollment.root);
  const options = { ...restoreOptions(f, candidate), enrollment, checkpointBytes: refreshed.exportCheckpoint(limits),
    expectedEnrollmentRoot: fieldBytes(enrollment.root) };
  const restored = await AccountWitness.restoreCheckpoint(options);
  assert.equal(restored.commitment, candidate.next.commitment);
  const directlyRestored = await AccountWitness.restoreCheckpoint({ ...options, checkpointBytes: candidate.next.exportCheckpoint(limits) });
  assert.equal(directlyRestored.commitment, candidate.next.commitment);
  assert.equal(directlyRestored.checkpoint.root, enrollment.root);
  assert.deepEqual(directlyRestored.slots, candidate.next.slots);
  await assert.rejects(AccountWitness.restoreCheckpoint({ ...options, expectedEnrollmentRoot: undefined }));
  const expired = await restored.expire(outgoing.event, 700);
  assert.equal(expired.next.opening.reserved, 0n);
  assert.deepEqual(expired.statement.enrollmentRoot, Array.from(fieldBytes(enrollment.root)));
  assert.equal((await AccountWitness.restoreCheckpoint({ ...options, checkpointBytes: expired.next.exportCheckpoint(limits),
    expectedStatement: expired.statement })).commitment, expired.next.commitment);
  const admitted = await refreshed.reserve({ peerIndex: 2, role: 0, nonce: bytes(82), group: bytes(83), contactPolicy: bytes(84), now: 300 });
  const slot = admitted.next.slots.get(admitted.event.toString());
  assert.deepEqual(slot.peer, bytes(80));
  assert.equal(slot.ownerAuthority, refreshed.owner.leaf);
  assert.equal(slot.peerAuthority, enrollment.entries[2].leaf);
  assert.deepEqual(admitted.statement.previousState, candidate.statement.nextState);
});

test('renewed owners retain original incoming Close and Answer authority after the peer leaves', async () => {
  const f = await fixture();
  const reserved = await f.genesis.next.reserve({ peerIndex: 1, role: 1, nonce: bytes(50), group: bytes(51), contactPolicy: bytes(52),
    openedAt: 110, expiresAt: 600, now: 111 });
  const active = await reserved.next.activate(reserved.event, 112), enrollment = await refreshedEnrollment(f);
  const refreshed = await active.next.withEnrollment({ enrollment, expectedRoot: fieldBytes(enrollment.root) });
  const resolution = { kind: 2, issuedAt: 113n, historyDigest: bytes(71), ed25519ReceiptDigest: bytes(72), signature: new Uint8Array(64) };
  const closed = await refreshed.settle(reserved.event, resolution, undefined, 300);
  assert.deepEqual(closed.input.owner_enrollment.key, enrollment.entries[1].key);
  assert.deepEqual(closed.input.receipt_owner_enrollment.key, f.enrollment.entries[0].key);
  assert.deepEqual(closed.input.peer_enrollment.key, f.enrollment.entries[1].key);
  assert.equal(closed.next.opening.reserved, 0n);
  // Signature validity remains the actual circuit's responsibility. Here the
  // storage contract verifies which exact original authority reaches that gate.
  const answered = await refreshed.settle(reserved.event, { ...resolution, kind: 1 }, { issuedAt: 114n, signature: new Uint8Array(64) }, 300);
  assert.deepEqual(answered.input.receipt_owner_enrollment, closed.input.receipt_owner_enrollment);
  assert.deepEqual(answered.input.peer_enrollment, closed.input.peer_enrollment);
  const altered = structuredClone(f.enrollment.entries[1]); altered.end = 9000n;
  await assert.rejects(refreshed.settle(reserved.event, { ...resolution, kind: 1 }, undefined, 300, altered));
  const currentOwner = await refreshed.settle(reserved.event, resolution, undefined, 300, undefined, enrollment.entries[1]);
  assert.deepEqual(currentOwner.input.receipt_owner_enrollment.key, enrollment.entries[1].key);
});

test('refresh rejects a different root, missing owner, changed owner secret and forged owner path', async () => {
  const f = await fixture(), enrollment = await refreshedEnrollment(f);
  await assert.rejects(f.genesis.next.withEnrollment({ enrollment, expectedRoot: fieldBytes(f.enrollment.root) }));
  const noOwner = await checkpointFromVerified(f.community, [f.entries[1]], f.hashes);
  await assert.rejects(f.genesis.next.withEnrollment({ enrollment: noOwner, expectedRoot: fieldBytes(noOwner.root) }));
  const changed = await checkpointFromVerified(f.community, [{ ...f.entries[0], secretHash: hex(await f.hashes.secretHash(f.community, bytes(90))) }], f.hashes);
  await assert.rejects(f.genesis.next.withEnrollment({ enrollment: changed, expectedRoot: fieldBytes(changed.root) }));
  const forged = structuredClone(enrollment); forged.entries[1].path[0] ^= 1n;
  await assert.rejects(f.genesis.next.withEnrollment({ enrollment: forged, expectedRoot: fieldBytes(enrollment.root) }));
  const repeated = structuredClone(enrollment); repeated.entries[2].member = repeated.entries[0].member;
  await assert.rejects(f.genesis.next.withEnrollment({ enrollment: repeated, expectedRoot: fieldBytes(enrollment.root) }));
});

test('asynchronous hash callbacks cannot mutate caller-owned recovery inputs after snapshotting', async () => {
  const f = await fixture(), { candidate } = await occupied(f), options = restoreOptions(f, candidate);
  const expectedBytes = options.checkpointBytes.slice(), original = f.hashes.secretHash;
  const hashes = { ...f.hashes, async secretHash(...args) {
    options.checkpointBytes.fill(0);
    options.ownerSecret.fill(0);
    options.expectedStatement.owner.fill(0);
    options.enrollment.entries[0].key.fill(0);
    return original(...args);
  } };
  const restored = await AccountWitness.restoreCheckpoint({ ...options, hashes });
  assert.deepEqual(restored.exportCheckpoint(limits), expectedBytes);
});

test('lost-reply recovery retains old and pending states until exact signed retry verifies acceptance', async () => {
  const f = await fixture();
  const candidate = await f.genesis.next.reserve({ peerIndex: 1, role: 0, nonce: bytes(50), group: bytes(51), contactPolicy: bytes(52), now: 111 });
  const operator = generateKeyPairSync('ed25519'), device = generateKeyPairSync('ed25519');
  const raw = key => new Uint8Array(key.export({ format: 'der', type: 'spki' }).subarray(-32));
  const b64 = (n, length = 32) => Buffer.alloc(length, n).toString('base64url');
  const chatPublicKey = Buffer.from(raw(device.publicKey)).toString('base64url');
  const identity = { grant: { version: 1, issuerKeyId: b64(1), communityId: 'checkpoint-test', memberId: b64(2),
    chatPublicKey, policyDigest: b64(3), issuedAt: 100, expiresAt: 1000, signature: b64(4, 64) },
  authorization: { version: 1, communityId: 'checkpoint-test', memberId: b64(2), rootPublicKey: b64(5),
    devicePublicKey: chatPublicKey, issuedAt: 100, expiresAt: 1000, signature: b64(6, 64) } };
  let accepted, originalRequest, lost = true;
  const clientOptions = { operatorPublicKey: raw(operator.publicKey), sign: async message => sign(null, message, device.privateKey),
    async transport(envelope) {
      const request = envelope.request, signingBytes = await accountRequestBytes(request);
      assert(verify(null, signingBytes, device.publicKey, Buffer.from(request.signature, 'base64url')));
      if (!accepted) {
        originalRequest = JSON.stringify(request);
        // A storage-only simulated acceptance; no synthetic proof is claimed valid.
        accepted = { statement: request.statement, requestId: request.requestId, proofScope: request.proofScope,
          requestDigest: Array.from(await sha(cat(signingBytes, Buffer.from(request.signature, 'base64url')))), acceptedAt: 112, signature: '' };
        accepted.signature = sign(null, await accountAcceptanceBytes(accepted), operator.privateKey).toString('base64url');
      } else assert.equal(JSON.stringify(request), originalRequest);
      if (lost) { lost = false; throw new Error('Simulated lost reply after durable acceptance'); }
      return { action: 'apply', value: structuredClone(accepted) };
    } };
  const client = new AccountClient(clientOptions);
  const request = await client.prepareApply({ record: { statement: candidate.statement, proof: '010203',
    proofScope: { circuitDigest: Array.from(bytes(41)), verifyingKeyDigest: Array.from(bytes(42)) } }, chatPublicKey, expiresAt: 190 });
  const journal = { old: f.genesis.next.exportCheckpoint(limits), successor: candidate.next.exportCheckpoint(limits), requestBytes: encode(request) };
  await assert.rejects(client.apply({ ...identity, request }), /lost reply/);
  const old = await AccountWitness.restoreCheckpoint({ ...restoreOptions(f, f.genesis), checkpointBytes: journal.old });
  const persistedRequest = decode(journal.requestBytes);
  const successor = await AccountWitness.restoreCheckpoint({ ...restoreOptions(f, candidate), checkpointBytes: journal.successor,
    expectedStatement: persistedRequest.statement });
  assert.equal(old.commitment, f.genesis.next.commitment);
  assert.equal(successor.commitment, candidate.next.commitment);
  const acceptance = await new AccountClient(clientOptions).apply({ ...identity, request: persistedRequest });
  const confirmed = await AccountWitness.restoreCheckpoint({ ...restoreOptions(f, candidate), checkpointBytes: journal.successor,
    expectedStatement: acceptance.statement });
  assert.equal(confirmed.commitment, successor.commitment);
  assert.equal(hex(fieldBytes(confirmed.commitment)), hex(Uint8Array.from(acceptance.statement.nextState)));
  assert.notEqual(old.commitment, successor.commitment);
});
