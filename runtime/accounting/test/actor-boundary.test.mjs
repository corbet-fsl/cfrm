import test from 'node:test';
import assert from 'node:assert/strict';
import { scopedAccountSigner } from '../actor-signing.mjs';
import { accountActorStorage } from '../actor-storage.mjs';

const encode = bytes => btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
const text = value => new TextEncoder().encode(value);
const u64 = value => { const bytes = new Uint8Array(8); new DataView(bytes.buffer).setBigUint64(0, BigInt(value)); return bytes; };

test('scoped account signer binds cmsg status scope and verifies a WebCrypto Ed25519 signature', async () => {
  const pair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const member = new Uint8Array(32).fill(9), challenge = new Uint8Array(32).fill(3);
  const community = new Uint8Array(await crypto.subtle.digest('SHA-256', text('community')));
  const authority = { grant: { communityId: 'community', memberId: encode(member), chatPublicKey: encode(raw) },
    authorization: { devicePublicKey: encode(raw) } };
  let message;
  const signer = scopedAccountSigner({ authority: () => authority,
    authorizeRequest: async () => { throw new Error('request callback not used'); },
    authorizeStatus: async fields => {
      const signature = encode(new Uint8Array(await crypto.subtle.sign('Ed25519', pair.privateKey, message)));
      return { ...fields, signature };
    } });
  message = new Uint8Array([...text('cfrm.account.status.v1\0'), ...community, ...member, 0,
    ...new Uint8Array(32), ...challenge, ...raw, ...u64(100), ...u64(200)]);
  assert.equal((await signer(message)).length, 86);
  const wrong = message.slice(); wrong[40] ^= 1;
  await assert.rejects(signer(wrong), /scope mismatch/);
});

test('account storage blocks after an ambiguous CAS and recovers the durable journal', async () => {
  let record = null, loseAck = true;
  const storage = {
    async load() { return record && structuredClone(record); },
    async seal(bytes) { return new Uint8Array(bytes); },
    async open(bytes) { return new Uint8Array(bytes); },
    async compareAndSwap(expected, next) {
      if ((record?.revision ?? 0) !== expected) return false;
      record = structuredClone(next);
      if (loseAck) { loseAck = false; throw new Error('lost acknowledgement'); }
      return true;
    },
  };
  const actorStorage = accountActorStorage({ storage, maxJournalBytes: 4096, maxCiphertextBytes: 4096 });
  await assert.rejects(actorStorage.save({ value: 'durable' }), /lost acknowledgement/);
  assert.equal(actorStorage.uncertain, true);
  await assert.rejects(actorStorage.save({ value: 'overwrite' }), /reload required/);
  assert.deepEqual(await actorStorage.load(), { value: 'durable', revision: 1 });
  assert.equal(actorStorage.uncertain, false);
  assert.deepEqual(await actorStorage.save({ value: 'next' }), { value: 'next', revision: 2 });
});

