// Actual libSQL SDK/SQL storage contract. Synthetic public records here do not
// claim delegation/proof verification; those checks belong to the service.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createClient } from '@libsql/client';
import { createTursoEnrollmentStore } from '../enrollment-turso.mjs';

const limits = { maxMembers: 2, maxRetainedSlots: 2, maxPublicationBytes: 4096, requestTimeoutMs: 5000 };
const record = (id, issuedAt = 100) => ({ delegation: { fixture: id, issuedAt }, entry: {
  memberId: id, accountKey: '11'.repeat(64), secretHash: '22'.repeat(32),
  delegationDigest: '33'.repeat(32), issuedAt, expiresAt: 900,
} });

test('libSQL enrollment preserves immutable bindings, monotonic clock and exact pending publication after reopen', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'cfrm-enrollment-libsql-'));
  const url = pathToFileURL(join(directory, 'state.db')).href;
  const open = () => createTursoEnrollmentStore({ ...limits, client: createClient({ url }) });
  let store = await open();
  try {
    await store.observeClock('community', 100);
    await assert.rejects(store.observeClock('community', 99), /backwards/);
    await store.upsert('community', record('alice'));
    await store.upsert('community', record('alice'));
    await assert.rejects(store.upsert('community', { ...record('alice'), entry: {
      ...record('alice').entry, secretHash: '44'.repeat(32), issuedAt: 101,
    } }), /immutable/);
    await store.upsert('community', record('alice', 101));
    await assert.rejects(store.upsert('community', record('alice', 100)), /Conflicting/);
    await store.upsert('community', record('bob'));
    await assert.rejects(store.upsert('community', record('carol')), /cap/);
    await store.putPending('community', 1, { fixture: 'common root' });
    await assert.rejects(store.putPending('community', 1, { fixture: 'different root' }), /conflict/);
    store.close(); store = await open();
    assert.deepEqual(await store.pending('community', 1), { publication: { fixture: 'common root' }, installed: false });
    await store.markInstalled('community', 1);
    assert.equal((await store.pending('community', 1)).installed, true);
    assert.equal((await store.list('community')).length, 2);
    assert.equal((await store.list('elsewhere')).length, 0);
    await store.putPending('community', 2, { fixture: 2 });
    await store.putPending('community', 3, { fixture: 3 });
    assert.equal(await store.pending('community', 1), null);
    await assert.rejects(store.putPending('community', 4, { fixture: 'é'.repeat(2100) }), /size limit/);
    assert.equal(await store.pending('community', 4), null);
  } finally { store.close(); await rm(directory, { recursive: true, force: true }); }
});

test('lost libSQL COMMIT response retires the client; reopening recovers the exact accepted publication', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'cfrm-enrollment-commit-'));
  const url = pathToFileURL(join(directory, 'state.db')).href;
  const client = createClient({ url });
  const uncertainClient = new Proxy(client, { get(target, name) {
    if (name === 'transaction') return async mode => {
      const tx = await target.transaction(mode);
      return new Proxy(tx, { get(transaction, method) {
        if (method === 'commit') return async () => { await transaction.commit(); throw new Error('Lost COMMIT response'); };
        const value = transaction[method]; return typeof value === 'function' ? value.bind(transaction) : value;
      } });
    };
    const value = target[name]; return typeof value === 'function' ? value.bind(target) : value;
  } });
  let store = await createTursoEnrollmentStore({ ...limits, client: uncertainClient });
  try {
    await assert.rejects(store.putPending('community', 1, { fixture: 'retained' }), /Lost COMMIT/);
    await assert.rejects(store.pending('community', 1), /closed/);
    store = await createTursoEnrollmentStore({ ...limits, client: createClient({ url }) });
    const expected = { publication: { fixture: 'retained' }, installed: false };
    assert.deepEqual(await store.pending('community', 1), expected);
    assert.deepEqual(await store.putPending('community', 1, expected.publication), expected);
  } finally { store.close(); await rm(directory, { recursive: true, force: true }); }
});
