import { createClient } from '@libsql/client/http';

const positive = value => Number.isSafeInteger(value) && value > 0;
const slotValue = value => Number.isSafeInteger(value) && value >= 0;
const json = value => JSON.stringify(value);
const clone = value => structuredClone(value);
const publicationRow = row => row ? { publication: JSON.parse(row.publication), installed: row.installed === 1 } : null;

// The registry contains only public delegations and common-root publications.
// It uses remote primary transactions; an embedded replica is never authority.
export async function createTursoEnrollmentStore({ url, authToken, requestTimeoutMs,
  maxMembers, maxRetainedSlots, maxPublicationBytes, client: suppliedClient } = {}) {
  for (const [value, maximum] of [[maxMembers, 65536], [maxRetainedSlots, 65536],
    [maxPublicationBytes, 64 * 1024 * 1024], [requestTimeoutMs, 120000]]) {
    if (!positive(value) || value > maximum) throw new TypeError('Explicit enrollment store limits required');
  }
  let client = suppliedClient;
  if (!client) {
    const target = new URL(url);
    if (!['https:', 'libsql:'].includes(target.protocol) || target.username || target.password
        || target.search || target.hash || typeof authToken !== 'string' || !authToken) throw new TypeError('Authenticated remote enrollment URL required');
    const remoteUrl = target.href.replace(/^libsql:/, 'https:');
    client = createClient({ url: remoteUrl, authToken, intMode: 'number', concurrency: 1,
      fetch: (request, init = {}) => fetch(request, { ...init,
        signal: AbortSignal.any([AbortSignal.timeout(requestTimeoutMs), ...(request.signal ? [request.signal] : []),
          ...(init.signal ? [init.signal] : [])]) }) });
  }
  if (!client || typeof client.transaction !== 'function' || typeof client.batch !== 'function') throw new TypeError('libSQL client required');
  let closed = false;
  const ensureOpen = () => { if (closed) throw new Error('Enrollment store is closed'); };
  const execute = (handle, sql, args = []) => handle.execute({ sql, args });
  const one = async (handle, sql, args) => (await execute(handle, sql, args)).rows[0];
  const rows = async (handle, sql, args) => (await execute(handle, sql, args)).rows;
  function community(value) {
    if (typeof value !== 'string' || !value || value.length > 256) throw new TypeError('Invalid enrollment community');
  }
  async function transaction(action) {
    ensureOpen();
    const tx = await client.transaction('write');
    let committing = false;
    try {
      const result = await action(tx);
      committing = true;
      await tx.commit();
      return result;
    } catch (error) {
      if (committing) {
        // A lost COMMIT response is uncertain. Retire this client; reopening
        // consults the durable slot/idempotency rows before any exact retry.
        closed = true; client.close();
      } else {
        try { await tx.rollback(); }
        catch { closed = true; client.close(); }
      }
      throw error;
    } finally { tx.close(); }
  }
  try {
    await client.batch([
      `CREATE TABLE IF NOT EXISTS cfrm_enrollment_clock (
        community_id TEXT PRIMARY KEY, clock INTEGER NOT NULL CHECK(clock > 0)
      ) STRICT, WITHOUT ROWID`,
      `CREATE TABLE IF NOT EXISTS cfrm_enrollment_members (
        community_id TEXT NOT NULL, member_id TEXT NOT NULL,
        account_key TEXT NOT NULL CHECK(length(account_key)=128),
        secret_hash TEXT NOT NULL CHECK(length(secret_hash)=64),
        delegation_digest TEXT NOT NULL CHECK(length(delegation_digest)=64),
        delegation TEXT NOT NULL, entry TEXT NOT NULL,
        updated_at INTEGER NOT NULL CHECK(updated_at > 0),
        PRIMARY KEY(community_id, member_id)
      ) STRICT, WITHOUT ROWID`,
      `CREATE TABLE IF NOT EXISTS cfrm_enrollment_pending (
        community_id TEXT NOT NULL, slot INTEGER NOT NULL CHECK(slot >= 0),
        publication TEXT NOT NULL, installed INTEGER NOT NULL CHECK(installed IN (0,1)),
        PRIMARY KEY(community_id, slot)
      ) STRICT, WITHOUT ROWID`,
    ], 'write');
  } catch (error) { client.close(); throw error; }
  return Object.freeze({
    get healthy() { return !closed; },
    async observeClock(communityId, now) {
      community(communityId);
      if (!positive(now)) throw new TypeError('Invalid enrollment clock');
      await transaction(async tx => {
        const prior = await one(tx, 'SELECT clock FROM cfrm_enrollment_clock WHERE community_id=?', [communityId]);
        if (prior && now < prior.clock) throw new Error('Enrollment clock moved backwards');
        await execute(tx, `INSERT INTO cfrm_enrollment_clock VALUES(?,?)
          ON CONFLICT(community_id) DO UPDATE SET clock=excluded.clock`, [communityId, now]);
      });
    },
    async list(communityId) {
      ensureOpen(); community(communityId);
      return (await rows(client, `SELECT delegation,entry,delegation_digest AS digest
        FROM cfrm_enrollment_members WHERE community_id=? ORDER BY member_id LIMIT ?`, [communityId, maxMembers + 1]))
        .map((row, index) => {
          if (index >= maxMembers) throw new Error('Enrollment member cap exceeded');
          return { delegation: JSON.parse(row.delegation), entry: JSON.parse(row.entry), digest: row.digest };
        });
    },
    async upsert(communityId, value) {
      community(communityId);
      // Capture values before asynchronous database work.
      value = clone(value);
      const entry = value?.entry, memberId = entry?.memberId;
      if (!value?.delegation || !entry || typeof memberId !== 'string' || !memberId
          || !/^[0-9a-f]{128}$/.test(entry.accountKey) || !/^[0-9a-f]{64}$/.test(entry.secretHash)
          || !/^[0-9a-f]{64}$/.test(entry.delegationDigest) || !positive(entry.issuedAt)) throw new TypeError('Invalid enrollment record');
      const encodedDelegation = json(value.delegation), encodedEntry = json(entry);
      if (Buffer.byteLength(encodedDelegation) + Buffer.byteLength(encodedEntry) > maxPublicationBytes) throw new Error('Enrollment record size limit');
      await transaction(async tx => {
        const prior = await one(tx, `SELECT account_key,secret_hash,delegation_digest,delegation,entry
          FROM cfrm_enrollment_members WHERE community_id=? AND member_id=?`, [communityId, memberId]);
        if (prior && (prior.account_key !== entry.accountKey || prior.secret_hash !== entry.secretHash)) throw new Error('Enrollment account binding is immutable');
        if (prior) {
          const same = prior.delegation_digest === entry.delegationDigest
            && prior.delegation === encodedDelegation && prior.entry === encodedEntry;
          if (same) return;
          if (entry.issuedAt <= JSON.parse(prior.entry).issuedAt) throw new Error('Conflicting enrollment renewal');
        } else if ((await one(tx, 'SELECT COUNT(*) AS count FROM cfrm_enrollment_members WHERE community_id=?', [communityId])).count >= maxMembers) {
          throw new Error('Enrollment member cap reached');
        }
        await execute(tx, `INSERT INTO cfrm_enrollment_members
          (community_id,member_id,account_key,secret_hash,delegation_digest,delegation,entry,updated_at)
          VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(community_id,member_id) DO UPDATE SET
          delegation_digest=excluded.delegation_digest,delegation=excluded.delegation,
          entry=excluded.entry,updated_at=excluded.updated_at`,
        [communityId, memberId, entry.accountKey, entry.secretHash, entry.delegationDigest, encodedDelegation, encodedEntry, entry.issuedAt]);
      });
      return value;
    },
    async pending(communityId, slot) {
      ensureOpen(); community(communityId);
      if (!slotValue(slot)) throw new TypeError('Invalid enrollment slot');
      return publicationRow(await one(client, `SELECT publication,installed FROM cfrm_enrollment_pending
        WHERE community_id=? AND slot=?`, [communityId, slot]));
    },
    async putPending(communityId, slot, publication) {
      community(communityId);
      if (!slotValue(slot) || !publication) throw new TypeError('Invalid pending publication');
      const encoded = json(publication);
      if (Buffer.byteLength(encoded) > maxPublicationBytes) throw new Error('Enrollment publication size limit');
      return transaction(async tx => {
        const prior = await one(tx, 'SELECT publication,installed FROM cfrm_enrollment_pending WHERE community_id=? AND slot=?', [communityId, slot]);
        if (prior) {
          if (prior.publication !== encoded) throw new Error('Pending enrollment publication conflict');
          return publicationRow(prior);
        }
        await execute(tx, 'INSERT INTO cfrm_enrollment_pending VALUES(?,?,?,0)', [communityId, slot, encoded]);
        // Keep the candidate being installed and retain newest other slots up
        // to both configured bounds. SQL measures UTF-8 bytes, not characters.
        const retained = await rows(tx, `SELECT slot,length(CAST(publication AS BLOB)) AS bytes
          FROM cfrm_enrollment_pending WHERE community_id=? ORDER BY slot DESC`, [communityId]);
        let total = Buffer.byteLength(encoded), kept = 1;
        for (const row of retained) {
          if (row.slot === slot) continue;
          if (kept < maxRetainedSlots && total + row.bytes <= maxPublicationBytes) { total += row.bytes; kept++; }
          else await execute(tx, 'DELETE FROM cfrm_enrollment_pending WHERE community_id=? AND slot=?', [communityId, row.slot]);
        }
        return { publication: JSON.parse(encoded), installed: false };
      });
    },
    async markInstalled(communityId, slot) {
      community(communityId);
      if (!slotValue(slot)) throw new TypeError('Invalid enrollment slot');
      await transaction(async tx => {
        const result = await execute(tx, 'UPDATE cfrm_enrollment_pending SET installed=1 WHERE community_id=? AND slot=?', [communityId, slot]);
        if (result.rowsAffected !== 1) throw new Error('Pending enrollment publication missing');
      });
    },
    close() { if (!closed) { closed = true; client.close(); } },
  });
}
