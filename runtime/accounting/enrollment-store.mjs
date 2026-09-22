// Durable server-side enrollment registry. This module is intentionally the
// only accounting enrollment module that imports Node's SQLite implementation.
import { DatabaseSync } from 'node:sqlite';

const clone = value => structuredClone(value);
const json = value => JSON.stringify(value);
const parse = value => JSON.parse(value);
const positive = value => Number.isSafeInteger(value) && value > 0;
const nonnegative = value => Number.isSafeInteger(value) && value >= 0;
const hex32 = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const hex64 = value => typeof value === 'string' && /^[0-9a-f]{128}$/.test(value);

function checkRecord(value) {
  if (!value || typeof value !== 'object' || !value.delegation || !value.entry
      || !hex64(value.entry.accountKey) || !hex32(value.entry.secretHash)
      || !hex32(value.entry.delegationDigest)) throw new TypeError('Invalid enrollment registry record');
}

/**
 * `path`, `maxMembers`, and the SQLite busy timeout are deployment choices;
 * there are no implicit in-memory or roster limits. All writes use durable
 * FULL/WAL transactions and the pending row is written before installation.
 */
export function createEnrollmentStore({ path, maxMembers, maxRetainedSlots, maxPublicationBytes, busyTimeoutMs = 5000 } = {}) {
  if (typeof path !== 'string' || path.length === 0 || !Number.isSafeInteger(maxMembers)
      || path === ':memory:' || maxMembers < 1 || maxMembers > 65536
      || !Number.isSafeInteger(maxRetainedSlots) || maxRetainedSlots < 1 || maxRetainedSlots > 65536
      || !Number.isSafeInteger(maxPublicationBytes) || maxPublicationBytes < 1 || maxPublicationBytes > 64 * 1024 * 1024
      || !Number.isSafeInteger(busyTimeoutMs)
      || busyTimeoutMs < 0 || busyTimeoutMs > 120000) throw new TypeError('Explicit enrollment store configuration required');
  const db = new DatabaseSync(path);
  db.enableLoadExtension(false);
  db.exec(`PRAGMA journal_mode = WAL;
           PRAGMA synchronous = FULL;
           PRAGMA foreign_keys = ON;
           PRAGMA trusted_schema = OFF;
           CREATE TABLE IF NOT EXISTS cfrm_enrollment_clock (
             community_id TEXT PRIMARY KEY, clock INTEGER NOT NULL CHECK(clock > 0)
           ) STRICT, WITHOUT ROWID;
           CREATE TABLE IF NOT EXISTS cfrm_enrollment_members (
             community_id TEXT NOT NULL, member_id TEXT NOT NULL,
             account_key TEXT NOT NULL CHECK(length(account_key)=128),
             secret_hash TEXT NOT NULL CHECK(length(secret_hash)=64),
             delegation_digest TEXT NOT NULL CHECK(length(delegation_digest)=64),
             delegation TEXT NOT NULL, entry TEXT NOT NULL,
             updated_at INTEGER NOT NULL CHECK(updated_at > 0),
             PRIMARY KEY(community_id, member_id)
           ) STRICT, WITHOUT ROWID;
           CREATE TABLE IF NOT EXISTS cfrm_enrollment_pending (
             community_id TEXT NOT NULL, slot INTEGER NOT NULL CHECK(slot >= 0),
             publication TEXT NOT NULL, installed INTEGER NOT NULL CHECK(installed IN (0,1)),
             PRIMARY KEY(community_id, slot)
           ) STRICT, WITHOUT ROWID;`);
  db.exec(`PRAGMA busy_timeout = ${busyTimeoutMs};`);
  let closed = false;
  const ensureOpen = () => { if (closed) throw new Error('Enrollment store is closed'); };
  const transaction = (fn) => {
    ensureOpen(); db.exec('BEGIN IMMEDIATE;');
    try { const value = fn(); db.exec('COMMIT;'); return value; }
    catch (error) { try { db.exec('ROLLBACK;'); } catch {} throw error; }
  };
  return Object.freeze({
    async observeClock(communityId, now) {
      ensureOpen();
      if (typeof communityId !== 'string' || !positive(now)) throw new TypeError('Invalid enrollment clock');
      transaction(() => {
        const prior = db.prepare('SELECT clock FROM cfrm_enrollment_clock WHERE community_id=?').get(communityId);
        if (prior && now < prior.clock) throw new Error('Enrollment clock moved backwards');
        if (prior) db.prepare('UPDATE cfrm_enrollment_clock SET clock=? WHERE community_id=?').run(now, communityId);
        else db.prepare('INSERT INTO cfrm_enrollment_clock VALUES(?,?)').run(communityId, now);
      });
    },
    async list(communityId) {
      ensureOpen();
      if (typeof communityId !== 'string') throw new TypeError('Invalid enrollment community');
      return db.prepare('SELECT delegation,entry,delegation_digest AS digest FROM cfrm_enrollment_members WHERE community_id=? ORDER BY member_id').all(communityId)
        .map(row => ({ delegation: parse(row.delegation), entry: parse(row.entry), digest: row.digest }));
    },
    async upsert(communityId, value) {
      ensureOpen();
      if (typeof communityId !== 'string') throw new TypeError('Invalid enrollment community');
      checkRecord(value);
      const memberId = value.entry.memberId;
      if (typeof memberId !== 'string' || !memberId) throw new TypeError('Invalid enrollment member');
      transaction(() => {
        const prior = db.prepare('SELECT account_key,secret_hash,delegation_digest,delegation,entry FROM cfrm_enrollment_members WHERE community_id=? AND member_id=?').get(communityId, memberId);
        if (prior && (prior.account_key !== value.entry.accountKey || prior.secret_hash !== value.entry.secretHash)) {
          throw new Error('Enrollment account binding is immutable');
        }
        if (prior) {
          const priorEntry = parse(prior.entry);
          const sameRetry = prior.delegation_digest === value.entry.delegationDigest
            && prior.delegation === json(value.delegation) && prior.entry === json(value.entry);
          if (!sameRetry && value.entry.issuedAt < priorEntry.issuedAt) throw new Error('Enrollment issued time moved backwards');
          if (!sameRetry && value.entry.issuedAt === priorEntry.issuedAt) throw new Error('Conflicting enrollment renewal');
          if (sameRetry) return;
        }
        if (!prior) {
          const count = db.prepare('SELECT COUNT(*) AS count FROM cfrm_enrollment_members WHERE community_id=?').get(communityId).count;
          if (count >= maxMembers) throw new Error('Enrollment member cap reached');
        }
        const sql = `INSERT INTO cfrm_enrollment_members
          (community_id,member_id,account_key,secret_hash,delegation_digest,delegation,entry,updated_at)
          VALUES(?,?,?,?,?,?,?,?)
          ON CONFLICT(community_id,member_id) DO UPDATE SET
          delegation_digest=excluded.delegation_digest,delegation=excluded.delegation,
          entry=excluded.entry,updated_at=excluded.updated_at`;
        db.prepare(sql).run(communityId, memberId, value.entry.accountKey, value.entry.secretHash,
          value.entry.delegationDigest, json(value.delegation), json(value.entry), value.entry.issuedAt);
      });
      return clone(value);
    },
    async pending(communityId, slot) {
      ensureOpen();
      if (typeof communityId !== 'string' || !nonnegative(slot)) throw new TypeError('Invalid enrollment slot');
      const row = db.prepare('SELECT publication,installed FROM cfrm_enrollment_pending WHERE community_id=? AND slot=?').get(communityId, slot);
      return row ? { publication: parse(row.publication), installed: row.installed === 1 } : null;
    },
    async putPending(communityId, slot, publication) {
      ensureOpen();
      if (typeof communityId !== 'string' || !nonnegative(slot) || !publication) throw new TypeError('Invalid pending publication');
      const encoded = json(publication);
      if (Buffer.byteLength(encoded, 'utf8') > maxPublicationBytes) throw new Error('Enrollment publication size limit');
      return transaction(() => {
        const prior = db.prepare('SELECT publication,installed FROM cfrm_enrollment_pending WHERE community_id=? AND slot=?').get(communityId, slot);
        if (prior) {
          if (prior.publication !== encoded) throw new Error('Pending enrollment publication conflict');
          return { publication: parse(prior.publication), installed: prior.installed === 1 };
        }
        db.prepare('INSERT INTO cfrm_enrollment_pending VALUES(?,?,?,0)').run(communityId, slot, encoded);
        const retained = db.prepare('SELECT slot FROM cfrm_enrollment_pending WHERE community_id=? ORDER BY slot DESC').all(communityId);
        for (const row of retained.slice(maxRetainedSlots)) {
          db.prepare('DELETE FROM cfrm_enrollment_pending WHERE community_id=? AND slot=?').run(communityId, row.slot);
        }
        let total = db.prepare('SELECT COALESCE(SUM(length(publication)),0) AS bytes FROM cfrm_enrollment_pending WHERE community_id=?').get(communityId).bytes;
        while (total > maxPublicationBytes) {
          const oldest = db.prepare('SELECT slot,length(publication) AS bytes FROM cfrm_enrollment_pending WHERE community_id=? AND slot<>? ORDER BY slot ASC LIMIT 1').get(communityId, slot);
          if (!oldest) throw new Error('Enrollment publication retention limit');
          db.prepare('DELETE FROM cfrm_enrollment_pending WHERE community_id=? AND slot=?').run(communityId, oldest.slot);
          total -= oldest.bytes;
        }
        return { publication: clone(publication), installed: false };
      });
    },
    async markInstalled(communityId, slot) {
      ensureOpen();
      if (typeof communityId !== 'string' || !nonnegative(slot)) throw new TypeError('Invalid pending publication');
      transaction(() => {
        const result = db.prepare('UPDATE cfrm_enrollment_pending SET installed=1 WHERE community_id=? AND slot=?').run(communityId, slot);
        if (result.changes !== 1) throw new Error('Pending enrollment publication missing');
      });
    },
    close() { if (!closed) { closed = true; db.close(); } },
  });
}
