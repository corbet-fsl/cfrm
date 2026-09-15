// Isolated STORAGE experiment. This module does not verify proofs or authorize
// owners. Only the trusted verifier may supply an accepted public statement.
import { DatabaseSync } from 'node:sqlite';
import { createHash, randomBytes } from 'node:crypto';
import { checkScheme } from './hashes.mjs';

const LIMIT = Number.MAX_SAFE_INTEGER;
const fail = code => { throw new Error('AccountingLedger:' + code); };
const digest = value => createHash('sha256').update(value).digest('hex');
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const hex32 = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const integer = value => Number.isSafeInteger(value) && value >= 0;
const STATEMENT_KEYS = ['community', 'owner', 'hashScheme', 'circuitSha256', 'verificationKeySha256',
  'checkpoint', 'old', 'next', 'marker', 'now', 'proofSha256', 'publicInputsSha256'];
const SCOPE_KEYS = ['community', 'owner', 'hashScheme', 'circuitSha256', 'verificationKeySha256', 'checkpoint'];
const scopeFor = statement => Object.fromEntries(SCOPE_KEYS.map(key => [key, statement[key]]));
const scopeJson = statement => JSON.stringify(scopeFor(statement));

export function immutableStatement(value) {
  if (!exact(value, STATEMENT_KEYS)) fail('StatementShape');
  checkScheme(value.hashScheme);
  for (const key of STATEMENT_KEYS) {
    if (key !== 'hashScheme' && key !== 'now' && !hex32(value[key])) fail('StatementEncoding');
  }
  if (!integer(value.now)) fail('ClockBounds');
  return Object.freeze(Object.fromEntries(STATEMENT_KEYS.map(key => [key, value[key]])));
}

// Call AFTER cryptographic verification and independent public-input pinning.
// Canonical public-input values and exact binary proof bytes are both bound.
export function statementAfterVerification(proof, scope) {
  return immutableStatement({ community: proof.community, owner: proof.owner,
    hashScheme: scope.hashScheme, circuitSha256: scope.circuitSha256,
    verificationKeySha256: scope.verificationKeySha256, checkpoint: proof.root,
    old: proof.old, next: proof.next, marker: proof.marker, now: Number(proof.now),
    proofSha256: digest(proof.proof),
    publicInputsSha256: digest(JSON.stringify(proof.publicInputs.map(value => BigInt(value).toString()))) });
}

export function ledgerRequest(statement, expectedVersion, requestId = randomBytes(32).toString('hex')) {
  statement = immutableStatement(statement);
  if (!integer(expectedVersion) || expectedVersion >= LIMIT) fail('VersionBounds');
  if (!hex32(requestId)) fail('RequestId');
  const statementDigest = digest(JSON.stringify(['cfrm.accounting.statement.fixture.v1', statement]));
  const requestDigest = digest(JSON.stringify(['cfrm.accounting.request.fixture.v1', requestId,
    expectedVersion, statementDigest, statement]));
  return Object.freeze({ requestId, expectedVersion, statement, statementDigest, requestDigest });
}

function checkedRequest(value) {
  if (!exact(value, ['requestId', 'expectedVersion', 'statement', 'statementDigest', 'requestDigest'])) fail('RequestShape');
  const checked = ledgerRequest(value.statement, value.expectedVersion, value.requestId);
  if (checked.statementDigest !== value.statementDigest || checked.requestDigest !== value.requestDigest) fail('RequestDigest');
  return checked;
}

export class ExperimentalLedger {
  #db;
  #now;
  constructor(path, { now } = {}) {
    if (!integer(now)) fail('ClockBounds');
    this.#now = now; // Synthetic verifier time, never an implicit product clock.
    this.#db = new DatabaseSync(path, { timeout: 5000, allowExtension: false });
    try {
      this.#db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;');
      this.#transaction(() => {
        const version = this.#db.prepare('PRAGMA user_version').get().user_version;
        if (version !== 0 && version !== 1) fail('SchemaVersion');
        if (version === 0) {
          if (this.#db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all().length) fail('UnversionedDatabase');
          this.#db.exec(`
            CREATE TABLE metadata(id INTEGER PRIMARY KEY CHECK(id=1), high_time INTEGER NOT NULL CHECK(high_time BETWEEN 0 AND ${LIMIT})) STRICT;
            CREATE TABLE accounts(community TEXT NOT NULL, owner TEXT NOT NULL, scope TEXT NOT NULL,
              seed_commitment TEXT NOT NULL, commitment TEXT NOT NULL,
              version INTEGER NOT NULL CHECK(version BETWEEN 0 AND ${LIMIT}),
              last_time INTEGER NOT NULL CHECK(last_time BETWEEN 0 AND ${LIMIT}),
              PRIMARY KEY(community,owner)) STRICT;
            CREATE TABLE markers(community TEXT NOT NULL, owner TEXT NOT NULL, marker TEXT NOT NULL,
              PRIMARY KEY(community,owner,marker), FOREIGN KEY(community,owner) REFERENCES accounts(community,owner)) STRICT;
            CREATE TABLE requests(community TEXT NOT NULL, owner TEXT NOT NULL, request_id TEXT NOT NULL,
              request_digest TEXT NOT NULL, statement_digest TEXT NOT NULL, response TEXT NOT NULL,
              PRIMARY KEY(community,owner,request_id), FOREIGN KEY(community,owner) REFERENCES accounts(community,owner)) STRICT;
            PRAGMA user_version=1;
          `);
          this.#db.prepare('INSERT INTO metadata VALUES(1,?)').run(now);
        }
        const metadata = this.#db.prepare('SELECT high_time FROM metadata WHERE id=1').get();
        if (!metadata || !integer(metadata.high_time)) fail('DurableClockBounds');
        if (now < metadata.high_time) fail('ClockRollback');
        for (const account of this.#db.prepare('SELECT * FROM accounts').all()) this.#checkAccount(account);
        this.#db.prepare('UPDATE metadata SET high_time=? WHERE id=1').run(now);
      });
    } catch (error) { this.#db.close(); this.#db = undefined; throw error; }
  }

  #transaction(work) {
    this.#db.exec('BEGIN IMMEDIATE');
    try { const result = work(); this.#db.exec('COMMIT'); return result; }
    catch (error) { try { this.#db.exec('ROLLBACK'); } catch {} throw error; }
  }

  #checkAccount(account) {
    if (!integer(account.version) || !integer(account.last_time) || account.last_time > this.#now) fail('DurableVersionOrClock');
    if (![account.community, account.owner, account.seed_commitment, account.commitment].every(hex32)) fail('DurableAccountEncoding');
    let scope;
    try { scope = JSON.parse(account.scope); } catch { fail('DurableScope'); }
    if (!exact(scope, SCOPE_KEYS) || scopeJson(scope) !== account.scope
        || scope.community !== account.community || scope.owner !== account.owner) fail('DurableScope');
    checkScheme(scope.hashScheme);
    for (const key of SCOPE_KEYS) if (key !== 'hashScheme' && !hex32(scope[key])) fail('DurableScope');
  }

  #clock() {
    const { high_time: high } = this.#db.prepare('SELECT high_time FROM metadata WHERE id=1').get() ?? {};
    if (!integer(high) || this.#now < high) fail('ClockRollback');
  }

  // Deliberately synthetic initial reserved state. Never a production genesis.
  seedSynthetic(statement) {
    statement = immutableStatement(statement);
    return this.#transaction(() => {
      this.#clock();
      if (statement.now !== this.#now) fail('StatementTime');
      if (this.#db.prepare('SELECT 1 FROM accounts WHERE community=? AND owner=?').get(statement.community, statement.owner)) fail('GenesisExists');
      this.#db.prepare('INSERT INTO accounts VALUES(?,?,?,?,?,?,?)').run(statement.community,
        statement.owner, scopeJson(statement), statement.old, statement.old, 0, this.#now);
    });
  }

  accept(request) {
    request = checkedRequest(request); // Snapshot/freeze before touching storage.
    const s = request.statement;
    return this.#transaction(() => {
      this.#clock();
      const account = this.#db.prepare('SELECT * FROM accounts WHERE community=? AND owner=?').get(s.community, s.owner);
      if (!account) fail('UnknownAccount');
      this.#checkAccount(account);
      const cached = this.#db.prepare('SELECT * FROM requests WHERE community=? AND owner=? AND request_id=?')
        .get(s.community, s.owner, request.requestId);
      if (cached) {
        if (cached.request_digest !== request.requestDigest || cached.statement_digest !== request.statementDigest) fail('RequestIdReuse');
        // Return the exact previously stored bytes, even after accepted proof time.
        return Object.freeze({ cached: true, response: cached.response });
      }
      if (account.scope !== scopeJson(s)) fail('ScopeMismatch');
      if (s.now !== this.#now) fail('StatementTime');
      if (account.version !== request.expectedVersion || account.commitment !== s.old) fail('StateConflict');
      if (this.#db.prepare('SELECT 1 FROM markers WHERE community=? AND owner=? AND marker=?').get(s.community, s.owner, s.marker)) fail('MarkerSpent');
      const nextVersion = request.expectedVersion + 1;
      const response = JSON.stringify({ domain: 'cfrm.accounting.acceptance.fixture.v1',
        community: s.community, owner: s.owner, scope: scopeFor(s), requestId: request.requestId,
        requestDigest: request.requestDigest, statementDigest: request.statementDigest,
        proofSha256: s.proofSha256, publicInputsSha256: s.publicInputsSha256,
        previousVersion: request.expectedVersion, nextVersion, previousCommitment: s.old,
        nextCommitment: s.next, marker: s.marker, acceptedAt: this.#now });
      this.#db.prepare('INSERT INTO markers VALUES(?,?,?)').run(s.community, s.owner, s.marker);
      const changed = this.#db.prepare('UPDATE accounts SET commitment=?,version=?,last_time=? WHERE community=? AND owner=? AND version=? AND commitment=?')
        .run(s.next, nextVersion, this.#now, s.community, s.owner, request.expectedVersion, s.old);
      if (Number(changed.changes) !== 1) fail('StateConflict');
      this.#db.prepare('INSERT INTO requests VALUES(?,?,?,?,?,?)').run(s.community, s.owner,
        request.requestId, request.requestDigest, request.statementDigest, response);
      return Object.freeze({ cached: false, response });
    });
  }

  status(community, owner) {
    if (!hex32(community) || !hex32(owner)) fail('OwnerEncoding');
    return this.#transaction(() => {
      this.#clock();
      const account = this.#db.prepare('SELECT * FROM accounts WHERE community=? AND owner=?').get(community, owner);
      if (!account) fail('UnknownAccount');
      this.#checkAccount(account);
      return Object.freeze({ commitment: account.commitment, version: account.version,
        markers: this.#db.prepare('SELECT count(*) AS n FROM markers WHERE community=? AND owner=?').get(community, owner).n,
        requests: this.#db.prepare('SELECT count(*) AS n FROM requests WHERE community=? AND owner=?').get(community, owner).n });
    });
  }

  close() { if (this.#db) { this.#db.close(); this.#db = undefined; } }
}
