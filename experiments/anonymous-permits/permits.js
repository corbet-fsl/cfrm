import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { RSABSSA } from '@cloudflare/blindrsa-ts';

const suite = RSABSSA.SHA384.PSS.Randomized();
const hash = (bytes) => createHash('sha256').update(bytes).digest();
const json = (value) => Buffer.from(JSON.stringify(value));
const encode = (value) => Buffer.from(value).toString('base64url');
const ownKeys = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join(',') === [...keys].sort().join(',');
function text(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9._:/-]{1,256}$/.test(value)) throw new TypeError('Invalid identifier');
  return value;
}
function integer(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError('Invalid integer');
  return value;
}
function decode(value, length) {
  if (typeof value !== 'string' || value.length > length * 2 || !/^[A-Za-z0-9_-]+$/.test(value)) throw new TypeError('Invalid encoding');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length !== length || encode(bytes) !== value) throw new TypeError('Invalid encoding');
  // Upstream uses Uint8Array.slice().buffer. Buffer.slice() instead keeps the
  // pooled backing allocation, which would verify unrelated bytes as well.
  return Uint8Array.from(bytes);
}
function validateContext(context) {
  text(context.scope); text(context.epoch);
  integer(context.notBefore); integer(context.expiresAt);
  if (context.expiresAt <= context.notBefore) throw new TypeError('Invalid validity interval');
}
function contextInfo(context) {
  validateContext(context);
  const key = context.publicKey;
  if (!key || key.kty !== 'RSA' || key.e !== 'AQAB') throw new TypeError('Invalid public key');
  decode(key.n, 384);
  // The trusted epoch catalog fixes scope, lifetime and public key for all members.
  const body = ['cfrm.contact.v1', context.scope, context.epoch, context.notBefore, context.expiresAt, key.kty, key.n, key.e];
  const domain = hash(json(body));
  return { id: encode(domain), domain, notBefore: context.notBefore, expiresAt: context.expiresAt };
}
function active(context, now) {
  integer(now);
  return now >= context.notBefore && now < context.expiresAt;
}
async function verificationKey(context) {
  // Blind RSA needs the public modulus; exporting a public key reveals no secret.
  return crypto.subtle.importKey('jwk', context.publicKey, { name: 'RSA-PSS', hash: 'SHA-384' }, true, ['verify']);
}

// A fresh key is generated for each scope/epoch, never separately per member.
export async function createEpoch({ scope, epoch, notBefore, expiresAt }) {
  validateContext({ scope, epoch, notBefore, expiresAt });
  const keys = await suite.generateKey({ publicExponent: Uint8Array.from([1, 0, 1]), modulusLength: 3072 });
  const publicKey = await crypto.subtle.exportKey('jwk', keys.publicKey);
  const publicContext = { scope, epoch, notBefore, expiresAt, publicKey };
  return { get public() { return structuredClone(publicContext); }, privateKey: keys.privateKey };
}

export function openLedger(path) {
  const db = new DatabaseSync(path);
  db.exec(`PRAGMA journal_mode=WAL;
    PRAGMA busy_timeout=5000;
    PRAGMA foreign_keys=ON;
    CREATE TABLE IF NOT EXISTS retirement (singleton INTEGER PRIMARY KEY CHECK(singleton=1), through INTEGER NOT NULL);
    INSERT INTO retirement(singleton,through) VALUES (1,0) ON CONFLICT DO NOTHING;
    CREATE TABLE IF NOT EXISTS contexts (id TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS allocations (
      context TEXT NOT NULL REFERENCES contexts(id) ON DELETE CASCADE,
      id TEXT NOT NULL, quota INTEGER NOT NULL, issued INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY(context,id));
    CREATE TABLE IF NOT EXISTS issuances (
      context TEXT NOT NULL, allocation TEXT NOT NULL, request_hash TEXT NOT NULL,
      signature TEXT NOT NULL, PRIMARY KEY(context,allocation,request_hash),
      FOREIGN KEY(context,allocation) REFERENCES allocations(context,id) ON DELETE CASCADE);
    CREATE TABLE IF NOT EXISTS spends (
      context TEXT NOT NULL REFERENCES contexts(id) ON DELETE CASCADE,
      nullifier TEXT NOT NULL, claim_hash TEXT, PRIMARY KEY(context,nullifier));`);
  function transaction(action) {
    db.exec('BEGIN IMMEDIATE');
    try { const result = action(); db.exec('COMMIT'); return result; }
    catch (error) { db.exec('ROLLBACK'); throw error; }
  }
  function register(info) {
    if (retired(info)) throw new Error('Epoch retired');
    db.prepare('INSERT INTO contexts(id,expires_at) VALUES (?,?) ON CONFLICT(id) DO NOTHING').run(info.id, info.expiresAt);
  }
  function retired(info) {
    return info.expiresAt <= db.prepare('SELECT through FROM retirement WHERE singleton=1').get().through;
  }
  return {
    allocate(info, allocation, quota) {
      text(allocation); integer(quota);
      return transaction(() => {
        register(info);
        const prior = db.prepare('SELECT quota FROM allocations WHERE context=? AND id=?').get(info.id, allocation);
        if (prior) {
          if (prior.quota !== quota) throw new Error('Allocation already fixed');
          return;
        }
        db.prepare('INSERT INTO allocations(context,id,quota) VALUES (?,?,?)').run(info.id, allocation, quota);
      });
    },
    prior(info, allocation, requestHash) {
      return db.prepare('SELECT signature FROM issuances WHERE context=? AND allocation=? AND request_hash=?')
        .get(info.id, allocation, requestHash)?.signature;
    },
    hasAllowance(info, allocation) {
      return Boolean(db.prepare('SELECT 1 FROM allocations WHERE context=? AND id=? AND issued<quota').get(info.id, allocation));
    },
    issue(info, allocation, requestHash, signature) {
      return transaction(() => {
        const prior = this.prior(info, allocation, requestHash);
        if (prior) return prior;
        const updated = db.prepare('UPDATE allocations SET issued=issued+1 WHERE context=? AND id=? AND issued<quota').run(info.id, allocation);
        if (Number(updated.changes) !== 1) throw new Error('No allowance');
        db.prepare('INSERT INTO issuances(context,allocation,request_hash,signature) VALUES (?,?,?,?)')
          .run(info.id, allocation, requestHash, signature);
        return signature;
      });
    },
    spend(info, nullifier, clock, claimHash) {
      return transaction(() => {
        // Re-read trusted time after acquiring the write lock; another process
        // may have pruned expired replay state while verification was pending.
        if (!active(info, clock()) || retired(info)) return false;
        register(info);
        const prior = db.prepare('SELECT claim_hash FROM spends WHERE context=? AND nullifier=?').get(info.id, nullifier);
        if (prior) return claimHash !== undefined && prior.claim_hash === claimHash;
        db.prepare('INSERT INTO spends(context,nullifier,claim_hash) VALUES (?,?,?)').run(info.id, nullifier, claimHash ?? null);
        return true;
      });
    },
    prune(now) {
      integer(now);
      transaction(() => {
        // One durable scalar prevents wall-clock rollback from reactivating
        // epochs whose spent-token state has already been discarded.
        db.prepare('UPDATE retirement SET through=max(through,?) WHERE singleton=1').run(now);
        db.prepare('DELETE FROM contexts WHERE expires_at<=?').run(now);
      });
    },
    counts() {
      return Object.fromEntries(['allocations', 'issuances', 'spends'].map((name) => [name, db.prepare(`SELECT count(*) AS n FROM ${name}`).get().n]));
    },
    close() { if (db.isOpen) db.close(); },
  };
}

export function createIssuer(epoch, ledger, clock) {
  const context = structuredClone(epoch.public);
  const info = contextInfo(context);
  const privateKey = epoch.privateKey;
  if (typeof clock !== 'function') throw new TypeError('Explicit clock required');
  return {
    // Trusted numerical rules call this method; it is not a client admission API.
    allocate(allocation, quota) {
      if (!active(context, clock())) throw new Error('Inactive epoch');
      return ledger.allocate(info, allocation, quota);
    },
    async issue(allocation, request) {
      try {
        text(allocation);
        if (!active(context, clock()) || !ownKeys(request, ['blinded'])) throw new Error();
        const blinded = decode(request.blinded, 384);
        const requestHash = encode(hash(blinded));
        const prior = ledger.prior(info, allocation, requestHash);
        if (prior) return { blindSignature: prior };
        // Reject missing/exhausted trusted allocations before private-key work.
        // The final transaction still handles concurrent requests atomically.
        if (!ledger.hasAllowance(info, allocation)) throw new Error();
        // Crypto completes before charging. The durable transaction is idempotent.
        const signature = encode(await suite.blindSign(privateKey, blinded));
        if (!active(context, clock())) throw new Error();
        return { blindSignature: ledger.issue(info, allocation, requestHash, signature) };
      } catch { throw new Error('Permit issuance rejected'); }
    },
  };
}

export async function preparePermit(publicContext) {
  const context = structuredClone(publicContext);
  const info = contextInfo(context);
  const publicKey = await verificationKey(context);
  const prepared = suite.prepare(Buffer.concat([info.domain, randomBytes(32)]));
  const { blindedMsg, inv } = await suite.blind(publicKey, prepared);
  return {
    request: { blinded: encode(blindedMsg) },
    async finish(response) {
      if (!ownKeys(response, ['blindSignature'])) throw new TypeError('Invalid issuer response');
      const blindSignature = decode(response.blindSignature, 384);
      const signature = await suite.finalize(publicKey, prepared, blindSignature, inv);
      return { message: encode(prepared), signature: encode(signature) };
    },
  };
}

async function validateAndSpend(publicContext, ledger, permit, clock, claimHash) {
  try {
    if (typeof clock !== 'function') return false;
    const now = clock();
    const context = structuredClone(publicContext);
    const info = contextInfo(context);
    if (!active(context, now) || !ownKeys(permit, ['message', 'signature'])) return false;
    const message = decode(permit.message, 96);
    const signature = decode(permit.signature, 384);
    if (!timingSafeEqual(info.domain, message.subarray(32, 64))) return false;
    const publicKey = await verificationKey(context);
    if (!(await suite.verify(publicKey, signature, message))) return false;
    // High-entropy nonce, not a hash of enumerable member/recipient pairs.
    const nullifier = encode(hash(Buffer.concat([info.domain, message.subarray(64)])));
    return ledger.spend(info, nullifier, clock, claimHash);
  } catch { return false; }
}

export async function redeemPermit(publicContext, ledger, permit, clock) {
  return validateAndSpend(publicContext, ledger, permit, clock);
}
export function prepareRedemption(permit) {
  if (!ownKeys(permit, ['message', 'signature'])) throw new TypeError('Invalid permit');
  decode(permit.message, 96); decode(permit.signature, 384);
  return { permit: { message: permit.message, signature: permit.signature }, claim: encode(randomBytes(32)) };
}
export async function redeemIntroduction(publicContext, ledger, redemption, clock) {
  try {
    if (!ownKeys(redemption, ['permit', 'claim'])) return { accepted: false };
    const claimHash = encode(hash(Buffer.concat([Buffer.from('cfrm.redemption.v1'), decode(redemption.claim, 32)])));
    const accepted = await validateAndSpend(publicContext, ledger, redemption.permit, clock, claimHash);
    return { accepted };
  } catch { return { accepted: false }; }
}
