import { createHash, createHmac, createPublicKey, hkdfSync, randomBytes, timingSafeEqual, verify } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { Identity } from '@semaphore-protocol/identity';
import { inCurve, mulPointEscalar, r, subOrder } from '@zk-kit/baby-jubjub';

const json = value => Buffer.from(JSON.stringify(value));
const b64 = value => Buffer.from(value).toString('base64url');
const hash = value => createHash('sha256').update(value).digest();
const integer = value => Number.isSafeInteger(value) && value > 0;
const scope = value => typeof value === 'string' && /^[A-Za-z0-9._:/-]{1,256}$/.test(value);
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join(',') === [...keys].sort().join(',');

function bytes(value, length) {
  if (typeof value !== 'string' || value.length !== Math.ceil(length * 4 / 3) ||
    !/^[A-Za-z0-9_-]+$/.test(value)) throw new TypeError('Invalid public encoding');
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.length !== length || b64(decoded) !== value) throw new TypeError('Invalid public encoding');
  return decoded;
}
function scalar(value, limit = r) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,77})$/.test(value) || BigInt(value) >= limit) {
    throw new TypeError('Invalid canonical scalar');
  }
  return BigInt(value);
}
function commitment(value) {
  if (scalar(value) === 0n) throw new TypeError('A nonzero commitment is required');
  return value;
}
function point(input, nonneutral) {
  if (!Array.isArray(input) || input.length !== 2) throw new TypeError('Invalid point');
  const value = input.map(coordinate => scalar(coordinate));
  if (!inCurve(value) || (nonneutral && value[0] === 0n && value[1] === 1n)) {
    throw new TypeError('Invalid curve point');
  }
  // Existing audited-lineage arithmetic, with the enrollment subgroup assumption explicit.
  const multiple = mulPointEscalar(value, subOrder);
  if (multiple[0] !== 0n || multiple[1] !== 1n) throw new TypeError('Invalid subgroup');
  return value;
}
function grantShape(grant) {
  if (!exact(grant, ['version', 'issuerKeyId', 'communityId', 'memberId', 'chatPublicKey',
    'policyDigest', 'issuedAt', 'expiresAt', 'signature']) || grant.version !== 1 ||
    !scope(grant.communityId) || !integer(grant.issuedAt) || !integer(grant.expiresAt) ||
    grant.expiresAt <= grant.issuedAt) throw new TypeError('Invalid admission grant');
  for (const field of ['issuerKeyId', 'memberId', 'chatPublicKey', 'policyDigest']) bytes(grant[field], 32);
  bytes(grant.signature, 64);
}

/** Pass cvld wallet.storageKey('cfrm-semaphore'); client material never enters enrollment requests. */
export function deriveSemaphoreIdentity(walletMaterial, communityId) {
  if (!(walletMaterial instanceof Uint8Array) || walletMaterial.length !== 32 || !scope(communityId)) {
    throw new TypeError('32-byte wallet material and a canonical community are required');
  }
  const seed = new Uint8Array(hkdfSync('sha256', walletMaterial,
    Buffer.from('cfrm.semaphore.wallet.v1'), json(['cfrm.semaphore.identity.v1', communityId]), 32));
  // Identity retains its derived seed for signing; zeroing it here would corrupt the identity.
  return new Identity(seed);
}

export function enrollmentBytes(challenge) {
  if (!exact(challenge, ['communityId', 'memberId', 'chatPublicKey', 'commitment',
    'challengeId', 'issuedAt', 'expiresAt']) || !scope(challenge.communityId) ||
    !integer(challenge.issuedAt) || !integer(challenge.expiresAt) || challenge.expiresAt <= challenge.issuedAt) {
    throw new TypeError('Invalid enrollment challenge');
  }
  for (const field of ['memberId', 'chatPublicKey', 'challengeId']) bytes(challenge[field], 32);
  commitment(challenge.commitment);
  return json(['cfrm.semaphore.enroll.v1', challenge.communityId, challenge.memberId,
    challenge.chatPublicKey, challenge.commitment, challenge.challengeId, challenge.issuedAt, challenge.expiresAt]);
}
export function enrollmentMessage(challenge) {
  return (BigInt('0x' + hash(enrollmentBytes(challenge)).toString('hex')) >> 8n).toString();
}

/** Internal trusted persistence API. No direct remote bind operation is exposed. */
export function openEnrollmentLedger(path) {
  const db = new DatabaseSync(path, { allowExtension: false, enableForeignKeyConstraints: true,
    enableDoubleQuotedStringLiterals: false });
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF; PRAGMA busy_timeout=5000;
    CREATE TABLE IF NOT EXISTS enrollment_bindings (
      community TEXT NOT NULL, member TEXT NOT NULL, commitment TEXT NOT NULL,
      PRIMARY KEY(community,member), UNIQUE(community,commitment)) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS enrollment_replays (
      community TEXT NOT NULL, nonce BLOB NOT NULL, expires_at INTEGER NOT NULL,
      PRIMARY KEY(community,nonce)) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS enrollment_clock (
      community TEXT PRIMARY KEY, floor INTEGER NOT NULL) WITHOUT ROWID;`);
  return {
    bind(challenge, clock) {
      enrollmentBytes(challenge);
      if (typeof clock !== 'function') throw new TypeError('A live clock is required');
      const nonce = hash(bytes(challenge.challengeId, 32));
      db.exec('BEGIN IMMEDIATE');
      try {
        const now = clock();
        const floor = db.prepare('SELECT floor FROM enrollment_clock WHERE community=?').get(challenge.communityId)?.floor ?? 0;
        if (!integer(now) || now < floor || now < challenge.issuedAt || now >= challenge.expiresAt) {
          db.exec('COMMIT'); return false;
        }
        db.prepare(`INSERT INTO enrollment_clock(community,floor) VALUES (?,?)
          ON CONFLICT(community) DO UPDATE SET floor=excluded.floor`).run(challenge.communityId, now);
        db.prepare('DELETE FROM enrollment_replays WHERE community=? AND expires_at<=?').run(challenge.communityId, now);
        if (db.prepare('SELECT 1 FROM enrollment_replays WHERE community=? AND nonce=?').get(challenge.communityId, nonce)) {
          db.exec('COMMIT'); return false;
        }
        const old = db.prepare('SELECT commitment FROM enrollment_bindings WHERE community=? AND member=?')
          .get(challenge.communityId, challenge.memberId);
        const owner = db.prepare('SELECT member FROM enrollment_bindings WHERE community=? AND commitment=?')
          .get(challenge.communityId, challenge.commitment);
        if ((old && old.commitment !== challenge.commitment) || (owner && owner.member !== challenge.memberId)) {
          db.exec('COMMIT'); return false;
        }
        db.prepare(`INSERT INTO enrollment_bindings(community,member,commitment) VALUES (?,?,?)
          ON CONFLICT DO NOTHING`).run(challenge.communityId, challenge.memberId, challenge.commitment);
        db.prepare('INSERT INTO enrollment_replays(community,nonce,expires_at) VALUES (?,?,?)')
          .run(challenge.communityId, nonce, challenge.expiresAt);
        db.exec('COMMIT');
        return true;
      } catch (error) { db.exec('ROLLBACK'); throw error; }
    },
    members(communityId) {
      if (!scope(communityId)) throw new TypeError('Invalid community');
      return db.prepare('SELECT member AS memberId, commitment FROM enrollment_bindings WHERE community=? ORDER BY member')
        .all(communityId).map(row => ({ ...row }));
    },
    close() { if (db.isOpen) db.close(); },
  };
}

export function createEnrollmentService(options) {
  const { communityId, policyDigest, verifyAdmission, ledger, clock, challengeSeconds } = options;
  if (!scope(communityId) || typeof verifyAdmission !== 'function' || typeof clock !== 'function' ||
    typeof ledger?.bind !== 'function' || !(options.trustedPublicKey instanceof Uint8Array) ||
    options.trustedPublicKey.length !== 32 || !integer(challengeSeconds) || challengeSeconds > 300) {
    throw new TypeError('Explicit trusted enrollment configuration is required');
  }
  bytes(policyDigest, 32);
  const trustedPublicKey = Uint8Array.from(options.trustedPublicKey);
  const secret = randomBytes(32);
  let closed = false;
  let lastNow = 0;
  function time() {
    if (closed) throw new Error('Enrollment service is closed');
    const now = clock();
    if (!integer(now) || now < lastNow) throw new Error('Clock must advance monotonically');
    lastNow = now;
    return now;
  }
  const authenticate = challenge => createHmac('sha256', secret).update(enrollmentBytes(challenge)).digest();
  const admitted = async (grant, now) => (await verifyAdmission({ grant: structuredClone(grant),
    trustedPublicKey: Uint8Array.from(trustedPublicKey), communityId, policyDigest, now })) === true;
  return {
    async begin(grantInput, proposedCommitment) {
      grantShape(grantInput);
      commitment(proposedCommitment);
      const grant = structuredClone(grantInput);
      if (!(await admitted(grant, time()))) throw new Error('Admission rejected');
      const now = time();
      if (now < grant.issuedAt || now >= grant.expiresAt) throw new Error('Admission expired');
      const challenge = { communityId, memberId: grant.memberId, chatPublicKey: grant.chatPublicKey,
        commitment: proposedCommitment, challengeId: b64(randomBytes(32)), issuedAt: now,
        expiresAt: Math.min(now + challengeSeconds, grant.expiresAt) };
      return { challenge, authenticator: b64(authenticate(challenge)) };
    },
    async enroll(input) {
      try {
        if (!exact(input, ['grant', 'challenge', 'authenticator', 'publicKey', 'semaphoreSignature', 'chatSignature'])) return false;
        grantShape(input.grant);
        enrollmentBytes(input.challenge);
        bytes(input.authenticator, 32); bytes(input.chatSignature, 64);
        const { grant, challenge, authenticator, publicKey, semaphoreSignature, chatSignature } = structuredClone(input);
        const now = time();
        if (now < challenge.issuedAt || now >= challenge.expiresAt ||
          challenge.expiresAt - challenge.issuedAt > challengeSeconds ||
          !timingSafeEqual(bytes(authenticator, 32), authenticate(challenge))) return false;
        if (!(await admitted(grant, now)) || grant.communityId !== challenge.communityId ||
          grant.memberId !== challenge.memberId || grant.chatPublicKey !== challenge.chatPublicKey ||
          grant.expiresAt < challenge.expiresAt) return false;
        const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: grant.chatPublicKey }, format: 'jwk' });
        if (!verify(null, enrollmentBytes(challenge), key, bytes(chatSignature, 64))) return false;
        if (!exact(semaphoreSignature, ['R8', 'S'])) return false;
        const candidate = point(publicKey, true);
        const signature = { R8: point(semaphoreSignature.R8, false), S: scalar(semaphoreSignature.S, subOrder) };
        if (Identity.generateCommitment(candidate).toString() !== challenge.commitment ||
          !Identity.verifySignature(enrollmentMessage(challenge), signature, candidate)) return false;
        // Grant expiry clips the signed challenge; ledger rechecks time after all async verification.
        return ledger.bind(challenge, time);
      } catch { return false; }
    },
    close() { closed = true; secret.fill(0); },
  };
}
