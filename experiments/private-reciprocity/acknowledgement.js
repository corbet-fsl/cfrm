import { createHash } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import { Group } from '@semaphore-protocol/group';
import { generateProof, verifyProof } from '@semaphore-protocol/proof';

// The commitment-only checkpoint integration has its own fail-first specification.
export function proveRegisteredAcknowledgement() { throw new Error('Registered checkpoint specification precedes implementation'); }
export function acceptRegisteredAcknowledgement() { throw new Error('Registered checkpoint specification precedes implementation'); }

const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const UINT256 = 1n << 256n;
const json = value => Buffer.from(JSON.stringify(value));
const digest = value => createHash('sha256').update(json(value)).digest('base64url');
const scalarHash = value => BigInt('0x' + createHash('sha256').update(json(value)).digest('hex')).toString();
const positive = value => Number.isSafeInteger(value) && value > 0;
const text = value => typeof value === 'string' && /^[A-Za-z0-9._:/-]{1,256}$/.test(value);
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join(',') === [...keys].sort().join(',');

function publicId(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value) ||
    Buffer.from(value, 'base64url').toString('base64url') !== value) throw new TypeError('Invalid member ID');
  return value;
}
function numeric(value, maximum = FIELD) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,77})$/.test(value) || BigInt(value) >= maximum) {
    throw new TypeError('Invalid canonical scalar');
  }
  return value;
}
function scalarBytes(value) {
  numeric(value, UINT256);
  return Buffer.from(BigInt(value).toString(16).padStart(64, '0'), 'hex');
}

/** Trusted, whole qualified set; it is not a public live-profile roster. */
export function freezeEligibility(input) {
  if (!text(input.communityId) || !text(input.epoch) || !positive(input.notBefore) ||
    !positive(input.expiresAt) || input.expiresAt <= input.notBefore || input.depth !== 7 ||
    !positive(input.minAnonymity) || input.minAnonymity < 16 || input.minAnonymity > 128 ||
    !Array.isArray(input.members) || input.members.length < 2 || input.members.length > 129) {
    throw new TypeError('Invalid explicit frozen eligibility bounds');
  }
  const members = input.members.map(member => {
    if (!exact(member, ['memberId', 'commitment']) || member.commitment === '0') throw new TypeError('Invalid eligible member');
    return Object.freeze({ memberId: publicId(member.memberId), commitment: numeric(member.commitment) });
  }).sort((a, b) => a.memberId < b.memberId ? -1 : a.memberId > b.memberId ? 1 : 0);
  if (new Set(members.map(member => member.memberId)).size !== members.length ||
    new Set(members.map(member => member.commitment)).size !== members.length) {
    throw new TypeError('Duplicate qualified identity');
  }
  const snapshot = { communityId: input.communityId, epoch: input.epoch,
    notBefore: input.notBefore, expiresAt: input.expiresAt,
    members: Object.freeze(members), minAnonymity: input.minAnonymity, depth: input.depth };
  return Object.freeze({ ...snapshot, digest: digest(['cfrm.eligible.v1', snapshot]) });
}

function excludedGroup(snapshot, senderId) {
  publicId(senderId);
  if (!snapshot.members.some(member => member.memberId === senderId)) throw new Error('Sender is not qualified');
  const others = snapshot.members.filter(member => member.memberId !== senderId);
  if (others.length < snapshot.minAnonymity) throw new Error('Insufficient anonymity set');
  return new Group(others.map(member => BigInt(member.commitment)));
}

export function acknowledgementContext(trustedSnapshot, senderId) {
  const snapshot = freezeEligibility(trustedSnapshot);
  const group = excludedGroup(snapshot, senderId);
  return Object.freeze({
    communityId: snapshot.communityId, epoch: snapshot.epoch,
    notBefore: snapshot.notBefore, expiresAt: snapshot.expiresAt,
    senderId, eligibleDigest: snapshot.digest, root: group.root.toString(),
    depth: snapshot.depth, anonymitySetSize: snapshot.members.length - 1,
    // Stable across epochs: one acknowledgement per private identity / sender.
    scope: scalarHash(['cfrm.ack.scope.v1', snapshot.communityId, senderId]),
    message: scalarHash(['cfrm.ack.message.v1', snapshot.communityId, snapshot.epoch,
      snapshot.digest, senderId, snapshot.notBefore, snapshot.expiresAt]),
  });
}

function expectedContext(snapshot, proposed) {
  const expected = acknowledgementContext(snapshot, proposed?.senderId);
  if (!exact(proposed, Object.keys(expected)) || Object.keys(expected).some(key => proposed[key] !== expected[key])) {
    throw new Error('Proposed context is not the complete trusted sender-excluded set');
  }
  return expected;
}

async function pinnedArtifacts(artifacts) {
  const manifest = JSON.parse(await readFile(new URL('./artifacts.json', import.meta.url), 'utf8'));
  if (!exact(artifacts, ['wasm', 'zkey'])) throw new TypeError('Explicit pinned artifacts required');
  for (const [kind, entry] of Object.entries(manifest.files)) {
    if (typeof artifacts[kind] !== 'string' || (await stat(artifacts[kind])).size !== entry.bytes) {
      throw new Error('Unexpected proving artifact size');
    }
    const bytes = await readFile(artifacts[kind]);
    if (createHash('sha256').update(bytes).digest('hex') !== entry.sha256) throw new Error('Proving artifact hash mismatch');
  }
  return artifacts;
}

export async function proveAcknowledgement(identity, trustedSnapshot, proposed, artifacts) {
  const snapshot = freezeEligibility(trustedSnapshot);
  const context = expectedContext(snapshot, proposed);
  const group = excludedGroup(snapshot, context.senderId);
  if (group.indexOf(identity.commitment) < 0) throw new Error('An eligible distinct identity is required');
  return generateProof(identity, group, context.message, context.scope, context.depth, await pinnedArtifacts(artifacts));
}

function active(context, now) {
  return positive(now) && now >= context.notBefore && now < context.expiresAt;
}

export function openAcknowledgementLedger(path) {
  const db = new DatabaseSync(path);
  db.exec(`PRAGMA journal_mode=WAL;
    PRAGMA busy_timeout=5000;
    CREATE TABLE IF NOT EXISTS acknowledgements (
      scope BLOB NOT NULL, nullifier BLOB NOT NULL,
      PRIMARY KEY(scope,nullifier)) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS credits (
      scope BLOB PRIMARY KEY, total INTEGER NOT NULL) WITHOUT ROWID;`);
  return {
    accept(context, nullifier, clock) {
      const scope = scalarBytes(context.scope);
      const nonce = scalarBytes(numeric(nullifier));
      db.exec('BEGIN IMMEDIATE');
      try {
        if (!active(context, clock())) { db.exec('COMMIT'); return false; }
        const inserted = db.prepare('INSERT INTO acknowledgements(scope,nullifier) VALUES (?,?) ON CONFLICT DO NOTHING').run(scope, nonce);
        if (Number(inserted.changes) !== 1) { db.exec('COMMIT'); return false; }
        db.prepare('INSERT INTO credits(scope,total) VALUES (?,1) ON CONFLICT(scope) DO UPDATE SET total=total+1').run(scope);
        db.exec('COMMIT');
        return true;
      } catch (error) { db.exec('ROLLBACK'); throw error; }
    },
    credits(scope) { return db.prepare('SELECT total FROM credits WHERE scope=?').get(scalarBytes(scope))?.total ?? 0; },
    counts() {
      const acknowledgements = db.prepare('SELECT count(*) AS n FROM acknowledgements').get().n;
      return { acknowledgements, scopes: db.prepare('SELECT count(*) AS n FROM credits').get().n,
        rawNullifierBytes: acknowledgements * 64,
        sqlitePageBytes: db.prepare('PRAGMA page_count').get().page_count * db.prepare('PRAGMA page_size').get().page_size };
    },
    close() { if (db.isOpen) db.close(); },
  };
}

export async function acceptAcknowledgement(trustedSnapshot, proposed, proofInput, ledger, clock) {
  try {
    if (typeof clock !== 'function') return false;
    const context = expectedContext(trustedSnapshot, proposed);
    if (!active(context, clock()) || !exact(proofInput,
      ['merkleTreeDepth', 'merkleTreeRoot', 'nullifier', 'message', 'scope', 'points'])) return false;
    if (proofInput.merkleTreeDepth !== context.depth || proofInput.merkleTreeRoot !== context.root ||
      proofInput.message !== context.message || proofInput.scope !== context.scope ||
      !Array.isArray(proofInput.points) || proofInput.points.length !== 8) return false;
    numeric(proofInput.merkleTreeRoot); numeric(proofInput.nullifier);
    numeric(proofInput.scope, UINT256); numeric(proofInput.message, UINT256);
    for (const point of proofInput.points) numeric(point, UINT256);
    const proof = structuredClone(proofInput);
    if (!(await verifyProof(proof))) return false;
    return ledger.accept(context, proof.nullifier, clock);
  } catch { return false; }
}
