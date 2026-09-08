import { createHash, createPublicKey, sign, timingSafeEqual, verify } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { verifyProof } from '@semaphore-protocol/proof';
import { registeredAcknowledgementContext } from '../private-reciprocity/checkpoints.js';

const suite = RSABSSA.SHA384.PSS.Randomized();
const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const UINT256 = 1n << 256n;
const json = value => Buffer.from(JSON.stringify(value));
const b64 = value => Buffer.from(value).toString('base64url');
const hash = value => createHash('sha256').update(value).digest();
const scalarHash = value => BigInt('0x' + hash(json(value)).toString('hex')).toString();
const positive = value => Number.isSafeInteger(value) && value > 0;
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join(',') === [...keys].sort().join(',');
function text(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9._:/-]{1,256}$/.test(value)) throw new TypeError('Invalid identifier');
  return value;
}
function decode(value, length) {
  if (typeof value !== 'string' || value.length !== Math.ceil(length * 4 / 3) ||
    !/^[A-Za-z0-9_-]+$/.test(value)) throw new TypeError('Invalid bytes');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length !== length || b64(bytes) !== value) throw new TypeError('Invalid bytes');
  // Upstream blind RSA requires Uint8Array.slice semantics rather than pooled Buffer views.
  return Uint8Array.from(bytes);
}
function numeric(value, limit = FIELD) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,77})$/.test(value) || BigInt(value) >= limit) {
    throw new TypeError('Invalid canonical scalar');
  }
  return value;
}
const scalarBytes = value => Buffer.from(BigInt(numeric(value, UINT256)).toString(16).padStart(64, '0'), 'hex');
function interval(value) {
  if (!positive(value.issuedAt) || !positive(value.expiresAt) || value.expiresAt <= value.issuedAt) {
    throw new TypeError('Invalid validity interval');
  }
}
const current = (value, now) => now >= value.issuedAt && now < value.expiresAt;

function cohortInfo(publicInput, options, attestationKeys) {
  const context = structuredClone(publicInput);
  if (!exact(context, ['version', 'purpose', 'communityId', 'policyDigest', 'cohortId',
    'notBefore', 'issueUntil', 'redeemUntil', 'publicKey']) || context.version !== (attestationKeys ? 2 : 1) ||
    context.purpose !== (attestationKeys ? 'release-acknowledged-receive' : 'acknowledged-receive') || !positive(context.notBefore) ||
    !positive(context.issueUntil) || !positive(context.redeemUntil) ||
    context.issueUntil <= context.notBefore || context.redeemUntil <= context.issueUntil) {
    throw new TypeError('Invalid shared receipt cohort');
  }
  text(context.communityId); text(context.cohortId); decode(context.policyDigest, 32);
  if (attestationKeys && (Buffer.byteLength(context.communityId) > 128 || Buffer.byteLength(context.cohortId) > 128)) {
    throw new TypeError('Release context exceeds the shared client bounds');
  }
  const key = context.publicKey;
  if (!key || key.kty !== 'RSA' || key.e !== 'AQAB' || key.alg !== 'PS384' ||
    !Array.isArray(key.key_ops) || key.key_ops.length !== 1 || key.key_ops[0] !== 'verify' ||
    Object.keys(key).some(name => !['kty', 'e', 'n', 'alg', 'key_ops', 'ext'].includes(name))) {
    throw new TypeError('A public RSA-PSS SHA384 key is required');
  }
  const modulus = decode(key.n, 384);
  if (modulus[0] < 128 || !(modulus[383] & 1)) throw new TypeError('A 3072-bit odd RSA modulus is required');
  const domain = hash(json([attestationKeys ? 'cfrm.directional.release-receipt.v1' : 'cfrm.directional.receipt.v1',
    context.communityId, context.policyDigest,
    context.cohortId, context.notBefore, context.issueUntil, context.redeemUntil, key.kty, key.n, key.e]));
  const keyFingerprint = hash(json(['RSA', key.n, key.e]));
  const configuration = ['cfrm.directional.configuration.v1', b64(domain),
    options.maxAuthorizedSend, options.maxAcknowledgedReceive, options.authorizationSeconds,
    b64(options.admissionTrust.trustedPublicKey), b64(options.checkpointTrust.trustedPublicKey)];
  if (attestationKeys) configuration.push(attestationKeys.senderCommit.publicKey, attestationKeys.recipientRedemption.publicKey);
  const configurationHash = hash(json(configuration));
  return { context, domain, keyFingerprint, configurationHash, community: context.communityId,
    cohort: context.cohortId, notBefore: context.notBefore, issueUntil: context.issueUntil,
    redeemUntil: context.redeemUntil, maxAuthorizedSend: options.maxAuthorizedSend,
    maxAcknowledgedReceive: options.maxAcknowledgedReceive };
}

function verifiedAttestationKeys(options) {
  if (!exact(options.attestationKeys, ['senderCommit', 'recipientRedemption'])) {
    throw new TypeError('Both purpose-specific attestation keys are required');
  }
  const result = {};
  const used = new Set([b64(options.admissionTrust.trustedPublicKey), b64(options.checkpointTrust.trustedPublicKey)]);
  for (const purpose of ['senderCommit', 'recipientRedemption']) {
    const candidate = options.attestationKeys[purpose];
    if (!exact(candidate, ['publicKey', 'privateKey']) || !(candidate.publicKey instanceof Uint8Array) ||
      candidate.publicKey.length !== 32 || candidate.privateKey?.type !== 'private' ||
      candidate.privateKey.asymmetricKeyType !== 'ed25519') throw new TypeError('An Ed25519 attestation key pair is required');
    const publicKey = createPublicKey(candidate.privateKey).export({ format: 'jwk' }).x;
    if (publicKey !== b64(candidate.publicKey) || used.has(publicKey)) {
      throw new TypeError('Attestation keys must match their public pins and have distinct purposes');
    }
    used.add(publicKey);
    result[purpose] = { publicKey, privateKey: candidate.privateKey };
  }
  return result;
}
function statementContext(info) {
  return { communityId: info.community, policyDigest: info.context.policyDigest, cohortId: info.cohort,
    notBefore: info.notBefore, expiresAt: info.redeemUntil };
}
function senderStatement(info, authorization, grant, keys) {
  const statement = { context: statementContext(info),
    sender: { memberId: grant.memberId, chatPublicKey: grant.chatPublicKey },
    authorizationNonce: authorization.nonce, blindedRequestHash: authorization.requestHash };
  const bytes = json(['cfrm.directional.commit.v1', info.community, info.context.policyDigest, info.cohort,
    grant.memberId, grant.chatPublicKey, authorization.nonce, authorization.requestHash, info.notBefore, info.redeemUntil]);
  return { ...statement, signature: b64(sign(null, bytes, keys.senderCommit.privateKey)) };
}
function recipientStatement(info, grant, releaseNonce, keys) {
  const statement = { context: statementContext(info),
    recipient: { memberId: grant.memberId, chatPublicKey: grant.chatPublicKey }, releaseNonce: b64(releaseNonce) };
  const bytes = json(['cfrm.directional.redemption.v1', info.community, info.context.policyDigest, info.cohort,
    grant.memberId, grant.chatPublicKey, b64(releaseNonce), info.notBefore, info.redeemUntil]);
  return { ...statement, signature: b64(sign(null, bytes, keys.recipientRedemption.privateKey)) };
}

function senderBytes(value) {
  return json(['cfrm.directional.authorize.v1', value.communityId, value.policyDigest,
    value.cohortId, value.senderId, value.requestHash, value.nonce, value.issuedAt, value.expiresAt]);
}
function receiveBytes(value) {
  return json(['cfrm.directional.redeem.v1', value.communityId, value.policyDigest,
    value.cohortId, value.memberId, value.receiptHash, value.nonce, value.issuedAt, value.expiresAt]);
}
function authorizationShape(value, info, receiving, seconds) {
  const member = receiving ? 'memberId' : 'senderId';
  const digest = receiving ? 'receiptHash' : 'requestHash';
  if (!exact(value, ['version', 'purpose', 'communityId', 'policyDigest', 'cohortId', member,
    digest, 'nonce', 'issuedAt', 'expiresAt', 'signature']) || value.version !== 1 ||
    value.purpose !== (receiving ? 'acknowledged-receive' : 'authorized-send') ||
    value.communityId !== info.community || value.policyDigest !== info.context.policyDigest ||
    value.cohortId !== info.cohort) throw new TypeError('Wrong authorization context');
  interval(value);
  if (value.expiresAt - value.issuedAt > seconds) throw new TypeError('Authorization exceeds the configured lifetime');
  for (const name of [member, digest, 'nonce']) decode(value[name], 32);
  decode(value.signature, 64);
}
function grantShape(grant, info, member) {
  if (!exact(grant, ['version', 'issuerKeyId', 'communityId', 'memberId', 'chatPublicKey',
    'policyDigest', 'issuedAt', 'expiresAt', 'signature']) || grant.version !== 1 ||
    grant.communityId !== info.community || grant.policyDigest !== info.context.policyDigest ||
    grant.memberId !== member) throw new TypeError('Wrong admission account or context');
  interval(grant);
  for (const name of ['issuerKeyId', 'memberId', 'chatPublicKey', 'policyDigest']) decode(grant[name], 32);
  decode(grant.signature, 64);
}
function ownSignature(grant, authorization, bytes) {
  const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: grant.chatPublicKey }, format: 'jwk' });
  if (!verify(null, bytes, key, decode(authorization.signature, 64))) throw new Error('Account authorization rejected');
}
function proofShape(proof, context, authorization, checkpoint) {
  const message = scalarHash(['cfrm.directional.ack.v1', checkpoint.digest,
    b64(senderBytes(authorization)), authorization.signature, authorization.requestHash]);
  if (!exact(proof, ['merkleTreeDepth', 'merkleTreeRoot', 'nullifier', 'message', 'scope', 'points']) ||
    proof.merkleTreeDepth !== context.depth || proof.merkleTreeRoot !== context.root ||
    proof.scope !== context.scope || proof.message !== message ||
    !Array.isArray(proof.points) || proof.points.length !== 8) throw new Error('Wrong bound membership proof');
  numeric(proof.merkleTreeRoot); numeric(proof.nullifier);
  numeric(proof.message, UINT256); numeric(proof.scope, UINT256);
  for (const point of proof.points) numeric(point, UINT256);
}
function clonedInput(input, maxBytes) {
  const encoded = JSON.stringify(input);
  if (!encoded || Buffer.byteLength(encoded) > maxBytes) throw new Error('Request exceeds its byte bound');
  return JSON.parse(encoded);
}
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  }
  return value;
}
function faultAt(fault, phase) {
  const result = fault?.(phase);
  if (result && typeof result.then === 'function') throw new TypeError('Fault hooks must be synchronous');
}

/** Internal trusted persistence API. There is no remotely callable direct counter update. */
export function openDirectionalLedger(path) {
  const db = new DatabaseSync(path, { allowExtension: false, enableForeignKeyConstraints: true,
    enableDoubleQuotedStringLiterals: false });
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF; PRAGMA busy_timeout=5000;
    CREATE TABLE IF NOT EXISTS directional_clock (singleton INTEGER PRIMARY KEY CHECK(singleton=1), floor INTEGER NOT NULL);
    INSERT INTO directional_clock(singleton,floor) VALUES (1,0) ON CONFLICT DO NOTHING;
    CREATE TABLE IF NOT EXISTS directional_keys (
      fingerprint BLOB PRIMARY KEY, configuration BLOB NOT NULL,
      community TEXT NOT NULL, cohort TEXT NOT NULL, UNIQUE(community,cohort)) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS directional_cohorts (
      community TEXT NOT NULL, cohort TEXT NOT NULL, expires_at INTEGER NOT NULL,
      PRIMARY KEY(community,cohort)) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS directional_counters (
      community TEXT NOT NULL, cohort TEXT NOT NULL, member TEXT NOT NULL,
      authorized_send INTEGER NOT NULL DEFAULT 0, acknowledged_receive INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY(community,cohort,member),
      FOREIGN KEY(community,cohort) REFERENCES directional_cohorts(community,cohort) ON DELETE CASCADE) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS directional_authorizations (
      community TEXT NOT NULL, sender TEXT NOT NULL, nonce BLOB NOT NULL, cohort TEXT NOT NULL,
      request_hash BLOB NOT NULL, response TEXT NOT NULL,
      PRIMARY KEY(community,sender,nonce),
      FOREIGN KEY(community,cohort) REFERENCES directional_cohorts(community,cohort) ON DELETE CASCADE) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS directional_nullifiers (
      community TEXT NOT NULL, scope BLOB NOT NULL, nullifier BLOB NOT NULL,
      PRIMARY KEY(community,scope,nullifier)) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS directional_spends (
      community TEXT NOT NULL, cohort TEXT NOT NULL, serial BLOB NOT NULL,
      member TEXT NOT NULL, receipt_hash BLOB NOT NULL, release_nonce BLOB, response TEXT,
      PRIMARY KEY(community,cohort,serial),
      FOREIGN KEY(community,cohort) REFERENCES directional_cohorts(community,cohort) ON DELETE CASCADE) WITHOUT ROWID;
    CREATE UNIQUE INDEX IF NOT EXISTS directional_release_nonce
      ON directional_spends(community,cohort,member,release_nonce) WHERE release_nonce IS NOT NULL;`);
  const floor = () => db.prepare('SELECT floor FROM directional_clock WHERE singleton=1').get().floor;
  let lastObserved = 0;
  function transaction(action) {
    db.exec('BEGIN IMMEDIATE');
    try { const result = action(); db.exec('COMMIT'); return result; }
    catch (error) {
      db.exec('ROLLBACK');
      // A rejected/failed operation still observed trusted time. Keep that floor
      // even when its accounting writes roll back, including a failed commit.
      db.prepare('UPDATE directional_clock SET floor=max(floor,?) WHERE singleton=1').run(lastObserved);
      throw error;
    }
  }
  function time(clock) {
    const now = clock();
    if (!positive(now) || now < floor()) throw new Error('Clock rollback rejected');
    lastObserved = now;
    db.prepare('UPDATE directional_clock SET floor=? WHERE singleton=1').run(now);
    return now;
  }
  function recoveryActive(info, now) {
    if (now < info.notBefore || now >= info.redeemUntil) throw new Error('Receipt cohort is inactive');
  }
  function recover(info, event) {
    const prior = db.prepare('SELECT cohort,request_hash,response FROM directional_authorizations WHERE community=? AND sender=? AND nonce=?')
      .get(info.community, event.sender, event.nonce);
    if (!prior) return null;
    if (prior.cohort !== info.cohort || !timingSafeEqual(prior.request_hash, event.requestHash)) {
      throw new Error('Authorization already belongs to a different request');
    }
    return prior.response;
  }
  function counters(community, cohort, member) {
    text(community); text(cohort); decode(member, 32);
    const row = db.prepare('SELECT authorized_send,acknowledged_receive FROM directional_counters WHERE community=? AND cohort=? AND member=?')
      .get(community, cohort, member);
    return { authorizedSend: row?.authorized_send ?? 0, acknowledgedReceive: row?.acknowledged_receive ?? 0 };
  }
  function newIssueAllowed(info, event, now) {
    if (now >= info.issueUntil || !current(event.authorization, now) || !current(event.grant, now) ||
      now < event.checkpoint.notBefore || now >= event.checkpoint.expiresAt) throw new Error('Issuance validity ended');
    if (counters(info.community, info.cohort, event.sender).authorizedSend >= info.maxAuthorizedSend) {
      throw new Error('Sender authorization cap exhausted');
    }
    if (db.prepare('SELECT 1 FROM directional_nullifiers WHERE community=? AND scope=? AND nullifier=?')
      .get(info.community, event.scope, event.nullifier)) throw new Error('Lifetime directed nullifier already consumed');
  }
  return {
    register(info) {
      return transaction(() => {
        // This registry survives cohort pruning: old signing interactions must
        // never become valid tokens under a future context that reuses the key.
        const priorKey = db.prepare('SELECT configuration FROM directional_keys WHERE fingerprint=?').get(info.keyFingerprint);
        const priorCohort = db.prepare('SELECT fingerprint FROM directional_keys WHERE community=? AND cohort=?')
          .get(info.community, info.cohort);
        if ((priorKey && !timingSafeEqual(priorKey.configuration, info.configurationHash)) ||
          (priorCohort && !timingSafeEqual(priorCohort.fingerprint, info.keyFingerprint))) {
          throw new Error('A cohort key or its fixed configuration cannot be reused or changed');
        }
        db.prepare('INSERT INTO directional_keys(fingerprint,configuration,community,cohort) VALUES (?,?,?,?) ON CONFLICT DO NOTHING')
          .run(info.keyFingerprint, info.configurationHash, info.community, info.cohort);
        if (info.redeemUntil > floor()) {
          db.prepare('INSERT INTO directional_cohorts(community,cohort,expires_at) VALUES (?,?,?) ON CONFLICT DO NOTHING')
            .run(info.community, info.cohort, info.redeemUntil);
        }
      });
    },
    recover(info, event, clock) {
      return transaction(() => { recoveryActive(info, time(clock)); return recover(info, event); });
    },
    preflightIssue(info, event, clock) {
      return transaction(() => {
        const now = time(clock);
        recoveryActive(info, now);
        const prior = recover(info, event);
        if (prior) return prior;
        newIssueAllowed(info, event, now);
        return null;
      });
    },
    issue(info, event, response, clock, fault) {
      return transaction(() => {
        const now = time(clock);
        recoveryActive(info, now);
        const prior = recover(info, event);
        if (prior) return { response: prior, committed: false };
        newIssueAllowed(info, event, now);
        db.prepare('INSERT INTO directional_authorizations(community,sender,nonce,cohort,request_hash,response) VALUES (?,?,?,?,?,?)')
          .run(info.community, event.sender, event.nonce, info.cohort, event.requestHash, response);
        db.prepare('INSERT INTO directional_nullifiers(community,scope,nullifier) VALUES (?,?,?)')
          .run(info.community, event.scope, event.nullifier);
        db.prepare(`INSERT INTO directional_counters(community,cohort,member,authorized_send) VALUES (?,?,?,1)
          ON CONFLICT(community,cohort,member) DO UPDATE SET authorized_send=authorized_send+1`)
          .run(info.community, info.cohort, event.sender);
        faultAt(fault, 'issue-before-commit');
        return { response, committed: true };
      });
    },
    redeem(info, event, clock, fault) {
      return transaction(() => {
        const now = time(clock);
        recoveryActive(info, now);
        if (!current(event.authorization, now) || !current(event.grant, now)) throw new Error('Receive authorization expired');
        const prior = db.prepare('SELECT member,receipt_hash,response FROM directional_spends WHERE community=? AND cohort=? AND serial=?')
          .get(info.community, info.cohort, event.serial);
        if (prior) {
          if (prior.member !== event.member || !timingSafeEqual(prior.receipt_hash, event.receiptHash)) {
            throw new Error('Receipt serial is already consumed');
          }
          return { committed: false, response: prior.response };
        }
        if (event.releaseNonce && db.prepare('SELECT 1 FROM directional_spends WHERE community=? AND cohort=? AND member=? AND release_nonce=?')
          .get(info.community, info.cohort, event.member, event.releaseNonce)) throw new Error('Release challenge already consumed');
        if (counters(info.community, info.cohort, event.member).acknowledgedReceive >= info.maxAcknowledgedReceive) {
          throw new Error('Receive cap exhausted');
        }
        db.prepare('INSERT INTO directional_spends(community,cohort,serial,member,receipt_hash,release_nonce,response) VALUES (?,?,?,?,?,?,?)')
          .run(info.community, info.cohort, event.serial, event.member, event.receiptHash, event.releaseNonce ?? null, event.response ?? null);
        db.prepare(`INSERT INTO directional_counters(community,cohort,member,acknowledged_receive) VALUES (?,?,?,1)
          ON CONFLICT(community,cohort,member) DO UPDATE SET acknowledged_receive=acknowledged_receive+1`)
          .run(info.community, info.cohort, event.member);
        faultAt(fault, 'receive-before-commit');
        return { committed: true, response: event.response ?? null };
      });
    },
    counters,
    counts() {
      const count = table => db.prepare(`SELECT count(*) AS n FROM ${table}`).get().n;
      return { authorizations: count('directional_authorizations'),
        lifetimeNullifiers: count('directional_nullifiers'), redeemedReceipts: count('directional_spends') };
    },
    prune(now) {
      transaction(() => {
        time(() => now);
        db.prepare('DELETE FROM directional_cohorts WHERE expires_at<=?').run(now);
      });
    },
    close() { if (db.isOpen) db.close(); },
  };
}

export function createDirectionalService(options) { return createConfiguredService(options, false); }

/** Isolated experimental service; the shipping cfrm API does not expose these statements. */
export function createReleaseReceiptService(options) { return createConfiguredService(options, true); }

function createConfiguredService(options, release) {
  const { ledger, verifyAdmission, clock, fault } = options;
  if (typeof verifyAdmission !== 'function' || typeof clock !== 'function' ||
    typeof ledger?.register !== 'function' || (fault !== undefined && typeof fault !== 'function')) {
    throw new TypeError('Explicit trusted verification, persistence and clock are required');
  }
  for (const [field, maximum] of [['maxAuthorizedSend', 1000000], ['maxAcknowledgedReceive', 1000000],
    ['maxPending', 128], ['maxRequestBytes', 1048576], ['authorizationSeconds', 300]]) {
    if (!positive(options[field]) || options[field] > maximum) throw new TypeError('Invalid explicit service bound');
  }
  for (const trust of [options.admissionTrust, options.checkpointTrust]) {
    if (!(trust?.trustedPublicKey instanceof Uint8Array) || trust.trustedPublicKey.length !== 32) {
      throw new TypeError('Pinned admission and checkpoint signing keys are required');
    }
  }
  const attestationKeys = release ? verifiedAttestationKeys(options) : null;
  const info = cohortInfo(options.cohort.public, options, attestationKeys);
  for (const trust of [options.admissionTrust, options.checkpointTrust]) {
    if (trust.communityId !== info.community || trust.policyDigest !== info.context.policyDigest) {
      throw new TypeError('Trust context must match the shared cohort');
    }
  }
  const admissionTrust = { trustedPublicKey: Uint8Array.from(options.admissionTrust.trustedPublicKey),
    communityId: info.community, policyDigest: info.context.policyDigest };
  const checkpointTrust = { trustedPublicKey: Uint8Array.from(options.checkpointTrust.trustedPublicKey),
    communityId: info.community, policyDigest: info.context.policyDigest, clock };
  const { maxPending, maxRequestBytes, authorizationSeconds } = options;
  const privateKey = options.cohort.privateKey;
  if (privateKey?.type !== 'private' || privateKey.algorithm?.name !== 'RSA-PSS' ||
    privateKey.algorithm.modulusLength !== 3072 || privateKey.algorithm.hash?.name !== 'SHA-384' ||
    privateKey.extractable !== true) {
    throw new TypeError('The cohort needs its configured blind RSA signing key');
  }
  ledger.register(info);
  let pending = 0;
  let publicKeyPromise;
  let pairedKeyPromise;
  const publicKey = () => publicKeyPromise ??= crypto.subtle.importKey('jwk', info.context.publicKey,
    { name: 'RSA-PSS', hash: 'SHA-384' }, true, ['verify']);
  const pairedKey = () => pairedKeyPromise ??= crypto.subtle.exportKey('jwk', privateKey).then(key => {
    // The maintained blind signer also exports its configured private key. Only
    // compare public parameters here; no private key material enters persistence.
    return key.n === info.context.publicKey.n && key.e === info.context.publicKey.e;
  });
  const admitted = async grant => (await verifyAdmission({ ...admissionTrust,
    trustedPublicKey: Uint8Array.from(admissionTrust.trustedPublicKey), grant: structuredClone(grant), now: clock() })) === true;
  const issuanceOutput = encoded => release ? JSON.parse(encoded) : { blindSignature: encoded };
  return {
    async authorizeAndAcknowledge(input) {
      let entered = false;
      try {
        const request = clonedInput(input, maxRequestBytes);
        if (!exact(request, ['senderAuthorization', 'senderAdmission', 'checkpoint', 'senderBinding',
          'blindedReceiptRequest', 'semaphoreProof']) || !exact(request.blindedReceiptRequest, ['blinded'])) {
          throw new TypeError('Invalid issuance envelope');
        }
        const authorization = request.senderAuthorization;
        const grant = request.senderAdmission;
        authorizationShape(authorization, info, false, authorizationSeconds);
        grantShape(grant, info, authorization.senderId);
        const blinded = decode(request.blindedReceiptRequest.blinded, 384);
        if (!timingSafeEqual(hash(blinded), decode(authorization.requestHash, 32))) throw new Error('Blinded request changed');
        ownSignature(grant, authorization, senderBytes(authorization));
        const event = { sender: authorization.senderId, nonce: decode(authorization.nonce, 32),
          requestHash: hash(json(canonical(request))), authorization, grant, checkpoint: request.checkpoint };
        // Exact committed recovery is authorized by the original whole request;
        // expired proof/admission is not permission to create a new counter event.
        const recovered = ledger.recover(info, event, clock);
        if (recovered) return issuanceOutput(recovered);
        if (pending >= maxPending) throw new Error('Pending operation capacity exhausted');
        pending++; entered = true;
        const now = clock();
        if (!positive(now) || !current(authorization, now) || !current(grant, now) || now >= info.issueUntil) {
          throw new Error('Issuance authorization is inactive');
        }
        if (!(await admitted(grant))) throw new Error('Current admission required');
        if (!(await pairedKey())) throw new Error('Signing key does not match the configured cohort');
        const context = registeredAcknowledgementContext(request.checkpoint, request.senderBinding, checkpointTrust);
        if (context.senderId !== authorization.senderId) throw new Error('Sender binding changed');
        proofShape(request.semaphoreProof, context, authorization, request.checkpoint);
        event.scope = scalarBytes(context.scope);
        event.nullifier = scalarBytes(request.semaphoreProof.nullifier);
        const prior = ledger.preflightIssue(info, event, clock);
        if (prior) return issuanceOutput(prior);
        if (!(await verifyProof(request.semaphoreProof))) throw new Error('Membership proof rejected');
        const signature = b64(await suite.blindSign(privateKey, blinded));
        // This candidate statement is private until the transaction caches it
        // alongside the debit. A failed commit never returns it to the caller.
        const response = release ? JSON.stringify({ blindSignature: signature,
          senderCommit: senderStatement(info, authorization, grant, attestationKeys) }) : signature;
        const result = ledger.issue(info, event, response, clock, fault);
        if (result.committed) faultAt(fault, 'issue-after-commit');
        return issuanceOutput(result.response);
      } catch { throw new Error('Directional receipt issuance rejected'); }
      finally { if (entered) pending--; }
    },
    async redeemAcknowledgedReceipt(input) {
      let entered = false;
      try {
        const request = clonedInput(input, maxRequestBytes);
        if (!exact(request, ['receipt', 'admission', 'authorization']) ||
          !exact(request.receipt, ['message', 'signature'])) return false;
        const authorization = request.authorization;
        authorizationShape(authorization, info, true, authorizationSeconds);
        const grant = request.admission;
        grantShape(grant, info, authorization.memberId);
        const message = decode(request.receipt.message, release ? 160 : 128);
        const signature = decode(request.receipt.signature, 384);
        const member = b64(message.subarray(64, 96));
        if (!timingSafeEqual(message.subarray(32, 64), info.domain) || member !== grant.memberId) return false;
        const receiptHash = hash(json([request.receipt.message, request.receipt.signature]));
        if (!timingSafeEqual(receiptHash, decode(authorization.receiptHash, 32))) return false;
        ownSignature(grant, authorization, receiveBytes(authorization));
        const now = clock();
        if (!positive(now) || now < info.notBefore || now >= info.redeemUntil ||
          !current(authorization, now) || !current(grant, now) || pending >= maxPending) return false;
        pending++; entered = true;
        if (!(await admitted(grant))) return false;
        if (!(await suite.verify(await publicKey(), signature, message))) return false;
        const releaseNonce = release ? message.subarray(128, 160) : null;
        // Compute a candidate, then durably cache it in the same serial/nonce/
        // counter transaction. Recovery returns the prior key/context verbatim.
        const response = release ? JSON.stringify({ recipientRedemption:
          recipientStatement(info, grant, releaseNonce, attestationKeys) }) : null;
        const result = ledger.redeem(info, { authorization, grant, member,
          serial: message.subarray(96, 128), receiptHash, releaseNonce, response }, clock, fault);
        if (result.committed) faultAt(fault, 'receive-after-commit');
        return release ? JSON.parse(result.response) : true;
      } catch { return false; }
      finally { if (entered) pending--; }
    },
  };
}
