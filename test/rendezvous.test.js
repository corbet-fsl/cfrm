import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { createRendezvous, rendezvousBytes } from '../src/rendezvous.js';

const ONION = { host: 'pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion', port: 443 };
const NOW = 1_800_000_000;
const key = () => generateKeyPairSync('ed25519');
const raw = publicKey => publicKey.export({ format: 'jwk' }).x;
const digest = bytes => createHash('sha256').update(bytes).digest('base64url');
const grantBytes = grant => Buffer.from(JSON.stringify(['cvld.admission.v1', grant.issuerKeyId,
  grant.communityId, grant.memberId, grant.chatPublicKey, grant.policyDigest, grant.issuedAt, grant.expiresAt]));

// The unit fixture really verifies Ed25519 signatures. CI can substitute the
// pinned cvld verifier to exercise the actual cross-repository implementation.
function fixtureVerifier({ grant, trustedPublicKey, communityId, policyDigest, now }) {
  try {
    const publicKey = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(trustedPublicKey).toString('base64url') }, format: 'jwk' });
    return grant.version === 1 && grant.communityId === communityId && grant.policyDigest === policyDigest &&
      grant.issuerKeyId === digest(trustedPublicKey) &&
      grant.issuedAt <= now && now < grant.expiresAt &&
      verify(null, grantBytes(grant), publicKey, Buffer.from(grant.signature, 'base64url'));
  } catch { return false; }
}
const admissionVerifier = process.env.CVLD_ADMISSION_MODULE ?
  (await import(process.env.CVLD_ADMISSION_MODULE)).verifyAdmission : fixtureVerifier;

function fixture(t, changes = {}) {
  const issuer = key();
  const alice = key();
  const bob = key();
  let now = NOW;
  let nextTimer = 0;
  const timers = new Map();
  const policyDigest = digest('policy');
  const certify = (member, id = digest(raw(member.publicKey)), overrides = {}) => {
    const grant = { version: 1, issuerKeyId: digest(Buffer.from(raw(issuer.publicKey), 'base64url')),
      communityId: 'community.example', memberId: id, chatPublicKey: raw(member.publicKey),
      policyDigest, issuedAt: NOW, expiresAt: NOW + 1000, ...overrides };
    return { ...grant, signature: sign(null, grantBytes(grant), issuer.privateKey).toString('base64url') };
  };
  const registry = createRendezvous({
    communityId: 'community.example', policyDigest, trustedPublicKey: Buffer.from(raw(issuer.publicKey), 'base64url'),
    verifyAdmission: admissionVerifier, clock: () => now,
    leaseSeconds: 10, challengeSeconds: 5, maxMembers: 100, maxReplayEntries: 200,
    setTimer: (callback, milliseconds) => {
      const id = ++nextTimer;
      timers.set(id, { callback, at: now + milliseconds / 1000 });
      return id;
    },
    clearTimer: id => timers.delete(id), ...changes,
  });
  t.after(() => registry.close());
  const advance = next => {
    now = next;
    for (;;) {
      const due = [...timers].find(([, timer]) => timer.at <= now);
      if (!due) break;
      timers.delete(due[0]); due[1].callback();
    }
  };
  const proof = async (member = alice, grant = certify(member), endpoint = ONION) => {
    const envelope = await registry.begin(grant, endpoint);
    return { grant, ...envelope,
      signature: sign(null, rendezvousBytes(envelope.challenge), member.privateKey).toString('base64url') };
  };
  const register = async (member = alice, grant = certify(member), endpoint = ONION) =>
    registry.register(await proof(member, grant, endpoint));
  return { registry, issuer, alice, bob, certify, proof, register, advance, timers, policyDigest };
}

test('a real certified chat-key signature registers and authorizes minimal live discovery', async t => {
  const { registry, register, certify, alice } = fixture(t);
  const session = await register();
  assert.deepEqual(registry.list(session.token), [{ memberId: certify(alice).memberId, endpoint: ONION }]);
  assert.equal(session.expiresAt, NOW + 10);
  assert.match(session.token, /^[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(registry.counts(), { members: 1, sessions: 1, replayMarkers: 1 });
});
test('a copied certificate or another chat key cannot impersonate a member', async t => {
  const { registry, alice, bob, certify, proof } = fixture(t);
  const candidate = await proof(alice, certify(alice));
  assert.equal(await registry.register({ ...candidate, signature: '' }), null);
  candidate.signature = sign(null, rendezvousBytes(candidate.challenge), bob.privateKey).toString('base64url');
  assert.equal(await registry.register(candidate), null);
  assert.deepEqual(registry.counts(), { members: 0, sessions: 0, replayMarkers: 0 });
});
test('issuer forgery, changed member ID, wrong community/policy and expired grants fail closed', async t => {
  const { registry, alice, certify } = fixture(t);
  const valid = certify(alice);
  const outsider = key();
  const forged = { ...valid, signature: sign(null, grantBytes(valid), outsider.privateKey).toString('base64url') };
  for (const grant of [forged, { ...valid, memberId: digest('other') },
    certify(alice, valid.memberId, { communityId: 'other.example' }),
    certify(alice, valid.memberId, { policyDigest: digest('other-policy') }),
    certify(alice, valid.memberId, { expiresAt: NOW }),
    certify(alice, valid.memberId, { issuedAt: NOW + 1 })]) {
    await assert.rejects(registry.begin(grant, ONION));
  }
});
test('only checksum-valid v3 onion hosts and explicit ports are advertised', async t => {
  const { registry, certify, alice } = fixture(t);
  for (const endpoint of [
    { ...ONION, host: '127.0.0.1' }, { ...ONION, host: 'example.com' },
    { ...ONION, host: `http://${ONION.host}` }, { ...ONION, host: `${ONION.host}/track` },
    { ...ONION, host: ONION.host.toUpperCase() },
    { ...ONION, host: 'a'.repeat(56) + '.onion' },
    { ...ONION, host: 'q' + ONION.host.slice(1) },
    { ...ONION, port: 0 }, { ...ONION, port: 65536 },
    { ...ONION, port: '443' }, { ...ONION, url: 'https://example.com' },
  ]) await assert.rejects(registry.begin(certify(alice), endpoint));
});
test('stateless challenge issuance cannot allocate roster or replay capacity from copied public grants', async t => {
  const { registry, alice, certify } = fixture(t, { maxReplayEntries: 1 });
  for (let i = 0; i < 250; i++) await registry.begin(certify(alice), ONION);
  assert.deepEqual(registry.counts(), { members: 0, sessions: 0, replayMarkers: 0 });
});
test('challenge and endpoint tampering, foreign-instance challenges and future signatures fail', async t => {
  const f = fixture(t);
  const other = fixture(t);
  const candidate = await f.proof();
  for (const challenge of [
    { ...candidate.challenge, endpoint: { ...ONION, port: 80 } },
    { ...candidate.challenge, memberId: digest('other') },
    { ...candidate.challenge, issuedAt: NOW + 100, expiresAt: NOW + 105 },
    { ...candidate.challenge, purpose: 'disconnect' },
  ]) {
    const signed = 'purpose' in challenge ? candidate.signature :
      sign(null, rendezvousBytes(challenge), f.alice.privateKey).toString('base64url');
    assert.equal(await f.registry.register({ ...candidate, challenge, signature: signed }), null);
  }
  assert.equal(await other.registry.register(candidate), null);
});
test('concurrent replays admit exactly once and cannot overwrite the new session', async t => {
  const { registry, proof } = fixture(t);
  const candidate = await proof();
  const results = await Promise.all([registry.register(candidate), registry.register(candidate), registry.register(candidate)]);
  const sessions = results.filter(Boolean);
  assert.equal(sessions.length, 1);
  assert.equal(registry.list(sessions[0].token).length, 1);
});
test('expired challenges cannot register and challenge expiry clips to credential lifetime', async t => {
  const { registry, alice, certify, proof, advance } = fixture(t);
  const candidate = await proof(alice, certify(alice, undefined, { expiresAt: NOW + 2 }));
  assert.equal(candidate.challenge.expiresAt, NOW + 2);
  advance(NOW + 2);
  assert.equal(await registry.register(candidate), null);
  assert.equal(registry.counts().members, 0);
});
test('lease expiry removes data on its timer even when no member calls the registry', async t => {
  const { registry, register, advance, timers } = fixture(t);
  const session = await register();
  advance(NOW + 10);
  assert.deepEqual(registry.counts(), { members: 0, sessions: 0, replayMarkers: 0 });
  assert.equal(timers.size, 0);
  assert.throws(() => registry.list(session.token));
});
test('disconnect removes the live ID and session but retains only opaque replay protection briefly', async t => {
  const { registry, register, proof, advance } = fixture(t);
  const candidate = await proof();
  const session = await registry.register(candidate);
  assert.equal(registry.disconnect(session.token), true);
  assert.deepEqual(registry.counts(), { members: 0, sessions: 0, replayMarkers: 1 });
  assert.equal(await registry.register(candidate), null);
  advance(NOW + 5);
  assert.deepEqual(registry.counts(), { members: 0, sessions: 0, replayMarkers: 0 });
  assert.equal((await register()).expiresAt, NOW + 15);
});
test('mobile suspension and signed re-registration retain identity while replacing only live session state', async t => {
  const { registry, register, advance, certify, alice } = fixture(t);
  const first = await register();
  advance(NOW + 3);
  const second = await register(alice, certify(alice), { ...ONION, port: 80 });
  assert.throws(() => registry.list(first.token));
  assert.deepEqual(registry.list(second.token), [{ memberId: certify(alice).memberId, endpoint: { ...ONION, port: 80 } }]);
  advance(NOW + 100);
  assert.throws(() => registry.list(second.token));
  const resumed = await register();
  assert.equal(registry.list(resumed.token)[0].memberId, certify(alice).memberId);
});
test('an active session is required for listing; stable IDs and certificates are not session capabilities', async t => {
  const { registry, register, certify, alice } = fixture(t);
  await register();
  for (const token of ['', 'a'.repeat(43), certify(alice).memberId, JSON.stringify(certify(alice))]) {
    assert.throws(() => registry.list(token));
    assert.equal(registry.disconnect(token), false);
  }
});
test('capacity bounds fail closed and concurrent distinct registrations cannot exceed the roster cap', async t => {
  const { registry, alice, bob, proof } = fixture(t, { maxMembers: 1 });
  const candidates = await Promise.all([proof(alice), proof(bob)]);
  const results = await Promise.all(candidates.map(candidate => registry.register(candidate)));
  assert.equal(results.filter(Boolean).length, 1);
  assert.equal(registry.counts().members, 1);
});
test('replay storage is bounded and renewed registration works after old replay entries expire', async t => {
  const { registry, register, advance } = fixture(t, { maxReplayEntries: 1 });
  const first = await register();
  assert.equal(await register(), null);
  assert.equal(registry.list(first.token).length, 1);
  advance(NOW + 5);
  assert.ok(await register());
  assert.equal(registry.counts().replayMarkers, 1);
});
test('changing caller-owned objects cannot change stored identity or endpoint', async t => {
  const { registry, proof } = fixture(t);
  const candidate = await proof();
  const session = await registry.register(candidate);
  candidate.challenge.endpoint.port = 80;
  candidate.grant.memberId = digest('evil');
  const roster = registry.list(session.token);
  assert.deepEqual(roster[0].endpoint, ONION);
  roster[0].endpoint.host = 'example.com';
  assert.deepEqual(registry.list(session.token)[0].endpoint, ONION);
});
test('invalid limits and backward clocks fail closed; close removes all in-memory state', async t => {
  assert.throws(() => fixture(t, { maxMembers: 0 }));
  assert.throws(() => fixture(t, { leaseSeconds: -1 }));
  assert.throws(() => fixture(t, { challengeSeconds: 0 }));
  const { registry, register, advance, timers } = fixture(t);
  const session = await register();
  advance(NOW - 1);
  assert.throws(() => registry.list(session.token));
  registry.close();
  assert.deepEqual(registry.counts(), { members: 0, sessions: 0, replayMarkers: 0 });
  assert.equal(timers.size, 0);
  await assert.rejects(register());
});

test('expiry during an asynchronous verifier cannot commit stale registration', async t => {
  let advance;
  let expireDuringVerification = false;
  const f = fixture(t, { verifyAdmission: async args => {
    const accepted = admissionVerifier(args);
    if (expireDuringVerification) advance(NOW + 5);
    return accepted;
  } });
  advance = f.advance;
  const candidate = await f.proof();
  expireDuringVerification = true;
  assert.equal(await f.registry.register(candidate), null);
  assert.deepEqual(f.registry.counts(), { members: 0, sessions: 0, replayMarkers: 0 });
});
test('the live lease cannot outlast a short-lived admission certificate', async t => {
  const { registry, alice, certify, register, advance } = fixture(t);
  const session = await register(alice, certify(alice, undefined, { expiresAt: NOW + 2 }));
  assert.equal(session.expiresAt, NOW + 2);
  advance(NOW + 2);
  assert.throws(() => registry.list(session.token));
  assert.equal(registry.counts().members, 0);
});
