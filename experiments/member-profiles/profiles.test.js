import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createProfileOwner, createProfileReader, profileChallengeBytes, profileResponseBytes, profileProofRequest } from './protocol.js';
import { NOW, COMMUNITY, ENDPOINT, textBytes, frame, decode, digest, randomId,
  challengeBytes, responseBytes, referenceRequest, credentialFixture, protocolFixture } from './fixtures.js';

function sampleChallenge(credential) {
  return { version: 1, communityId: COMMUNITY, ownerMemberId: randomId(), ownerChatPublicKey: randomId(),
    onionHost: ENDPOINT.host, onionPort: ENDPOINT.port, sessionId: randomId(), readerNonce: randomId(),
    ownerNonce: randomId(), policyDigest: credential.policyDigest, issuedAt: NOW, expiresAt: NOW + 30 };
}

test('prerequisite: real AnonCreds proves and verifies a full SHA256 transcript nonce without revealing member identity', async () => {
  const credential = await credentialFixture();
  const challenge = sampleChallenge(credential);
  const request = referenceRequest(credential.issuer, challenge);
  assert.ok(BigInt(request.nonce) > (1n << 80n));
  const proof = credential.prove(request);
  assert.equal(credential.verify(request, proof), true);
  assert.deepEqual(Object.keys(proof.requested_proof.revealed_attrs).sort(), ['community_id', 'policy']);
  assert.deepEqual(proof.requested_proof.self_attested_attrs, {});
  for (const secret of [credential.memberId, credential.receiptId, credential.secret, credential.exactExpiry]) {
    assert.equal(JSON.stringify(proof).includes(secret), false);
  }
  for (const changed of [
    { ...challenge, ownerMemberId: randomId() }, { ...challenge, ownerChatPublicKey: randomId() },
    { ...challenge, onionPort: 80 }, { ...challenge, sessionId: randomId() },
    { ...challenge, readerNonce: randomId() }, { ...challenge, ownerNonce: randomId() },
    { ...challenge, expiresAt: NOW + 29 }, { ...challenge, communityId: 'other.example' },
  ]) assert.equal(credential.verify(referenceRequest(credential.issuer, changed), proof), false);
  assert.notDeepEqual(credential.prove(request), proof);
});

test('wire codecs match the fixed cmsg owner-signing domain and full-width nonce exactly', async () => {
  const credential = await credentialFixture();
  const challenge = sampleChallenge(credential);
  assert.deepEqual(await profileChallengeBytes(challenge), challengeBytes(challenge));
  const profileDigest = digest(textBytes('Public posture'));
  assert.deepEqual(await profileResponseBytes(challenge, profileDigest), responseBytes(challenge, profileDigest));
  assert.deepEqual(await profileProofRequest(credential.issuer, challenge), referenceRequest(credential.issuer, challenge));
  assert.equal((await profileProofRequest(credential.issuer, challenge)).nonce,
    BigInt(`0x${createHash('sha256').update(challengeBytes(challenge)).digest('hex')}`).toString(10));
});

test('an anonymous eligible holder reads authenticated owner text over the onion capability only', async () => {
  const f = await protocolFixture();
  assert.deepEqual(await f.reader.read(), { ownerMemberId: f.grant.memberId, text: 'A quiet place to discuss shared interests.' });
  assert.deepEqual(f.destinations, [ENDPOINT]);
  assert.equal(f.proveCalls(), 1);
  const sent = f.wire.filter(item => item.direction === 'reader-to-owner').map(item => decode(item.bytes));
  assert.deepEqual(Object.keys(sent[0]), ['hello']);
  assert.deepEqual(Object.keys(sent[1].read).sort(), ['challenge', 'ownerSignature', 'presentation']);
  for (const secret of [f.credential.memberId, f.credential.receiptId, f.credential.secret, f.credential.exactExpiry]) {
    assert.equal(JSON.stringify(sent).includes(secret), false);
  }
});

test('a copied public admission certificate or invented boolean cannot substitute for a holder proof', async () => {
  const f = await protocolFixture();
  const hello = decode(await f.owner.handle(frame({ hello: { version: 1, readerNonce: randomId() } }))).challenge;
  for (const presentation of [f.grant, true, { eligible: true }, null]) {
    await assert.rejects(f.owner.handle(frame({ read: { challenge: hello.value, ownerSignature: hello.signature, presentation } })));
  }
});

test('the owner identity, route and challenge signature are checked before the wallet creates any proof', async () => {
  for (const mutate of [
    envelope => { envelope.challenge.ownerGrant.memberId = randomId(); },
    envelope => { envelope.challenge.value.ownerChatPublicKey = randomId(); },
    envelope => { envelope.challenge.value.onionPort = 80; },
    envelope => { envelope.challenge.signature = 'A'.repeat(86); },
    envelope => { envelope.challenge.value.readerNonce = randomId(); },
    envelope => { envelope.challenge.value.viewerId = 'tracking'; },
  ]) {
    const f = await protocolFixture();
    const transport = { async open(endpoint) {
      const channel = await f.onionTransport.open(endpoint);
      return { ...channel, async exchange(bytes) { const value = decode(await channel.exchange(bytes)); mutate(value); return frame(value); } };
    } };
    const reader = createProfileReader({ ...f.trust, limits: f.limits, clock: () => NOW,
      expectedOwner: { memberId: f.grant.memberId, endpoint: ENDPOINT }, onionTransport: transport,
      proveEligibility: () => { throw new Error('WALLET_WAS_CALLED'); } });
    await assert.rejects(reader.read(), error => !String(error).includes('WALLET_WAS_CALLED'));
  }
});

test('admission from an untrusted issuer, community, policy or expired owner cannot solicit a proof', async () => {
  const f = await protocolFixture();
  for (const changed of [
    { trustedPublicKey: new Uint8Array(32) }, { communityId: 'other.example' },
    { policyDigest: randomId() }, { clock: () => NOW + 300 },
  ]) {
    let calls = 0;
    const reader = createProfileReader({ ...f.trust, limits: f.limits, clock: () => NOW,
      expectedOwner: { memberId: f.grant.memberId, endpoint: ENDPOINT }, onionTransport: f.onionTransport,
      proveEligibility: () => { calls++; throw new Error('Wallet called'); }, ...changed });
    await assert.rejects(reader.read()); assert.equal(calls, 0);
  }
});

test('owner proof requests cannot add member identity or exact-expiry disclosure', async () => {
  const credential = await credentialFixture();
  const challenge = sampleChallenge(credential);
  await assert.rejects(Promise.resolve().then(() => profileProofRequest(credential.issuer,
    { ...challenge, request: { requested_attributes: { identity: { name: 'member_id' } } } })));
  await assert.rejects(Promise.resolve().then(() => profileProofRequest(credential.issuer,
    { ...challenge, requestedAttributes: ['valid_until'] })));
});

test('successful profile proof authorization is consumed once under concurrent replay', async () => {
  const f = await protocolFixture();
  const envelope = decode(await f.owner.handle(frame({ hello: { version: 1, readerNonce: randomId() } }))).challenge;
  const presentation = f.credential.prove(referenceRequest(f.credential.issuer, envelope.value));
  const request = frame({ read: { challenge: envelope.value, ownerSignature: envelope.signature, presentation } });
  const results = await Promise.allSettled([f.owner.handle(request), f.owner.handle(request), f.owner.handle(request)]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
});

test('disconnect immediately prevents new reads and invalidates an already signed challenge', async () => {
  const f = await protocolFixture();
  const hello = decode(await f.owner.handle(frame({ hello: { version: 1, readerNonce: randomId() } }))).challenge;
  const presentation = f.credential.prove(referenceRequest(f.credential.issuer, hello.value));
  f.owner.disconnect();
  await assert.rejects(f.reader.read());
  await assert.rejects(f.owner.handle(frame({ read: { challenge: hello.value, ownerSignature: hello.signature, presentation } })));
});

test('lease expiry and reactivation cannot revive a challenge from the earlier profile session', async () => {
  const f = await protocolFixture();
  const hello = decode(await f.owner.handle(frame({ hello: { version: 1, readerNonce: randomId() } }))).challenge;
  f.setNow(NOW + 120);
  await assert.rejects(f.reader.read());
  f.owner.activate({ endpoint: ENDPOINT, leaseExpiresAt: NOW + 240 });
  const presentation = f.credential.prove(referenceRequest(f.credential.issuer, hello.value));
  await assert.rejects(f.owner.handle(frame({ read: { challenge: hello.value, ownerSignature: hello.signature, presentation } })));
  assert.equal((await f.reader.read()).ownerMemberId, f.grant.memberId);
});

test('disconnect during asynchronous proof verification cannot release profile text', async () => {
  let owner;
  const f = await protocolFixture({ owner: { verifyEligibilityProof: async () => { owner.disconnect(); return true; } } });
  owner = f.owner;
  await assert.rejects(f.reader.read());
});

test('challenge expiry and live-lease expiry are rechecked before proof and response acceptance', async () => {
  const f = await protocolFixture();
  f.owner.activate({ endpoint: ENDPOINT, leaseExpiresAt: NOW + 2 });
  const hello = decode(await f.owner.handle(frame({ hello: { version: 1, readerNonce: randomId() } }))).challenge;
  assert.equal(hello.value.expiresAt, NOW + 2);
  f.setNow(NOW + 2);
  const presentation = f.credential.prove(referenceRequest(f.credential.issuer, hello.value));
  await assert.rejects(f.owner.handle(frame({ read: { challenge: hello.value, ownerSignature: hello.signature, presentation } })));
});

test('only text is served and UTF-8 byte bounds apply to multibyte content', async () => {
  const f = await protocolFixture({ limits: { maxProfileBytes: 8 } });
  f.owner.setText('éééé');
  assert.equal((await f.reader.read()).text, 'éééé');
  assert.throws(() => f.owner.setText('ééééé'));
  assert.throws(() => f.owner.setText('\ud800'));
  assert.throws(() => f.owner.setText({ text: 'x', image: 'https://example.invalid/x' }));
});

test('URL-looking and HTML-looking text stays inert and does not cause a fetch', async () => {
  const f = await protocolFixture();
  const previous = globalThis.fetch;
  globalThis.fetch = () => { throw new Error('A profile triggered URL fetch'); };
  try {
    const text = '<img src="https://example.invalid/tracker"> https://example.invalid/file';
    f.owner.setText(text);
    assert.equal((await f.reader.read()).text, text);
  } finally { globalThis.fetch = previous; }
});

test('oversized or invalid UTF-8 frames fail before application parsing or profile release', async () => {
  const f = await protocolFixture();
  await assert.rejects(f.owner.handle(new Uint8Array(f.limits.maxFrameBytes + 1)));
  await assert.rejects(f.owner.handle(new Uint8Array([0xc3, 0x28])));
  await assert.rejects(f.owner.handle(frame({ hello: { version: 1, readerNonce: randomId(), profile: 'unexpected' } })));
});

test('tampering with profile text, signature or response context cannot produce accepted posture', async () => {
  for (const mutate of [
    profile => { profile.text += ' modified'; }, profile => { profile.signature = 'A'.repeat(86); },
    profile => { profile.challengeDigest = randomId(); }, profile => { profile.profileDigest = randomId(); },
    profile => { profile.lastSeen = NOW; },
  ]) {
    const f = await protocolFixture();
    const transport = { async open(endpoint) {
      const channel = await f.onionTransport.open(endpoint);
      return { ...channel, async exchange(bytes) {
        const reply = decode(await channel.exchange(bytes)); if (reply.profile) mutate(reply.profile); return frame(reply);
      } };
    } };
    const reader = createProfileReader({ ...f.trust, limits: f.limits, clock: () => NOW,
      expectedOwner: { memberId: f.grant.memberId, endpoint: ENDPOINT }, onionTransport: transport,
      proveEligibility: request => f.credential.prove(request) });
    await assert.rejects(reader.read());
  }
});

test('transport failure has no direct fallback and ordinary addresses are rejected before dialing', async () => {
  const f = await protocolFixture();
  let calls = 0;
  const failing = { async open() { calls++; throw new Error('Onion transport unavailable'); } };
  const config = { ...f.trust, limits: f.limits, clock: () => NOW,
    expectedOwner: { memberId: f.grant.memberId, endpoint: ENDPOINT }, onionTransport: failing,
    proveEligibility: request => f.credential.prove(request) };
  await assert.rejects(createProfileReader(config).read()); assert.equal(calls, 1);
  for (const endpoint of [{ host: '127.0.0.1', port: 80 }, { host: 'example.com', port: 443 },
    { host: `https://${ENDPOINT.host}`, port: 443 }, { ...ENDPOINT, url: 'https://example.invalid' }]) {
    await assert.rejects(Promise.resolve().then(() => createProfileReader({ ...config,
      expectedOwner: { memberId: f.grant.memberId, endpoint } }).read()));
  }
  assert.equal(calls, 1);
});

test('anonymous challenge creation does not exhaust successful-read replay capacity', async () => {
  const f = await protocolFixture({ limits: { maxReplayEntries: 1 } });
  for (let i = 0; i < 50; i++) await f.owner.handle(frame({ hello: { version: 1, readerNonce: randomId() } }));
  assert.ok(await f.reader.read());
  await assert.rejects(f.reader.read());
  f.setNow(NOW + 30);
  assert.ok(await f.reader.read());
});

test('limits and transport/identity dependencies have no silent security defaults', async () => {
  assert.throws(() => createProfileOwner({}));
  assert.throws(() => createProfileReader({}));
  await assert.rejects(protocolFixture({ limits: { maxChallengeSeconds: 301 } }));
  await assert.rejects(protocolFixture({ limits: { maxReplayEntries: 0 } }));
});

test('a response that arrives after the reader deadline is not returned as current posture', async () => {
  const f = await protocolFixture();
  let readerNow = NOW;
  const transport = { async open(endpoint) {
    const channel = await f.onionTransport.open(endpoint);
    return { ...channel, async exchange(bytes) {
      const response = await channel.exchange(bytes);
      if (decode(response).profile) readerNow = NOW + 30;
      return response;
    } };
  } };
  const reader = createProfileReader({ ...f.trust, limits: f.limits, clock: () => readerNow,
    expectedOwner: { memberId: f.grant.memberId, endpoint: ENDPOINT }, onionTransport: transport,
    proveEligibility: request => f.credential.prove(request) });
  await assert.rejects(reader.read());
});

test('anonymous proof work has an explicit concurrency cap without a viewer identity table', async () => {
  const pending = [];
  const f = await protocolFixture({ owner: { verifyEligibilityProof: () => new Promise(resolve => pending.push(resolve)) } });
  const requests = [];
  for (let i = 0; i < 3; i++) {
    const envelope = decode(await f.owner.handle(frame({ hello: { version: 1, readerNonce: randomId() } }))).challenge;
    const presentation = f.credential.prove(referenceRequest(f.credential.issuer, envelope.value));
    requests.push(frame({ read: { challenge: envelope.value, ownerSignature: envelope.signature, presentation } }));
  }
  const finished = Promise.allSettled(requests.map(request => f.owner.handle(request)));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(pending.length, f.limits.maxConcurrentProofs);
  for (const resume of pending) resume(true);
  const results = await finished;
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 2);
});
