import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { createFramedSocket, startProfileWireService, createOnionProfileTransport } from './wire.js';
import { createProfileReader } from './protocol.js';
import { NOW, ENDPOINT, frame, decode, protocolFixture } from './fixtures.js';

const limits = { maxFrameBytes: 4096, frameTimeoutMs: 1000, sessionTimeoutMs: 3000, maxConnections: 2 };
const hello = frame({ hello: { version: 1, readerNonce: 'synthetic-wire-only' } });
const read = frame({ read: { synthetic: true } });
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }
function packet(bytes) { const result = Buffer.alloc(bytes.length + 4); result.writeUInt32BE(bytes.length); result.set(bytes, 4); return result; }
function prefix(length) { const result = Buffer.alloc(4); result.writeUInt32BE(length); return result; }
async function connect(t, address) {
  const socket = net.createConnection({ host: address.host, port: address.port });
  socket.on('error', () => {});
  t.after(() => socket.destroy()); await once(socket, 'connect'); return socket;
}
async function pair(t) {
  const server = net.createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => server.close()); const incoming = once(server, 'connection');
  const client = await connect(t, { host: '127.0.0.1', port: server.address().port });
  const [socket] = await incoming; socket.on('error', () => {}); t.after(() => socket.destroy());
  return { socket, client };
}
async function closed(socket) { if (!socket.destroyed) await new Promise(resolve => socket.once('close', resolve)); }
function ownerDouble(overrides = {}) {
  const calls = { active: 0, disconnected: 0, requests: [] };
  const owner = {
    activate() { calls.active++; }, disconnect() { calls.disconnected++; },
    async handle(bytes) {
      calls.requests.push(decode(bytes));
      return frame(Object.hasOwn(decode(bytes), 'hello') ? { challenge: { synthetic: true } } : { profile: { text: 'bounded local text' } });
    }, ...overrides,
  };
  return { owner, calls };
}
async function serviceFixture(t, overrides = {}) {
  const f = ownerDouble(overrides.owner); const loss = new AbortController(); const seen = [];
  let publicationClosed = 0;
  const publication = { signal: loss.signal, close() { publicationClosed++; } };
  const options = {
    owner: f.owner, endpoint: ENDPOINT, leaseExpiresAt: NOW + 60, bindHost: '127.0.0.1', clock: () => NOW,
    limits, onionServiceProvider: { async publish(value) { seen.push(value); return publication; } },
    async verifyPublication(value) {
      assert.equal(value.publication, publication); assert.deepEqual(value.endpoint, ENDPOINT);
      assert.equal(value.localAddress.host, '127.0.0.1'); assert.ok(value.localAddress.port > 0); return true;
    }, ...overrides, owner: f.owner,
  };
  const service = await startProfileWireService(options); t.after(() => service.disconnect());
  return { ...f, service, options, loss, seen, publicationClosed: () => publicationClosed };
}

test('real sockets reassemble fragmented BE header/body and emit exact framed bytes', async t => {
  const { socket, client } = await pair(t);
  const channel = createFramedSocket(socket, limits);
  const pending = channel.read(); const bytes = packet(Buffer.from('UTF-8: ö'));
  for (const part of [bytes.subarray(0, 1), bytes.subarray(1, 3), bytes.subarray(3, 6), bytes.subarray(6)]) client.write(part);
  assert.equal(Buffer.from(await pending).toString(), 'UTF-8: ö');
  const received = []; client.on('data', chunk => received.push(chunk));
  await channel.write(Buffer.from('reply')); channel.close(); await closed(client);
  assert.deepEqual(Buffer.concat(received), packet(Buffer.from('reply')));
});

test('zero and oversized prefixes terminate before any body or handler work', async t => {
  for (const length of [0, limits.maxFrameBytes + 1, 0xffffffff]) {
    const { socket, client } = await pair(t); const channel = createFramedSocket(socket, limits);
    const pending = assert.rejects(channel.read()); client.write(prefix(length)); await pending;
    assert.equal(socket.destroyed, true); await assert.rejects(channel.read());
  }
});

test('truncated headers and bodies terminate instead of treating EOF as a frame', async t => {
  for (const bytes of [Buffer.from([0, 0]), Buffer.concat([prefix(20), Buffer.from('short')])]) {
    const { socket, client } = await pair(t); const channel = createFramedSocket(socket, limits);
    const pending = assert.rejects(channel.read()); client.end(bytes); await pending;
    assert.equal(socket.destroyed, true);
  }
});

test('whole-frame deadline cannot be extended by dribbling bytes', async t => {
  const { socket, client } = await pair(t);
  const channel = createFramedSocket(socket, { ...limits, frameTimeoutMs: 60 });
  const pending = assert.rejects(channel.read()); client.write(prefix(30));
  const interval = setInterval(() => client.write(Buffer.from('x')), 10); t.after(() => clearInterval(interval));
  await pending; assert.equal(socket.destroyed, true);
});

test('overlapping operations, pipelined frames and explicit cancellation close the socket', async t => {
  for (const behavior of ['overlap', 'pipeline', 'cancel']) {
    const { socket, client } = await pair(t); const channel = createFramedSocket(socket, limits);
    const pending = channel.read(); const settled = Promise.allSettled([pending]);
    if (behavior === 'overlap') await assert.rejects(channel.read());
    if (behavior === 'pipeline') client.write(Buffer.concat([packet(hello), packet(hello)]));
    if (behavior === 'cancel') channel.close();
    assert.equal((await settled)[0].status, 'rejected'); assert.equal(socket.destroyed, true);
  }
});

test('explicit limits reject zero, missing and excessive configuration', async t => {
  const { socket } = await pair(t);
  for (const invalid of [{}, { ...limits, maxFrameBytes: 0 }, { ...limits, maxFrameBytes: 1048577 },
    { ...limits, frameTimeoutMs: 60001 }]) assert.throws(() => createFramedSocket(socket, invalid));
  const f = ownerDouble();
  await assert.rejects(startProfileWireService({ owner: f.owner, endpoint: ENDPOINT, limits }));
});

test('listener rejects non-loopback bind and requires explicit publication verification', async t => {
  const f = await serviceFixture(t); await f.service.disconnect();
  for (const bindHost of ['0.0.0.0', '::', 'localhost', '192.0.2.1']) {
    await assert.rejects(startProfileWireService({ ...f.options, bindHost }));
  }
  await assert.rejects(startProfileWireService({ ...f.options, verifyPublication: undefined }));
  await assert.rejects(startProfileWireService({ ...f.options, verifyPublication: async () => false }));
});

test('owner stays disconnected while publication verification awaits and rejects early sockets', async t => {
  const f = ownerDouble(); const published = deferred(), verified = deferred(); const loss = new AbortController();
  let publicationClosed = 0;
  const starting = startProfileWireService({ owner: f.owner, endpoint: ENDPOINT, leaseExpiresAt: NOW + 60,
    bindHost: '127.0.0.1', clock: () => NOW, limits,
    onionServiceProvider: { async publish(value) { published.resolve(value.localAddress); return {
      signal: loss.signal, close() { publicationClosed++; },
    }; } }, verifyPublication: () => verified.promise });
  // Stub failures must be observable, not leave this test waiting for publication.
  const address = await Promise.race([published.promise, starting.then(() => { throw new Error('Premature start'); })]);
  const socket = await connect(t, address); socket.write(packet(hello)); await closed(socket);
  assert.equal(f.calls.active, 0); assert.ok(f.calls.disconnected >= 1);
  verified.resolve(true); const service = await starting; t.after(() => service.disconnect());
  assert.equal(f.calls.active, 1); await service.disconnect(); assert.equal(publicationClosed, 1);
});

test('real loopback sessions permit hello then read only and close after the bounded response', async t => {
  const f = await serviceFixture(t); const socket = await connect(t, f.service.localAddress);
  const channel = createFramedSocket(socket, limits);
  await channel.write(hello); assert.ok(decode(await channel.read()).challenge);
  await channel.write(read); assert.equal(decode(await channel.read()).profile.text, 'bounded local text');
  await closed(socket); assert.equal(f.calls.requests.length, 2);
  const bad = await connect(t, f.service.localAddress); bad.write(packet(read)); await closed(bad);
  assert.equal(f.calls.requests.length, 2);
});

test('connection cap includes idle sessions and capacity returns after closure', async t => {
  const f = await serviceFixture(t, { limits: { ...limits, maxConnections: 1 } });
  const first = await connect(t, f.service.localAddress); const excess = await connect(t, f.service.localAddress);
  await closed(excess); assert.equal(first.destroyed, false); first.destroy(); await closed(first);
  await delay(20); const next = await connect(t, f.service.localAddress); const channel = createFramedSocket(next, limits);
  await channel.write(hello); assert.ok(decode(await channel.read()).challenge);
});

test('session deadline closes an idle connection without more requests', async t => {
  const f = await serviceFixture(t, { limits: { ...limits, sessionTimeoutMs: 50 } });
  const socket = await connect(t, f.service.localAddress); await closed(socket);
  assert.equal(f.calls.requests.length, 0);
});

test('disconnecting peers cannot free capacity while their handler work is still pending', async t => {
  const entered = deferred(), release = deferred();
  const f = await serviceFixture(t, { limits: { ...limits, maxConnections: 1 },
    owner: { async handle() { entered.resolve(); await release.promise; return frame({ challenge: { synthetic: true } }); } } });
  const first = await connect(t, f.service.localAddress); first.write(packet(hello)); await entered.promise;
  first.destroy(); await closed(first);
  const excess = await connect(t, f.service.localAddress); await closed(excess);
  release.resolve(); await delay(20);
  const next = await connect(t, f.service.localAddress); const channel = createFramedSocket(next, limits);
  await channel.write(hello); assert.ok(decode(await channel.read()).challenge);
});

test('disconnect, lease expiry and publication loss suppress pending handler responses', async t => {
  for (const trigger of ['disconnect', 'lease', 'publication']) {
    const entered = deferred(), release = deferred(); let now = NOW;
    const f = await serviceFixture(t, { clock: () => now,
      owner: { async handle() { entered.resolve(); await release.promise; return frame({ challenge: { text: 'must not escape' } }); } } });
    const socket = await connect(t, f.service.localAddress); const received = [];
    socket.on('data', bytes => received.push(bytes)); socket.write(packet(hello)); await entered.promise;
    if (trigger === 'disconnect') await f.service.disconnect();
    if (trigger === 'lease') now += 61;
    if (trigger === 'publication') f.loss.abort();
    release.resolve(); await closed(socket); assert.equal(Buffer.concat(received).length, 0);
    await f.service.disconnect(); assert.ok(f.calls.disconnected >= 2);
  }
});

test('lease timer closes idle listeners and accepted sockets without new traffic', async t => {
  const now = Math.floor(Date.now() / 1000);
  const f = await serviceFixture(t, { clock: () => Math.floor(Date.now() / 1000), leaseExpiresAt: now + 1 });
  const socket = await connect(t, f.service.localAddress);
  await f.service.closed; await closed(socket); assert.ok(f.calls.disconnected >= 2);
});

test('reader dials only a validated onion capability and never retries direct routes', async t => {
  const f = await serviceFixture(t); const destinations = [];
  const transport = createOnionProfileTransport({ limits, async dialOnion(endpoint) {
    destinations.push(endpoint); return connect(t, f.service.localAddress);
  } });
  const connection = await transport.open(ENDPOINT);
  assert.ok(decode(await connection.exchange(hello)).challenge);
  assert.ok(decode(await connection.exchange(read)).profile); connection.close();
  assert.deepEqual(destinations, [ENDPOINT]);
  for (const host of ['127.0.0.1', 'example.com', 'https://example.com', `${'a'.repeat(56)}.onion`]) {
    await assert.rejects(transport.open({ host, port: 443 }));
  }
  assert.equal(destinations.length, 1);
  let failures = 0;
  const unavailable = createOnionProfileTransport({ limits, async dialOnion() { failures++; throw new Error('Unavailable'); } });
  await assert.rejects(unavailable.open(ENDPOINT)); assert.equal(failures, 1);
  assert.throws(() => createOnionProfileTransport({ limits }));
});

test('reader session cancellation aborts a pending dial and destroys late sockets', async t => {
  const { socket } = await pair(t); const release = deferred(); let signal;
  const transport = createOnionProfileTransport({ limits: { ...limits, sessionTimeoutMs: 40 },
    async dialOnion(endpoint, options) { signal = options.signal; await release.promise; return socket; } });
  await assert.rejects(transport.open(ENDPOINT)); assert.equal(signal.aborted, true);
  release.resolve(); await closed(socket);
});

test('real anonymous credential and certified owner flow crosses actual loopback framing', async t => {
  const f = await protocolFixture(); const wireLimits = { ...limits, maxFrameBytes: f.limits.maxFrameBytes, frameTimeoutMs: 30000, sessionTimeoutMs: 60000 };
  const loss = new AbortController();
  const service = await startProfileWireService({ owner: f.owner, endpoint: ENDPOINT, leaseExpiresAt: NOW + 120,
    bindHost: '127.0.0.1', clock: () => NOW, limits: wireLimits,
    onionServiceProvider: { async publish() { return { signal: loss.signal, close() {} }; } },
    // Synthetic publication explicitly tests loopback integration, not Tor ownership.
    verifyPublication: async () => true });
  t.after(() => service.disconnect()); const destinations = [];
  const transport = createOnionProfileTransport({ limits: wireLimits, async dialOnion(endpoint) {
    destinations.push(endpoint); return connect(t, service.localAddress);
  } });
  const reader = createProfileReader({ ...f.trust, clock: () => NOW, limits: f.limits,
    expectedOwner: { memberId: f.grant.memberId, endpoint: ENDPOINT }, onionTransport: transport,
    proveEligibility: request => f.credential.prove(request) });
  assert.deepEqual(await reader.read(), { ownerMemberId: f.grant.memberId, text: 'A quiet place to discuss shared interests.' });
  assert.deepEqual(destinations, [ENDPOINT]);
});
