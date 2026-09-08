// Node socket integration for the member-owned protocol, never an operator service.
import net from 'node:net';
import { validateProfileEndpoint } from './protocol.js';

const rejected = () => new Error('Profile wire connection rejected');
function positive(value, maximum) {
  if (!Number.isSafeInteger(value) || value < 1 || (maximum !== undefined && value > maximum)) throw rejected();
  return value;
}
function frameLimits(value) {
  if (!value || typeof value !== 'object') throw rejected();
  return { maxFrameBytes: positive(value.maxFrameBytes, 1048576), frameTimeoutMs: positive(value.frameTimeoutMs, 60000) };
}
function sessionLimits(value) {
  return { ...frameLimits(value), sessionTimeoutMs: positive(value.sessionTimeoutMs, 300000),
    maxConnections: positive(value.maxConnections) };
}
function jsonKind(bytes, expected, maxFrameBytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 1 || bytes.length > maxFrameBytes) throw rejected();
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== 1 || !Object.hasOwn(value, expected)) throw rejected();
}
function waitFor(promise, signal) {
  if (signal.aborted) { Promise.resolve(promise).catch(() => {}); return Promise.reject(rejected()); }
  return new Promise((resolve, reject) => {
    const aborted = () => reject(rejected());
    signal.addEventListener('abort', aborted, { once: true });
    Promise.resolve(promise).then(resolve, () => reject(rejected())).finally(() => signal.removeEventListener('abort', aborted));
  });
}

export function createFramedSocket(socket, options) {
  const limits = frameLimits(options);
  if (!(socket instanceof net.Socket) || socket.destroyed) throw rejected();
  let terminal = false, operation = null, deadline = null, incomingDeadline = null;
  let header = Buffer.alloc(4), headerUsed = 0, body = null, bodyUsed = 0, ready = null;
  let receiveAfterWrite = false;
  function clearDeadlines() { clearTimeout(deadline); clearTimeout(incomingDeadline); deadline = incomingDeadline = null; }
  function close() {
    if (terminal) return;
    terminal = true; clearDeadlines(); const pending = operation; operation = null;
    ready = body = null; socket.destroy(); pending?.reject(rejected());
  }
  function finish(value) {
    const pending = operation; operation = null; clearTimeout(deadline); deadline = null;
    pending?.resolve(value);
  }
  function resetIncoming() {
    clearTimeout(incomingDeadline); incomingDeadline = null;
    header = Buffer.alloc(4); headerUsed = 0; body = null; bodyUsed = 0;
  }
  function completed() {
    const bytes = body; resetIncoming();
    if (operation?.kind === 'read') { receiveAfterWrite = false; finish(new Uint8Array(bytes)); }
    else ready = bytes;
  }
  socket.on('error', close); socket.on('end', close); socket.on('close', close);
  socket.on('data', chunk => {
    if (terminal) return;
    if (ready || (!operation && !receiveAfterWrite)) { close(); return; }
    if (!incomingDeadline) incomingDeadline = setTimeout(close, limits.frameTimeoutMs);
    let offset = 0;
    if (headerUsed < 4) {
      const count = Math.min(4 - headerUsed, chunk.length);
      chunk.copy(header, headerUsed, 0, count); headerUsed += count; offset += count;
      if (headerUsed < 4) return;
      const length = header.readUInt32BE();
      if (length < 1 || length > limits.maxFrameBytes) { close(); return; }
      body = Buffer.alloc(length);
    }
    const count = Math.min(body.length - bodyUsed, chunk.length - offset);
    chunk.copy(body, bodyUsed, offset, offset + count); bodyUsed += count; offset += count;
    // Reject coalesced extra frames before fulfilling the first pending read.
    if (offset !== chunk.length) { close(); return; }
    if (bodyUsed === body.length) completed();
  });
  function begin(kind, action) {
    if (terminal) return Promise.reject(rejected());
    if (operation) { close(); return Promise.reject(rejected()); }
    return new Promise((resolve, reject) => {
      operation = { kind, resolve, reject }; deadline = setTimeout(close, limits.frameTimeoutMs);
      try { action(); } catch { close(); }
    });
  }
  return Object.freeze({
    read() {
      return begin('read', () => {
        if (ready) { const bytes = ready; ready = null; receiveAfterWrite = false; finish(new Uint8Array(bytes)); }
        else { receiveAfterWrite = false; socket.resume(); }
      });
    },
    write(bytes) {
      if (!(bytes instanceof Uint8Array) || bytes.length < 1 || bytes.length > limits.maxFrameBytes) {
        close(); return Promise.reject(rejected());
      }
      return begin('write', () => {
        receiveAfterWrite = true;
        const packet = Buffer.alloc(bytes.length + 4); packet.writeUInt32BE(bytes.length); packet.set(bytes, 4);
        socket.write(packet, error => { if (error) close(); else if (!terminal) finish(); });
      });
    }, close,
  });
}

export async function startProfileWireService(options) {
  const limits = sessionLimits(options?.limits);
  if (!options || typeof options.clock !== 'function' ||
      !['127.0.0.1', '::1'].includes(options.bindHost) ||
      typeof options.owner?.activate !== 'function' || typeof options.owner?.disconnect !== 'function' ||
      typeof options.owner?.handle !== 'function' || typeof options.onionServiceProvider?.publish !== 'function' ||
      typeof options.verifyPublication !== 'function') throw rejected();
  const endpoint = Object.freeze(validateProfileEndpoint(options.endpoint));
  const leaseExpiresAt = positive(options.leaseExpiresAt);
  const now = () => positive(options.clock());
  if (now() >= leaseExpiresAt) throw rejected();
  const owner = options.owner, abort = new AbortController(), sessions = new Set();
  const closedPublications = new Set();
  let state = 'starting', publication = null, publicationLoss = null, localAddress;
  let leaseTimer, startupTimer, resolveClosed;
  const closed = new Promise(resolve => { resolveClosed = resolve; });
  function closePublication(value) {
    if (!value || closedPublications.has(value)) return;
    closedPublications.add(value);
    try { Promise.resolve(value.close?.()).catch(() => {}); } catch {}
  }
  const server = net.createServer({ pauseOnConnect: true }, socket => {
    socket.on('error', () => {});
    try {
      live();
      if (sessions.size >= limits.maxConnections) { socket.destroy(); return; }
      const channel = createFramedSocket(socket, limits);
      const session = { socket, channel, timer: setTimeout(() => channel.close(), limits.sessionTimeoutMs) };
      sessions.add(session);
      socket.once('close', () => { clearTimeout(session.timer); });
      void serve(session);
    } catch { socket.destroy(); }
  });
  server.on('error', () => { disconnect(); });
  function disconnect() {
    if (state === 'closed') return closed;
    state = 'closed'; abort.abort(); clearTimeout(startupTimer); clearTimeout(leaseTimer);
    publicationLoss?.removeEventListener('abort', disconnect);
    try { owner.disconnect(); } catch {}
    for (const session of sessions) { clearTimeout(session.timer); session.channel.close(); }
    closePublication(publication);
    server.close(() => resolveClosed());
    return closed;
  }
  function live() {
    if (state !== 'active') throw rejected();
    if (publicationLoss?.aborted || now() >= leaseExpiresAt) { disconnect(); throw rejected(); }
  }
  async function serve(session) {
    const { socket, channel } = session;
    try {
      for (const [requestKind, responseKind] of [['hello', 'challenge'], ['read', 'profile']]) {
        live(); const request = await channel.read(); live();
        if (socket.destroyed) throw rejected();
        jsonKind(request, requestKind, limits.maxFrameBytes);
        const response = await owner.handle(request);
        live(); if (socket.destroyed) throw rejected();
        jsonKind(response, responseKind, limits.maxFrameBytes); await channel.write(response); live();
      }
    } catch { /* A rejected session returns no diagnostic payload or profile metadata. */ }
    finally { channel.close(); clearTimeout(session.timer); sessions.delete(session); }
  }
  function watchLease() {
    if (state !== 'active') return;
    try {
      live(); leaseTimer = setTimeout(watchLease, Math.min(1000, (leaseExpiresAt - now()) * 1000));
    } catch { disconnect(); }
  }
  try {
    owner.disconnect();
    startupTimer = setTimeout(disconnect, limits.sessionTimeoutMs);
    await waitFor(new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, options.bindHost, () => { server.removeListener('error', reject); resolve(); });
    }), abort.signal);
    const address = server.address();
    if (state === 'closed' || !address || typeof address !== 'object') throw rejected();
    localAddress = Object.freeze({ host: address.address, port: address.port });
    const pending = Promise.resolve().then(() => options.onionServiceProvider.publish({ endpoint, localAddress, signal: abort.signal }));
    pending.then(value => { if (state === 'closed') closePublication(value); }, () => {});
    publication = await waitFor(pending, abort.signal);
    if (typeof publication?.close !== 'function' || !(publication?.signal instanceof AbortSignal)) throw rejected();
    publicationLoss = publication.signal;
    publicationLoss.addEventListener('abort', disconnect, { once: true });
    if (publicationLoss.aborted) throw rejected();
    const verified = await waitFor(Promise.resolve().then(() => options.verifyPublication({
      publication, endpoint, localAddress, signal: abort.signal,
    })), abort.signal);
    if (verified !== true || state === 'closed' || publicationLoss.aborted || now() >= leaseExpiresAt) throw rejected();
    owner.activate({ endpoint, leaseExpiresAt });
    state = 'active'; clearTimeout(startupTimer); watchLease(); live();
    return Object.freeze({ localAddress, disconnect, closed });
  } catch {
    disconnect();
    // A listen completing after cancellation is immediately closed as well.
    if (server.listening) server.close();
    throw rejected();
  }
}

export function createOnionProfileTransport(options) {
  const limits = sessionLimits(options?.limits);
  if (typeof options?.dialOnion !== 'function') throw rejected();
  const dial = options.dialOnion;
  return Object.freeze({
    async open(destination) {
      const endpoint = Object.freeze(validateProfileEndpoint(destination));
      const abort = new AbortController(); let channel, socket, busy = false, stage = 0;
      function close() { clearTimeout(timer); abort.abort(); channel?.close(); socket?.destroy(); }
      const timer = setTimeout(close, limits.sessionTimeoutMs);
      try {
        const pending = Promise.resolve().then(() => dial(endpoint, { signal: abort.signal }));
        pending.then(value => { if (abort.signal.aborted) value?.destroy?.(); }, () => {});
        socket = await waitFor(pending, abort.signal);
        if (abort.signal.aborted) throw rejected();
        channel = createFramedSocket(socket, limits);
        return Object.freeze({
          async exchange(bytes) {
            if (abort.signal.aborted || busy || stage > 1) { close(); throw rejected(); }
            busy = true;
            try {
              jsonKind(bytes, stage === 0 ? 'hello' : 'read', limits.maxFrameBytes);
              await channel.write(bytes);
              if (abort.signal.aborted) throw rejected();
              const response = await channel.read();
              if (abort.signal.aborted) throw rejected();
              jsonKind(response, stage === 0 ? 'challenge' : 'profile', limits.maxFrameBytes);
              stage++; return response;
            } catch { close(); throw rejected(); }
            finally { busy = false; }
          }, close,
        });
      } catch { close(); throw rejected(); }
    },
  });
}
