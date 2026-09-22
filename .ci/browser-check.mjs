// Execute only synthetic project fixtures in a preinstalled headless Chromium.
// No npm packages, browser downloads, persistent browser profiles or services.
import { createServer } from 'node:http';
import { readFile, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { tmpdir } from 'node:os';
import { resolve, join, extname, isAbsolute, sep } from 'node:path';

const root = resolve(process.cwd());
const artifact = process.env.BROWSER_EVIDENCE;
const binary = process.env.BROWSER_BIN;
const fixtureBinary = process.env.BROWSER_FIXTURE;
if (!binary || !artifact || !fixtureBinary) throw new Error('BROWSER_BIN, BROWSER_EVIDENCE and BROWSER_FIXTURE are required');
if (process.env.BROWSER_RUNTIME_ROOT && !isAbsolute(process.env.BROWSER_RUNTIME_ROOT)) {
  throw new Error('BROWSER_RUNTIME_ROOT must be an explicit absolute asset directory');
}
const runtimeRoot = process.env.BROWSER_RUNTIME_ROOT ?? join(root, 'browser/pkg');
const runtimeAssets = { source: process.env.BROWSER_RUNTIME_ROOT ? 'override' : 'repository', files: {} };
const mime = { '.mjs': 'text/javascript', '.js': 'text/javascript', '.wasm': 'application/wasm' };
const MAX_BODY = 16 * 1024;
const fixtureQueue = [];
const fixtureStats = { requests: 0, rejected: 0 };
let fixture;
let fixturePending;
let fixtureFailure;
let fixtureOutput = '';
let fixtureStderr = '';
let closing = false;

function failFixture(error) {
  fixtureFailure = error;
  if (fixturePending) {
    clearTimeout(fixturePending.timer);
    fixturePending.reject(error);
    fixturePending = undefined;
  }
  for (const queued of fixtureQueue.splice(0)) queued.reject(error);
}

function pumpFixture() {
  if (fixturePending || fixtureFailure || !fixtureQueue.length) return;
  fixturePending = fixtureQueue.shift();
  fixturePending.timer = setTimeout(() => failFixture(new Error('Native fixture response deadline exceeded')), 30_000);
  fixture.stdin.write(JSON.stringify(fixturePending.command) + '\n', error => {
    if (error) failFixture(new Error('Native fixture input failed'));
  });
}

function callFixture(command) {
  if (fixtureFailure) return Promise.reject(fixtureFailure);
  if (fixtureQueue.length >= 8 || fixtureStats.requests >= 64) return Promise.reject(new Error('Fixture bridge request bound exceeded'));
  fixtureStats.requests++;
  return new Promise((resolve, reject) => {
    fixtureQueue.push({ command, resolve, reject });
    pumpFixture();
  });
}

function exactKeys(value, expected) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === expected.sort().join(',');
}

// Only public protocol messages may cross this test bridge. Reject accidental
// private claim/checkpoint fields before they can enter the fixture process.
function publicFixtureCommand(value) {
  if (value?.action === 'config') return exactKeys(value, ['action']);
  if (value?.action === 'issue') return exactKeys(value, ['action', 'blindedRequest', 'nonce'])
    && typeof value.blindedRequest === 'string' && value.blindedRequest.length <= 832
    && typeof value.nonce === 'string' && value.nonce.length === 43;
  if (value?.action !== 'redeem' || !exactKeys(value, ['action', 'request'])) return false;
  const request = value.request;
  return exactKeys(request, ['permit', 'commitment', 'claim'])
    && typeof request.commitment === 'string' && request.commitment.length === 43
    && typeof request.claim === 'string' && request.claim.length === 43
    && exactKeys(request.permit, ['contextId', 'serial', 'randomizer', 'signature'])
    && Object.values(request.permit).every(field => typeof field === 'string' && field.length <= 1024);
}

const server = createServer(async (request, response) => {
  try {
    const pathname = new URL(request.url, 'http://localhost').pathname;
    if (pathname === '/fixture') {
      if (request.method !== 'POST' || request.headers.origin !== origin
          || !request.headers['content-type']?.startsWith('application/json')) {
        response.writeHead(400).end(); return;
      }
      const chunks = [];
      let size = 0;
      for await (const chunk of request) {
        size += chunk.length;
        if (size > MAX_BODY) { response.writeHead(413).end(); return; }
        chunks.push(chunk);
      }
      let command;
      try { command = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
      catch { response.writeHead(400).end(); return; }
      if (!publicFixtureCommand(command)) { response.writeHead(400).end(); return; }
      const reply = await callFixture(command);
      response.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      response.end(JSON.stringify(reply));
      return;
    }
    if (request.method !== 'GET') { response.writeHead(405).end(); return; }
    if (pathname === '/') {
      response.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' });
      response.end('<!doctype html><meta charset="utf-8"><title>cfrm browser contract</title>');
      return;
    }
    const decoded = decodeURIComponent(pathname);
    const runtimeName = decoded.startsWith('/browser/pkg/') ? decoded.slice('/browser/pkg/'.length) : undefined;
    if (runtimeName !== undefined && !['cfrm.js', 'cfrm_bg.wasm'].includes(runtimeName)) {
      response.writeHead(404).end(); return;
    }
    const file = runtimeName === undefined ? resolve(root, '.' + decoded) : join(runtimeRoot, runtimeName);
    if ((runtimeName === undefined && !file.startsWith(join(root, 'browser') + sep)) || !mime[extname(file)]) {
      response.writeHead(404).end(); return;
    }
    const bytes = await readFile(file);
    if (runtimeName !== undefined) runtimeAssets.files[runtimeName] = createHash('sha256').update(bytes).digest('hex');
    response.writeHead(200, { 'Content-Type': mime[extname(file)], 'Cache-Control': 'no-store' });
    response.end(bytes);
  } catch { if (!response.headersSent) response.writeHead(500); response.end(); }
});
server.requestTimeout = 10_000;
server.headersTimeout = 10_000;
server.listen(0, '127.0.0.1');
await once(server, 'listening');
const origin = `http://127.0.0.1:${server.address().port}`;
const profile = await mkdtemp(join(tmpdir(), 'cfrm-browser-test-'));
let browser;
let socket;
let stderr = '';
let browserVersion;
let nextId = 1;
const pending = new Map();
const forbiddenRequests = [];
const loaded = new Set();
let deadline;

async function command(method, params = {}) {
  const id = nextId++;
  const result = new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
  socket.send(JSON.stringify({ id, method, params }));
  return result;
}

try {
  fixture = spawn(fixtureBinary, [], { stdio: ['pipe', 'pipe', 'pipe'] });
  fixture.on('error', () => failFixture(new Error('Native fixture failed to start')));
  fixture.stdin.on('error', () => failFixture(new Error('Native fixture input closed')));
  fixture.on('exit', () => {
    if (!closing) failFixture(new Error(`Native fixture exited: ${fixtureStderr}`));
  });
  fixture.stderr.on('data', bytes => { fixtureStderr = (fixtureStderr + bytes.toString()).slice(-8000); });
  fixture.stdout.on('data', bytes => {
    fixtureOutput += bytes.toString();
    if (fixtureOutput.length > 32 * 1024) { failFixture(new Error('Native fixture output bound exceeded')); return; }
    let newline;
    while ((newline = fixtureOutput.indexOf('\n')) >= 0) {
      const line = fixtureOutput.slice(0, newline);
      fixtureOutput = fixtureOutput.slice(newline + 1);
      if (!fixturePending) { failFixture(new Error('Unsolicited native fixture output')); return; }
      let reply;
      try { reply = JSON.parse(line); }
      catch { failFixture(new Error('Malformed native fixture reply')); return; }
      if (!reply || typeof reply.ok !== 'boolean' || (reply.ok ? !('value' in reply) : typeof reply.error !== 'string')) {
        failFixture(new Error('Invalid native fixture reply')); return;
      }
      const waiting = fixturePending;
      fixturePending = undefined;
      clearTimeout(waiting.timer);
      if (!reply.ok) fixtureStats.rejected++;
      waiting.resolve(reply);
      pumpFixture();
    }
  });
  browser = spawn(binary, [
    '--headless', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage',
    '--disable-background-networking', '--disable-component-update', '--no-first-run',
    '--no-default-browser-check', '--disable-extensions', '--remote-debugging-address=127.0.0.1',
    '--remote-debugging-port=0', `--user-data-dir=${profile}`, `--disk-cache-dir=${join(profile, 'cache')}`, 'about:blank',
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
  let launchError;
  browser.on('error', error => { launchError = error; });
  browser.stderr.on('data', bytes => { stderr = (stderr + bytes.toString()).slice(-8000); });
  let port;
  for (let attempt = 0; attempt < 300; attempt++) {
    if (launchError) throw launchError;
    if (browser.exitCode !== null) throw new Error(`Chromium exited: ${stderr}`);
    try { port = Number((await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]); break; }
    catch { await new Promise(resolve => setTimeout(resolve, 100)); }
  }
  if (!port) throw new Error(`Chromium did not expose its test interface: ${stderr}`);
  const metadata = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
  browserVersion = metadata.Browser;
  const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  const page = targets.find(target => target.type === 'page');
  if (!page) throw new Error('Chromium has no test page');
  socket = new WebSocket(page.webSocketDebuggerUrl);
  await once(socket, 'open');
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.id) {
      const waiting = pending.get(message.id);
      if (waiting) {
        pending.delete(message.id);
        if (message.error) waiting.reject(new Error(JSON.stringify(message.error)));
        else waiting.resolve(message.result);
      }
    } else if (message.method === 'Page.lifecycleEvent' && message.params.name === 'load') {
      loaded.add(message.params.loaderId);
    } else if (message.method === 'Fetch.requestPaused') {
      const { requestId, request } = message.params;
      if (request.url.startsWith(origin + '/')) {
        command('Fetch.continueRequest', { requestId }).catch(() => {});
      } else {
        forbiddenRequests.push(request.url);
        command('Fetch.failRequest', { requestId, errorReason: 'BlockedByClient' }).catch(() => {});
      }
    }
  });
  await command('Page.enable');
  await command('Page.setLifecycleEventsEnabled', { enabled: true });
  await command('Runtime.enable');
  await command('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
  const navigation = await command('Page.navigate', { url: origin });
  if (navigation.errorText || !navigation.loaderId) throw new Error('Browser navigation failed');
  for (let attempt = 0; attempt < 300 && !loaded.has(navigation.loaderId); attempt++) {
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  if (!loaded.has(navigation.loaderId)) throw new Error('Browser navigation deadline exceeded');
  // Evaluation waits for the current page's document before importing fixtures.
  const running = command('Runtime.evaluate', {
    expression: "(async () => { while (document.readyState === 'loading') await new Promise(r => setTimeout(r, 10)); return await (await import('/browser/contract.mjs')).runBrowserContract(async request => { const response = await fetch('/fixture', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(request) }); if (!response.ok) throw new Error('Fixture bridge HTTP failure'); return await response.json(); }); })()",
    awaitPromise: true, returnByValue: true,
  });
  const result = await Promise.race([running, new Promise((_, reject) => {
    deadline = setTimeout(() => reject(new Error('Browser contract deadline exceeded')), 180_000);
  })]);
  if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
  if (!result.result || !('value' in result.result)) throw new Error('Browser contract returned no evidence');
  if (result.result.value?.ok !== true || result.result.value.count < 30 || fixtureStats.requests < 8) {
    throw new Error('Browser contract evidence incomplete');
  }
  if (fixtureFailure) throw fixtureFailure;
  if (forbiddenRequests.length) throw new Error(`Unexpected external requests: ${JSON.stringify(forbiddenRequests)}`);
  const evidence = { source: process.env.CI_COMMIT_SHA, browser: metadata.Browser,
    runtime: process.version, runtimeAssets, contract: result.result.value, fixture: fixtureStats, unexpectedExternalRequests: forbiddenRequests };
  await writeFile(artifact, JSON.stringify(evidence, null, 2) + '\n');
  process.stdout.write(JSON.stringify(evidence) + '\n');
} catch (error) {
  await writeFile(artifact, JSON.stringify({ source: process.env.CI_COMMIT_SHA,
    browser: browserVersion, runtime: process.version, runtimeAssets, ok: false,
    error: String(error), fixture: fixtureStats, fixtureError: fixtureFailure?.message,
    unexpectedExternalRequests: forbiddenRequests,
  }, null, 2) + '\n');
  throw error;
} finally {
  closing = true;
  failFixture(new Error('Fixture bridge closed'));
  clearTimeout(deadline);
  socket?.close();
  if (browser?.pid && browser.exitCode === null && browser.signalCode === null) {
    const exited = once(browser, 'close');
    browser.kill('SIGTERM');
    const force = setTimeout(() => browser.kill('SIGKILL'), 5000);
    await exited;
    clearTimeout(force);
  }
  if (fixture?.pid && fixture.exitCode === null && fixture.signalCode === null) {
    const exited = once(fixture, 'close');
    fixture.kill('SIGTERM');
    const force = setTimeout(() => fixture.kill('SIGKILL'), 5000);
    await exited;
    clearTimeout(force);
  }
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
  // Chromium can finish a final profile write as its children shut down.
  // Retry only this owned temporary directory, after process/stdio closure.
  await rm(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
