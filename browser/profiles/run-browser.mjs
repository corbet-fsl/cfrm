// CI-only runner. Uses an already installed Chromium and Node's native CDP
// WebSocket support; no packages, browser download or persistent user profile.
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const binary = process.env.BROWSER_BIN, artifact = process.env.PROFILE_BROWSER_EVIDENCE;
if (!binary || !artifact) throw new Error('BROWSER_BIN and PROFILE_BROWSER_EVIDENCE are required');
const directory = dirname(fileURLToPath(import.meta.url));
const profile = await mkdtemp(join(tmpdir(), 'cfrm-profile-contract-'));
let browser, socket, stderr = '', version, nextId = 0, deadline, stop;
const pending = new Map(), forbidden = [];
const cancellation = new Promise((_, reject) => { stop = reason => reject(new Error(reason)); });
cancellation.catch(() => {});
const terminate = () => stop('Profile browser test interrupted');
process.once('SIGTERM', terminate); process.once('SIGINT', terminate);
const server = createServer(async (request, response) => {
  try {
    const pathname = new URL(request.url, 'http://localhost').pathname;
    if (request.method !== 'GET') { response.writeHead(405).end(); return; }
    if (pathname === '/') {
      response.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' });
      response.end('<!doctype html><meta charset="utf-8"><title>Profile WebCrypto contract</title>'); return;
    }
    if (pathname !== `/${basename(pathname)}` || !/^[a-z-]+\.(js|mjs)$/.test(basename(pathname)) || pathname === '/run-browser.mjs') {
      response.writeHead(404).end(); return;
    }
    const bytes = await readFile(join(directory, basename(pathname)));
    response.writeHead(200, { 'Content-Type': 'text/javascript', 'Cache-Control': 'no-store' }); response.end(bytes);
  } catch { response.writeHead(404).end(); }
});
server.requestTimeout = 10_000; server.headersTimeout = 10_000;

async function command(method, params = {}) {
  const id = ++nextId;
  const result = new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`CDP ${method} timed out`)); }, method === 'Runtime.evaluate' ? 120_000 : 15_000);
    pending.set(id, { resolve, reject, timer });
  });
  socket.send(JSON.stringify({ id, method, params })); return result;
}
const pause = () => new Promise(resolve => setTimeout(resolve, 100));
async function run() {
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const origin = `http://127.0.0.1:${server.address().port}`;
  browser = spawn(binary, ['--headless', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage',
    '--disable-background-networking', '--disable-component-update', '--no-first-run', '--no-default-browser-check',
    '--disable-extensions', '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0',
    `--user-data-dir=${profile}`, `--disk-cache-dir=${join(profile, 'cache')}`, 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
  browser.on('error', error => stop(error.message));
  browser.stderr.on('data', bytes => { stderr = (stderr + bytes.toString()).slice(-6000); });
  let port;
  for (let attempt = 0; attempt < 300; attempt++) {
    if (browser.exitCode !== null) throw new Error(`Chromium exited: ${stderr}`);
    try { port = Number((await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]); break; }
    catch { await pause(); }
  }
  if (!port) throw new Error(`Chromium startup deadline: ${stderr}`);
  const metadata = await (await fetch(`http://127.0.0.1:${port}/json/version`, { signal: AbortSignal.timeout(10_000) })).json();
  version = metadata.Browser;
  const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`, { signal: AbortSignal.timeout(10_000) })).json();
  const page = targets.find(target => target.type === 'page');
  if (!page) throw new Error('Chromium has no test page');
  socket = new WebSocket(page.webSocketDebuggerUrl); await once(socket, 'open');
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.id) {
      const waiting = pending.get(message.id); if (!waiting) return;
      pending.delete(message.id); clearTimeout(waiting.timer);
      if (message.error) waiting.reject(new Error(JSON.stringify(message.error))); else waiting.resolve(message.result);
    } else if (message.method === 'Fetch.requestPaused') {
      const { requestId, request } = message.params;
      if (request.url.startsWith(origin + '/')) command('Fetch.continueRequest', { requestId }).catch(() => {});
      else { forbidden.push(request.url); command('Fetch.failRequest', { requestId, errorReason: 'BlockedByClient' }).catch(() => {}); }
    }
  });
  await command('Page.enable'); await command('Runtime.enable');
  await command('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
  const navigation = await command('Page.navigate', { url: origin });
  if (navigation.errorText) throw new Error('Profile contract navigation failed');
  let loaded = false;
  for (let attempt = 0; attempt < 300; attempt++) {
    const state = await command('Runtime.evaluate', { expression: `location.origin === ${JSON.stringify(origin)} && document.readyState === 'complete'`, returnByValue: true });
    if (state.result?.value === true) { loaded = true; break; }
    await pause();
  }
  if (!loaded) throw new Error('Profile contract document deadline');
  const result = await command('Runtime.evaluate', { expression: "import('/contract.mjs').then(module => module.runProfileClientContract())", awaitPromise: true, returnByValue: true });
  if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
  const contract = result.result?.value;
  if (!contract || contract.count < 18 || contract.count !== contract.checks?.length || forbidden.length) throw new Error('Incomplete browser evidence');
  return { source: process.env.CI_COMMIT_SHA, browser: version, runtime: process.version, contract,
    unexpectedTabRequests: forbidden, networkLimit: 'Tab interception is not browser-process packet confinement' };
}
try {
  deadline = setTimeout(() => stop('Profile browser contract deadline exceeded'), 180_000);
  const evidence = await Promise.race([run(), cancellation]);
  await writeFile(artifact, JSON.stringify(evidence, null, 2) + '\n'); process.stdout.write(JSON.stringify(evidence) + '\n');
} catch (error) {
  await writeFile(artifact, JSON.stringify({ source: process.env.CI_COMMIT_SHA, browser: version, ok: false,
    error: String(error), unexpectedTabRequests: forbidden }, null, 2) + '\n'); throw error;
} finally {
  clearTimeout(deadline); process.off('SIGTERM', terminate); process.off('SIGINT', terminate);
  for (const waiting of pending.values()) { clearTimeout(waiting.timer); waiting.reject(new Error('Browser closed')); }
  pending.clear(); socket?.close(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
  if (browser?.pid && browser.exitCode === null && browser.signalCode === null) {
    const exited = once(browser, 'exit'); browser.kill('SIGTERM');
    const timer = setTimeout(() => browser.kill('SIGKILL'), 5000); await exited; clearTimeout(timer);
  }
  await rm(profile, { recursive: true, force: true });
}
