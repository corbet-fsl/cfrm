// Dedicated bounded CI runner. Existing Chromium, temporary loopback server.
import { createServer } from 'node:http';
import { readFile, readdir, writeFile, mkdtemp, rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { resolve, join, extname, sep } from 'node:path';
import { tmpdir } from 'node:os';
import { checkScheme, SHA_SCHEME, POSEIDON_SCHEME } from './hashes.mjs';

const binary = process.env.BROWSER_BIN;
const fixtureBinary = process.env.ACCOUNTING_FIXTURE;
const evidencePath = process.env.BROWSER_EVIDENCE;
const checkPhase = process.env.BROWSER_CHECK_PHASE ?? 'proof';
if (!['proof', 'startup'].includes(checkPhase)) throw new Error('Unsupported browser check phase');
const startupOnly = checkPhase === 'startup';
if (startupOnly && (!process.env.BROWSER_DIST || !/^[0-9a-f]{40}$/.test(process.env.BROWSER_BUNDLE_SHA ?? ''))) {
  throw new Error('Startup check requires BROWSER_DIST and exact BROWSER_BUNDLE_SHA');
}
const hashScheme = startupOnly ? null : checkScheme(process.env.HASH_SCHEME ?? SHA_SCHEME);
const accountingMode = startupOnly ? null : process.env.ACCOUNTING_MODE ?? 'settlement-v1';
const accountScenario = process.env.ACCOUNT_SCENARIO;
// Account-state Close includes twelve sequential proofs and the shipped factory.
// Keep its browser work bounded with room beyond the measured fifteen minutes.
const browserProofDeadlineMs = accountingMode === 'account-state-v2' ? 1_200_000 : 480_000;
if (!startupOnly) {
  if (!['settlement-v1','account-state-v2'].includes(accountingMode)
      || (accountingMode === 'account-state-v2' && !['answer','close'].includes(accountScenario))) throw new Error('Explicit accounting mode/scenario required');
  const localManifest = JSON.parse(await readFile('public/manifest.json', 'utf8'));
  if (localManifest.hashScheme !== hashScheme) throw new Error('Harness hash scheme differs from built circuit');
  if ((localManifest.accountingMode ?? 'settlement-v1') !== accountingMode) throw new Error('Harness accounting mode differs from build');
}
if (!binary || (!startupOnly && !fixtureBinary) || !evidencePath) throw new Error('BROWSER_BIN, BROWSER_EVIDENCE and proof ACCOUNTING_FIXTURE required');
const root = resolve(startupOnly ? process.env.BROWSER_DIST : 'dist');
const profile = await mkdtemp(join(tmpdir(), 'cfrm-accounting-'));
const evidence = { source: process.env.CI_COMMIT_SHA, runtime: process.version, hashScheme, accountingMode, accountScenario, ok: false,
  checkPhase, ...(startupOnly ? { bundleSource: process.env.BROWSER_BUNDLE_SHA,
    scope: 'Static browser entry initialization; proof behavior is untested', heldManifestRequests: 0 } : {}),
  fixtureRequests: 0, forbiddenRequests: [], loadedBytes: 0, browserErrors: [] };
let fixture, browser, socket, origin, fixtureWaiting, fixtureTimer, deadline, browserMemory, ledgerBridge;
let fixtureOutput = '', fixtureStderr = '', stderr = '', enrolled;
const pending = new Map(); let nextId = 1;
const loaded = new Set();
const closed = new WeakMap();
function captureClose(child) { closed.set(child, new Promise(resolve => child.once('close', resolve))); return child; }

// Read only our Chromium PID and descendants discovered through its thread
// children files. Never enumerate /proc globally or retain process contents.
function sampleBrowserMemory(child) {
  const intervalMs = 200, sampleDeadlineMs = 750, maximumDurationMs = Math.max(browserProofDeadlineMs, 600_000);
  const maximumProcesses = 128, maximumThreads = 256, maximumReads = 2048;
  const began = performance.now();
  const report = {
    measurement: 'sampled Chromium process-family PSS estimate; not exact Wasm peak',
    scope: 'Chromium and discovered descendants only; native fixture and Node verifier excluded',
    source: '/proc/PID/smaps_rollup; VmRSS fallback from /proc/PID/status',
    sampleIntervalMs: intervalMs, sampleDeadlineMs, maximumDurationMs,
    maximumProcesses, maximumThreadsPerProcess: maximumThreads, maximumReadsPerSample: maximumReads,
    sampleCount: 0, completePssSamples: 0, completeRssSamples: 0, incompleteSamples: 0,
    peakSampledPssBytes: null, peakSampledRssBytes: null, peakPartialPssBytes: null,
    rssFallbackProcessSamples: 0, maximumObservedProcesses: 0,
    maximumSampleDurationMs: 0, maximumSampleGapMs: 0, elapsedMs: 0, incomplete: false, reasons: {},
    rssCaveat: 'Summed RSS double-counts shared pages; it is not interchangeable with PSS.',
    samplingCaveat: 'Sequential reads are not atomic; between-sample peaks and children reparented before discovery can be missed.',
  };
  let stopping = false, finished = false, rootIdentity, activeAbort, pauseTimer, wake, lastSampleStarted;
  const known = new Map();
  const reason = name => { report.reasons[name] = (report.reasons[name] ?? 0) + 1; };
  const same = (a, b) => a && b && a.pid === b.pid && a.started === b.started;
  const live = () => child?.pid && child.exitCode === null && child.signalCode === null;
  const peak = (previous, value) => previous === null ? value : Math.max(previous, value);

  async function sample() {
    const beganSample = performance.now();
    if (lastSampleStarted !== undefined) report.maximumSampleGapMs = Math.max(report.maximumSampleGapMs, beganSample - lastSampleStarted);
    lastSampleStarted = beganSample;
    report.sampleCount += 1;
    let reads = 0, incomplete = false, familyIncomplete = false;
    let pssTotal = 0, rssTotal = 0, measured = 0, pssCount = 0, rssCount = 0;
    activeAbort = new AbortController();
    const abort = activeAbort;
    const timeout = setTimeout(() => abort.abort(), sampleDeadlineMs);
    const miss = name => { incomplete = true; familyIncomplete = true; reason(name); };
    async function read(path) {
      if (abort.signal.aborted || ++reads > maximumReads) throw new Error('sample bound');
      const text = await readFile(path, { encoding: 'utf8', signal: abort.signal });
      if (text.length > 65_536) throw new Error('proc file bound');
      return text;
    }
    async function identity(pid) {
      const text = await read(`/proc/${pid}/stat`);
      // comm may contain spaces or parentheses; fields after its last ')' have
      // stable positions: state(3), ppid(4), starttime(22).
      const end = text.lastIndexOf(')');
      const fields = text.slice(end + 1).trim().split(/\s+/);
      if (end < 0 || Number(text.slice(0, text.indexOf(' '))) !== pid
          || fields.length < 20 || !/^\d+$/.test(fields[19])) throw new Error('proc identity');
      const parent = Number(fields[1]);
      if (!Number.isSafeInteger(parent) || parent < 0) throw new Error('proc parent');
      return { pid, parent, started: fields[19] };
    }
    const kb = (text, name) => {
      const match = text.match(new RegExp(`^${name}:\\s+(\\d+) kB$`, 'm'));
      if (!match) return null;
      const bytes = Number(match[1]) * 1024;
      return Number.isSafeInteger(bytes) && bytes >= 0 ? bytes : null;
    };
    try {
      if (!live()) { stopping = true; return; }
      const currentRoot = await identity(child.pid);
      if (!live() || currentRoot.parent !== process.pid || (rootIdentity && !same(rootIdentity, currentRoot))) {
        miss('root-identity-changed'); stopping = true; return;
      }
      rootIdentity ??= currentRoot;
      known.set(currentRoot.pid, currentRoot);
      const queue = [currentRoot, ...Array.from(known.values()).filter(p => p.pid !== currentRoot.pid)];
      const visited = new Set();
      while (queue.length && !abort.signal.aborted) {
        if (visited.size >= maximumProcesses) { miss('process-limit'); break; }
        const expected = queue.shift();
        if (visited.has(expected.pid)) continue;
        visited.add(expected.pid);
        let current;
        try { current = await identity(expected.pid); }
        catch { known.delete(expected.pid); miss('process-exited-or-unreadable'); continue; }
        if (!same(current, expected)) { known.delete(expected.pid); miss('pid-reuse'); continue; }
        try {
          // Children can be forked by any Chromium thread, not only its leader.
          if (abort.signal.aborted || ++reads > maximumReads) throw new Error('sample bound');
          const threads = (await readdir(`/proc/${current.pid}/task`)).filter(t => /^\d+$/.test(t));
          if (threads.length > maximumThreads) miss('thread-limit');
          const children = new Set();
          for (const tid of threads.slice(0, maximumThreads)) {
            try {
              for (const childPid of (await read(`/proc/${current.pid}/task/${tid}/children`)).trim().split(/\s+/)) {
                if (/^[1-9]\d*$/.test(childPid)) children.add(Number(childPid));
              }
            } catch { miss('children-unreadable'); }
            if (abort.signal.aborted || reads >= maximumReads) break;
          }
          if (!same(current, await identity(current.pid))) { miss('parent-identity-changed'); continue; }
          for (const pid of children) {
            if (!Number.isSafeInteger(pid) || visited.has(pid)) continue;
            if (known.size >= maximumProcesses && !known.has(pid)) { miss('process-limit'); break; }
            try {
              const descendant = await identity(pid);
              if (descendant.parent !== current.pid || BigInt(descendant.started) < BigInt(current.started)
                  || !same(current, await identity(current.pid))) { miss('child-identity-changed'); continue; }
              known.set(pid, descendant); queue.push(descendant);
            } catch { miss('child-exited-or-unreadable'); }
          }
        } catch { miss('discovery-incomplete'); }
        let pss = null, rss = null;
        try {
          const rollup = await read(`/proc/${current.pid}/smaps_rollup`);
          pss = kb(rollup, 'Pss'); rss = kb(rollup, 'Rss');
        } catch { /* Restricted procfs can still expose VmRSS below. */ }
        if (pss === null || rss === null) {
          report.rssFallbackProcessSamples += 1;
          try { rss = kb(await read(`/proc/${current.pid}/status`), 'VmRSS'); }
          catch { /* Count this sample as incomplete; never substitute zero. */ }
        }
        try {
          if (!same(current, await identity(current.pid))) { miss('memory-identity-changed'); continue; }
        } catch { miss('process-exited-during-read'); continue; }
        measured += 1;
        if (pss !== null) { pssTotal += pss; pssCount += 1; }
        if (rss !== null) { rssTotal += rss; rssCount += 1; }
        if (rss === null) miss('memory-measurement-incomplete');
        else if (pss === null) { incomplete = true; reason('pss-unavailable-rss-fallback'); }
      }
      if (abort.signal.aborted || reads >= maximumReads) miss('sample-deadline-or-read-limit');
      report.maximumObservedProcesses = Math.max(report.maximumObservedProcesses, measured);
      if (pssCount) report.peakPartialPssBytes = peak(report.peakPartialPssBytes, pssTotal);
      if (!incomplete && measured > 0 && pssCount === measured) {
        report.completePssSamples += 1;
        report.peakSampledPssBytes = peak(report.peakSampledPssBytes, pssTotal);
      }
      if (measured > 0 && rssCount === measured && !familyIncomplete) {
        report.completeRssSamples += 1;
        report.peakSampledRssBytes = peak(report.peakSampledRssBytes, rssTotal);
      }
    } catch { miss(abort.signal.aborted ? 'sample-deadline' : 'sample-unavailable'); }
    finally {
      clearTimeout(timeout); activeAbort = undefined;
      report.maximumSampleDurationMs = Math.max(report.maximumSampleDurationMs, performance.now() - beganSample);
      if (!measured) miss('no-process-measurement');
      if (incomplete) { report.incompleteSamples += 1; report.incomplete = true; }
    }
  }

  const done = (async () => {
    if (process.platform !== 'linux' || !child?.pid) { report.incomplete = true; reason('linux-procfs-unavailable'); return; }
    while (!stopping && live()) {
      if (performance.now() - began >= maximumDurationMs) { report.incomplete = true; reason('sampler-duration-limit'); break; }
      const started = performance.now();
      await sample();
      if (stopping || !live()) break;
      await new Promise(resolve => {
        wake = resolve;
        pauseTimer = setTimeout(resolve, Math.max(1, intervalMs - (performance.now() - started)));
      });
      clearTimeout(pauseTimer); wake = undefined;
    }
  })().catch(() => { report.incomplete = true; reason('sampler-unavailable'); });
  return {
    report,
    async stop() {
      if (finished) return report;
      stopping = true; activeAbort?.abort(); clearTimeout(pauseTimer); wake?.();
      await done;
      if (finished) return report;
      finished = true;
      known.clear(); report.elapsedMs = performance.now() - began;
      if (!report.completePssSamples) report.incomplete = true;
      return report;
    },
  };
}

function failFixture(error) { fixtureWaiting?.reject(error); fixtureWaiting = undefined; clearTimeout(fixtureTimer); }
function publicCommand(value) {
  const exact = (v, keys) => v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).sort().join(',') === [...keys].sort().join(',');
  if (accountingMode === 'account-state-v2') {
    const key = k => exact(k, ['accountKey','secretHash']) && /^[0-9a-f]{128}$/.test(k.accountKey) && /^[0-9a-f]{64}$/.test(k.secretHash);
    if (value?.command === 'enroll') return exact(value, ['command','keys','peerExpires']) && value.keys?.length === 2 && value.keys.every(key) && value.peerExpires === (accountScenario === 'answer' ? 200 : 10000);
    if (value?.command === 'verify') return exact(value, ['command','delegations']) && value.delegations?.length === 2;
    if (value?.command === 'answer') return exact(value, ['command']) && accountScenario === 'answer';
    if (value?.command === 'close') return exact(value, ['command','now']) && accountScenario === 'close' && value.now === 100;
    if (value?.command === 'advance') return exact(value, ['command','now']) && [300,600].includes(value.now);
    if (value?.command === 'prepareGate') return exact(value, ['command']);
    if (value?.command === 'authorizeIncoming') return exact(value, ['command','outgoingPresentation']);
    if (value?.command === 'bindGate') return exact(value, ['command','outgoingPresentation','incomingPresentation']);
    if (value?.command === 'ack') return exact(value, ['command','answer']) && accountScenario === 'answer';
    if (['verifyReceipt','verifyHistoricalReceipt'].includes(value?.command)) return exact(value, ['command','receipt','now']) && [100,300].includes(value.now);
    if (['verifyAcknowledgment','verifyHistoricalAcknowledgment'].includes(value?.command)) return exact(value, ['command','acknowledgment','now']) && [100,300].includes(value.now);
    if (value?.command === 'authorize') return exact(value, ['command','owner','requestId','circuitDigest','verifyingKeyDigest','statementDigest','proofDigest','issuedAt','expiresAt'])
      && [0,1].includes(value.owner) && [100,300,600].includes(value.issuedAt) && Number.isSafeInteger(value.expiresAt)
      && value.expiresAt > value.issuedAt && value.expiresAt <= 10000
      && ['requestId','circuitDigest','verifyingKeyDigest','statementDigest','proofDigest'].every(k => /^[0-9a-f]{64}$/.test(value[k]));
    return false;
  }
  if (value?.hashScheme !== SHA_SCHEME && value?.hashScheme !== POSEIDON_SCHEME) return false;
  if (value?.action === 'enroll') return value.hashScheme === hashScheme && exact(value, ['action', 'hashScheme', 'keys']) && value.keys?.length === 4 && value.keys.every(k =>
    exact(k, ['accountKey', 'secretHash']) && /^[0-9a-f]{128}$/.test(k.accountKey) && /^[0-9a-f]{64}$/.test(k.secretHash));
  if (value?.action !== 'verify' || !exact(value, ['action', 'hashScheme', 'entries']) || value.entries?.length !== 4) return false;
  return value.entries.every(e => exact(e, ['admission', 'authorization', 'hashScheme', 'accountKey', 'secretHash', 'issuedAt', 'expiresAt', 'signature'])
    && exact(e.admission, ['version', 'issuerKeyId', 'communityId', 'memberId', 'chatPublicKey', 'policyDigest', 'issuedAt', 'expiresAt', 'signature'])
    && exact(e.authorization, ['version', 'communityId', 'memberId', 'rootPublicKey', 'devicePublicKey', 'issuedAt', 'expiresAt', 'signature']));
}
async function callFixture(value) {
  if (!publicCommand(value) || fixtureWaiting || ++evidence.fixtureRequests > (accountingMode === 'account-state-v2' ? 48 : 16)) throw new Error('Public fixture request bound');
  const result = new Promise((resolve, reject) => { fixtureWaiting = { resolve, reject }; });
  fixtureTimer = setTimeout(() => failFixture(new Error('Native cmsg fixture deadline')),
    ['authorizeIncoming','bindGate'].includes(value.command) ? 270_000 : 15_000);
  fixture.stdin.write(JSON.stringify(value) + '\n');
  const response = await result;
  if ((value.action === 'enroll' || value.command === 'enroll') && response.ok) {
    if (enrolled) throw new Error('Enrollment genesis already created');
    enrolled = response.value;
    if (ledgerBridge) await ledgerBridge.enroll(enrolled);
  }
  return response;
}
const server = createServer(async (request, response) => {
  try {
    response.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    response.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Content-Security-Policy', "default-src 'none'; connect-src 'self' blob:; worker-src 'self' blob:; script-src 'self' 'wasm-unsafe-eval'; object-src 'none'");
    const pathname = new URL(request.url, 'http://localhost').pathname;
    if (pathname === '/test-config.json' && accountingMode === 'account-state-v2') {
      if (request.method !== 'GET') { response.writeHead(405).end(); return; }
      response.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ accountScenario })); return;
    }
    if (pathname === '/fixture' || (pathname === '/account-ledger' && ledgerBridge)) {
      if (request.method !== 'POST' || request.headers.origin !== origin || !request.headers['content-type']?.startsWith('application/json')) { response.writeHead(400).end(); return; }
      const chunks = []; let size = 0;
      for await (const chunk of request) { size += chunk.length; if (size > 262144) { response.writeHead(413).end(); return; } chunks.push(chunk); }
      const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      const result = pathname === '/fixture' ? await callFixture(input) : await ledgerBridge.call(input);
      response.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify(result)); return;
    }
    if (request.method !== 'GET') { response.writeHead(405).end(); return; }
    const file = resolve(root, '.' + (pathname === '/' ? '/index.html' : pathname));
    if (!file.startsWith(root + sep)) { response.writeHead(404).end(); return; }
    const mime = { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.json': 'application/json', '.wasm': 'application/wasm', '.bin': 'application/octet-stream', '.dat': 'application/octet-stream' };
    if (!mime[extname(file)]) { response.writeHead(404).end(); return; }
    const data = await readFile(file); evidence.loadedBytes += data.length;
    response.writeHead(200, { 'Content-Type': mime[extname(file)] }).end(data);
  } catch { if (!response.headersSent) response.writeHead(500); response.end(); }
});
server.requestTimeout = 280_000; server.headersTimeout = 20_000;
const command = (method, params = {}) => {
  const id = nextId++; const result = new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
  socket.send(JSON.stringify({ id, method, params }));
  if (!startupOnly) return result;
  let timer;
  return Promise.race([result, new Promise((_, reject) => {
    timer = setTimeout(() => { pending.delete(id); reject(new Error('Browser startup command deadline: ' + method)); }, 10_000);
  })]).finally(() => clearTimeout(timer));
};
async function stop(child) {
  if (!child) return;
  let force, bound;
  if (child?.pid && child.exitCode === null && child.signalCode === null) {
    child.kill('SIGTERM'); force = setTimeout(() => child.kill('SIGKILL'), 3000);
  }
  // Even a child with exitCode set can still own its profile until 'close'.
  try { await Promise.race([closed.get(child), new Promise((_, reject) => { bound = setTimeout(() => reject(new Error('Child close deadline')), 10_000); })]); }
  finally { clearTimeout(force); clearTimeout(bound); }
}
try {
  server.listen(0, '127.0.0.1'); await once(server, 'listening'); origin = `http://127.0.0.1:${server.address().port}`;
  if (!startupOnly) {
  let fixtureEnvironment = process.env;
  if (accountingMode === 'account-state-v2') {
    if (!process.env.ACCOUNTING_ARTIFACT_DIR) throw new Error('Owned account artifact directory required');
    const { createLedgerBridge } = await import('./peer-reservation/ledger-bridge.mjs');
    ledgerBridge = await createLedgerBridge({ directory: await mkdtemp(join(resolve(process.env.ACCOUNTING_ARTIFACT_DIR), 'live-ledger-')),
      manifestPath: resolve('public/manifest.json'), binary: process.env.ACCOUNTING_LEDGER_FIXTURE });
    evidence.liveLedger = ledgerBridge.evidence;
    fixtureEnvironment = { ...process.env, CMSG_PEER_VERIFIER_NODE: process.execPath,
      CMSG_PEER_VERIFIER_SCRIPT: ledgerBridge.paths.peerVerifier, CMSG_PEER_VERIFIER_MANIFEST: ledgerBridge.paths.manifest,
      CMSG_PEER_VERIFIER_ENROLLMENT: ledgerBridge.paths.enrollment, CMSG_PEER_VERIFIER_LEDGER: ledgerBridge.paths.ledger };
  }
  fixture = captureClose(spawn(fixtureBinary, accountingMode === 'account-state-v2' ? ['--serve'] : [], { stdio: ['pipe', 'pipe', 'pipe'], env: fixtureEnvironment }));
  fixture.on('error', error => failFixture(error)); fixture.stdin.on('error', error => failFixture(error));
  fixture.stderr.on('data', chunk => { fixtureStderr = (fixtureStderr + chunk).slice(-4096); });
  fixture.stdout.on('data', chunk => {
    fixtureOutput += chunk;
    if (fixtureOutput.length > 65536) { failFixture(new Error('Fixture output bound')); return; }
    const newline = fixtureOutput.indexOf('\n'); if (newline < 0) return;
    try {
      let reply = JSON.parse(fixtureOutput.slice(0, newline)); fixtureOutput = fixtureOutput.slice(newline + 1);
      if (accountingMode === 'account-state-v2') {
        if (!reply || Object.keys(reply).length !== 1) throw new Error('Unexpected cmsg fixture response');
        if (reply.ok && typeof reply.ok === 'object') reply = { ok: true, value: reply.ok };
        else if (typeof reply.error === 'string') reply = { ok: false, error: reply.error };
        else throw new Error('Invalid cmsg fixture response');
      }
      if (!fixtureWaiting || typeof reply.ok !== 'boolean') throw new Error('Unexpected fixture reply');
      clearTimeout(fixtureTimer); const waiting = fixtureWaiting; fixtureWaiting = undefined; waiting.resolve(reply);
    } catch (error) { failFixture(error); }
  });
  }
  browser = captureClose(spawn(binary, ['--headless', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--disable-background-networking',
    '--disable-component-update', '--no-first-run', '--no-default-browser-check', '--disable-extensions',
    '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'],
  { stdio: ['ignore', 'ignore', 'pipe'] }));
  let launchError; browser.on('error', error => { launchError = error; });
  browser.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(-8000); });
  if (!startupOnly) {
    browserMemory = sampleBrowserMemory(browser);
    evidence.browserProcessMemory = browserMemory.report;
  }
  let port;
  for (let attempt = 0; attempt < 300; attempt++) {
    if (launchError) throw launchError;
    if (browser.exitCode !== null) throw new Error('Browser exited during startup');
    try { port = Number((await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]); break; }
    catch { await new Promise(resolve => setTimeout(resolve, 100)); }
  }
  if (!port) throw new Error('Browser startup deadline');
  const startupRequestOptions = () => startupOnly ? { signal: AbortSignal.timeout(5000) } : undefined;
  evidence.browser = (await (await fetch(`http://127.0.0.1:${port}/json/version`, startupRequestOptions())).json()).Browser;
  const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`, startupRequestOptions())).json();
  socket = new WebSocket(pages.find(p => p.type === 'page').webSocketDebuggerUrl); await once(socket, 'open', startupRequestOptions());
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.id) {
      const waiting = pending.get(message.id); if (!waiting) return; pending.delete(message.id);
      if (message.error) waiting.reject(new Error(JSON.stringify(message.error))); else waiting.resolve(message.result);
    } else if (message.method === 'Page.lifecycleEvent' && message.params.name === 'load') {
      loaded.add(message.params.loaderId);
    } else if (message.method === 'Fetch.requestPaused') {
      const { requestId, request } = message.params;
      if (startupOnly && request.url === origin + '/manifest.json' && request.method === 'GET') {
        // Hold the first application fetch: the entry can initialize its globals,
        // but cannot load circuits, start a prover or contact a fixture.
        evidence.heldManifestRequests += 1;
      } else if (request.url.startsWith(origin + '/') || request.url.startsWith('blob:' + origin + '/')) command('Fetch.continueRequest', { requestId }).catch(() => {});
      else { evidence.forbiddenRequests.push(request.url); command('Fetch.failRequest', { requestId, errorReason: 'BlockedByClient' }).catch(() => {}); }
    } else if (message.method === 'Runtime.exceptionThrown' && evidence.browserErrors.length < 16) {
      const details = message.params.exceptionDetails;
      // CDP's text is commonly just "Uncaught". Preserve the bounded exception
      // description/stack so module startup failures can actually be diagnosed.
      evidence.browserErrors.push(String(details.exception?.description ?? details.text).slice(0, 8192));
    }
  });
  await command('Runtime.enable'); await command('Page.enable');
  await command('Page.setLifecycleEventsEnabled', { enabled: true });
  await command('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
  const navigation = await command('Page.navigate', { url: origin });
  for (let attempt = 0; attempt < 300 && !loaded.has(navigation.loaderId); attempt++) {
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  if (!loaded.has(navigation.loaderId)) throw new Error('Browser navigation deadline');
  // The entry module installs this promise synchronously before page load.
  // A missing promise means startup failed, not that proof generation is slow.
  const startup = await command('Runtime.evaluate', { expression: 'Boolean(window.accountingDone && typeof window.accountingDone.then === "function")', returnByValue: true });
  if (startup.exceptionDetails || startup.result?.value !== true) {
    throw new Error('Browser application did not initialize: ' + (evidence.browserErrors[0] ?? 'no accountingDone promise'));
  }
  if (startupOnly) {
    for (let attempt = 0; attempt < 20 && !evidence.heldManifestRequests; attempt++) {
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    const entry = await command('Runtime.evaluate', { expression: '({ isolated: crossOriginIsolated, progress: window.accountingProgress })', returnByValue: true });
    evidence.entry = entry.result?.value;
    if (entry.exceptionDetails || !evidence.entry?.isolated || !evidence.entry.progress
        || evidence.heldManifestRequests !== 1 || evidence.browserErrors.length || evidence.forbiddenRequests.length) {
      throw new Error('Browser entry startup contract incomplete');
    }
  } else {
  const running = command('Runtime.evaluate', { expression: 'window.accountingDone', awaitPromise: true, returnByValue: true });
  const result = await Promise.race([running, new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('Bounded browser proof/ledger deadline')), browserProofDeadlineMs); })]);
  clearTimeout(deadline);
  if (result.exceptionDetails || !result.result?.value) throw new Error('No browser result');
  evidence.contract = result.result.value;
  const expectedProofs = accountingMode === 'account-state-v2' ? (accountScenario === 'answer' ? 10 : 12) : 2;
  if (!evidence.contract.ok || evidence.contract.proofs?.length !== expectedProofs || evidence.contract.checks.length < 30) throw new Error('Browser proof contract incomplete');
  if (evidence.forbiddenRequests.length) throw new Error('Unlisted browser network traffic');
  await browserMemory.stop();
  socket.close(); await stop(browser);
  // A separate runtime verifies local pinned VK + public inputs, never witnesses.
  const { verifyResults } = await import('./verify.mjs');
  evidence.independent = await verifyResults(evidence.contract, enrolled);
  if (accountingMode === 'account-state-v2') {
    if (evidence.contract.peerReservations?.length !== 2 || evidence.liveLedger.applies !== expectedProofs) throw new Error('Actual peer/ledger bridge contract incomplete');
    const { runRustAccountLedgerContract } = await import('./account-state/ledger-contract.mjs');
    evidence.ledger = await runRustAccountLedgerContract(evidence.contract, enrolled);
  }
  }
  evidence.ok = true;
} catch (error) {
  evidence.error = String(error); evidence.stderr = stderr; evidence.fixtureStderr = fixtureStderr;
  if (socket?.readyState === WebSocket.OPEN) {
    try {
      const progress = await Promise.race([command('Runtime.evaluate', { expression: 'window.accountingProgress', returnByValue: true }),
        new Promise(resolve => setTimeout(() => resolve(undefined), 1000))]);
      evidence.partial = progress?.result?.value;
    } catch { /* Failure evidence still retained if renderer crashed. */ }
  }
} finally {
  clearTimeout(deadline); failFixture(new Error('Fixture closed')); socket?.close();
  const cleanupErrors = [];
  try { await ledgerBridge?.close(); }
  catch { cleanupErrors.push('Live ledger child cleanup failed'); }
  try { await browserMemory?.stop(); }
  catch { cleanupErrors.push('Browser memory sampler cleanup failed'); }
  for (const child of [browser, fixture]) { try { await stop(child); } catch (error) { cleanupErrors.push(String(error)); } }
  try { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
  catch (error) { cleanupErrors.push(String(error)); }
  try { await rm(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); }
  catch (error) { cleanupErrors.push(String(error)); }
  if (cleanupErrors.length) { evidence.ok = false; evidence.cleanupErrors = cleanupErrors; }
  await writeFile(evidencePath, JSON.stringify(evidence, null, 2) + '\n');
}
process.stdout.write(JSON.stringify({ ok: evidence.ok, checks: evidence.contract?.checks.length, proofBytes: evidence.contract?.proofs.map(p => p.proofBytes), evidence: evidencePath, error: evidence.error }) + '\n');
if (!evidence.ok) process.exitCode = 1;
