// Disposable official sqld; this proxy forwards bytes unchanged and only drops
// one successful COMMIT reply to exercise uncertain network outcomes.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createServer, request as httpRequest } from 'node:http';
import { createServer as createTcpServer } from 'node:net';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';

assert.equal(process.env.CI, 'true');
const artifacts = resolve(process.env.ARTIFACT_ROOT);
const work = resolve(process.env.TURSO_CONTRACT_WORK);
const executable = resolve(process.env.SQLD_BINARY);
const evidence = { ok: false, sdk: 'libsql remote+tls', server: 'libsql-server-v0.24.32',
  serverSource: '40c272de85ee4e62d722c5ccae5da2e76b4253a1',
  archiveSha256: '71720fc8648c19efef416efebd47145ef59b62e198770533530a858e1336879f',
  scope: 'official SQL transport and durable transactions; account proof verdicts remain storage-only fixtures' };
const children = new Set();
let proxy, dropped = 0;
const waiting = new Set();
async function port() {
  const socket = createTcpServer();
  await new Promise(resolveListen => socket.listen(0, '127.0.0.1', resolveListen));
  const port = socket.address().port;
  await new Promise(resolveClose => socket.close(resolveClose));
  return port;
}
function run(command, args, env, log) {
  const child = spawn(command, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
  children.add(child);
  let output = '';
  for (const stream of [child.stdout, child.stderr]) stream.on('data', bytes => {
    if (output.length < 4 * 1024 * 1024) output += bytes;
    if (!log) process.stdout.write(bytes);
  });
  const done = new Promise((accept, reject) => {
    child.on('error', reject);
    child.on('close', async code => {
      children.delete(child);
      if (log) await writeFile(log, output);
      accept(code);
    });
  });
  return { child, done };
}
try {
  await mkdir(work, { recursive: true });
  evidence.binarySha256 = createHash('sha256').update(await readFile(executable)).digest('hex');
  const actualPort = await port(), url = `http://127.0.0.1:${actualPort}`;
  const sqld = run(executable, ['--db-path', join(work, 'database'), '--http-listen-addr', `127.0.0.1:${actualPort}`],
    { ...process.env, RUST_LOG: 'warn' }, join(artifacts, 'sqld.log'));
  let ready = false;
  for (let n = 0; n < 100; n++) {
    if (sqld.child.exitCode !== null) throw new Error('Official sqld stopped before readiness');
    try { const response = await fetch(url + '/health', { signal: AbortSignal.timeout(300) }); ready = response.ok; } catch {}
    if (ready) break;
    await new Promise(resolveWait => setTimeout(resolveWait, 100));
  }
  assert(ready, 'Official sqld readiness');
  proxy = createServer(async (request, response) => {
    const chunks = []; let length = 0;
    for await (const chunk of request) { length += chunk.length; assert(length <= 1024 * 1024); chunks.push(chunk); }
    const bytes = Buffer.concat(chunks);
    const requestBody = JSON.parse(bytes);
    const commit = requestBody.requests?.some(item => item.type === 'execute' && item.stmt.sql.trim() === 'COMMIT');
    const upstream = httpRequest(url + request.url, { method: request.method, headers: request.headers }, returned => {
      const output = [];
      returned.on('data', chunk => output.push(chunk));
      returned.on('end', () => {
        const body = Buffer.concat(output);
        if (commit && dropped === 0 && returned.statusCode === 200) {
          const result = JSON.parse(body);
          assert(result.results.every(value => value.type === 'ok'), 'Actual server COMMIT must succeed before fault');
          dropped++;
          waiting.add(response);
          response.on('close', () => waiting.delete(response));
          return;
        }
        response.writeHead(returned.statusCode, returned.headers); response.end(body);
      });
    });
    upstream.on('error', () => { response.statusCode = 503; response.end(); });
    upstream.end(bytes);
  });
  await new Promise(resolveListen => proxy.listen(0, '127.0.0.1', resolveListen));
  const env = { ...process.env, CFRM_TURSO_CONTRACT_URL: url,
    CFRM_TURSO_FAULT_URL: `http://127.0.0.1:${proxy.address().port}` };
  const contract = run('cargo', ['test', '--locked', '--features', 'turso,permit-issuer',
    '--lib', '--test', 'accounting_ledger', '--test', 'key_access', 'remote_', '--', '--ignored', '--test-threads=1'], env);
  assert.equal(await contract.done, 0, 'Remote durable contracts');
  assert.equal(dropped, 1, 'One actual committed response was withheld');
  evidence.lostCommittedResponses = dropped;
  evidence.ok = true;
} catch (error) { evidence.error = String(error.stack ?? error); process.exitCode = 1; }
finally {
  for (const response of waiting) response.destroy();
  if (proxy) { proxy.closeAllConnections(); await new Promise(resolveClose => proxy.close(resolveClose)); }
  for (const child of children) child.kill('SIGTERM');
  await new Promise(resolveWait => setTimeout(resolveWait, 500));
  for (const child of children) child.kill('SIGKILL');
  await writeFile(join(artifacts, 'turso-contract.json'), JSON.stringify(evidence, null, 2) + '\n');
}
