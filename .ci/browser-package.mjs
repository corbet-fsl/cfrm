// Pack existing bindings and run the existing browser contract on the archive.
// No dependency install, code generation, registry publication or extra suite.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

if (process.argv.length !== 3 || !/^[0-9a-f]{40}$/.test(process.env.CI_COMMIT_SHA ?? '')) {
  throw new Error('Owned artifact directory and exact CI_COMMIT_SHA required');
}
for (const key of ['BROWSER_BIN', 'BROWSER_EVIDENCE', 'BROWSER_FIXTURE']) {
  if (!process.env[key]) throw new Error(key + ' required for the packed browser contract');
}
const repository = fileURLToPath(new URL('../', import.meta.url));
const artifacts = resolve(process.argv[2]);
await mkdir(artifacts, { recursive: true });
const scratch = await mkdtemp(join(tmpdir(), 'cfrm-browser-package-'));
const stage = join(scratch, 'stage'), consumer = join(scratch, 'consumer');
const generated = ['pkg/cfrm.js', 'pkg/cfrm.d.ts', 'pkg/cfrm_bg.wasm', 'pkg/cfrm_bg.wasm.d.ts'];
const selected = [...generated, 'README.md', 'LICENSE.md'];
const exports = { '.': { types: './pkg/cfrm.d.ts', import: './pkg/cfrm.js' }, './wasm': './pkg/cfrm_bg.wasm' };
const evidence = { source: process.env.CI_COMMIT_SHA, runtime: process.version, ok: false,
  scope: 'Packed roster/blind-permit bindings; existing browser contract on extracted assets' };
const execute = promisify(execFile);
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
async function run(label, binary, args, cwd, env = process.env, timeout = 120_000) {
  let output, failure;
  try { output = await execute(binary, args, { cwd, env, timeout, killSignal: 'SIGTERM', maxBuffer: 1024 * 1024 }); }
  catch (error) { output = error; failure = error; }
  await writeFile(join(artifacts, label + '.stdout.log'), String(output.stdout ?? ''));
  await writeFile(join(artifacts, label + '.stderr.log'), String(output.stderr ?? ''));
  if (label === 'browser-harness') process.stdout.write(String(output.stdout ?? ''));
  if (failure) throw new Error(label + ' failed; see retained stdout/stderr logs', { cause: failure });
  return output.stdout;
}
try {
  await mkdir(stage); await mkdir(consumer);
  const inputs = new Map();
  for (const path of ['package.json', ...selected]) {
    const source = path === 'LICENSE.md' ? join(repository, path)
      : join(repository, 'browser', path === 'README.md' ? 'CONSUMER.md' : path);
    assert((await lstat(source)).isFile(), 'Regular package input required: ' + path);
    const bytes = await readFile(source);
    assert(bytes.length, 'Empty package input: ' + path);
    inputs.set(path, bytes);
    await mkdir(dirname(join(stage, path)), { recursive: true });
    await writeFile(join(stage, path), bytes);
  }
  const manifest = JSON.parse(inputs.get('package.json'));
  assert.equal(manifest.name, 'cfrm-browser'); assert.equal(manifest.version, '0.1.0-alpha.0');
  assert.equal(manifest.private, true); assert.equal(manifest.type, 'module');
  assert.deepEqual(manifest.files, selected); assert.deepEqual(manifest.exports, exports);
  for (const key of ['dependencies', 'optionalDependencies', 'peerDependencies', 'scripts']) {
    assert(!manifest[key] || !Object.keys(manifest[key]).length, 'Bindings package must have no ' + key);
  }
  const packed = JSON.parse(await run('npm-pack', 'npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', artifacts],
    stage, { ...process.env, npm_config_update_notifier: 'false' }));
  assert.equal(packed.length, 1, 'Exactly one browser package required');
  const pack = packed[0];
  assert.equal(pack.name, manifest.name); assert.equal(pack.version, manifest.version);
  assert.equal(pack.filename, basename(pack.filename));
  assert.deepEqual(pack.files.map(file => file.path).sort(), [...inputs.keys()].sort(), 'Only selected consumer files may ship');
  const archivePath = join(artifacts, pack.filename), archive = await readFile(archivePath);
  const integrity = 'sha512-' + createHash('sha512').update(archive).digest('base64');
  assert.equal(pack.integrity, integrity, 'Packed archive integrity');
  await run('unpack', 'tar', ['--extract', '--file', archivePath, '--directory', consumer, '--no-same-owner'], scratch, process.env, 30_000);
  const installed = join(consumer, 'package');
  const files = {};
  for (const [path, expected] of inputs) {
    assert((await lstat(join(installed, path))).isFile(), 'Regular extracted file required: ' + path);
    const actual = await readFile(join(installed, path));
    assert(actual.equals(expected), 'Packed file must match source, including license: ' + path);
    files[path] = sha256(actual);
  }
  for (const target of [exports['.'].types, exports['.'].import, exports['./wasm']]) {
    assert(Object.hasOwn(files, target.slice(2)), 'Missing package export: ' + target);
  }
  const glue = (await readFile(join(installed, 'pkg/cfrm.js'))).toString();
  assert(!/^\s*import\s+(?!\.)/m.test(glue) && !/\bimport\s*\(/.test(glue)
    && !/\bexport\s+[^;]*\bfrom\s*['"]/.test(glue), 'Generated glue must have no module dependencies');
  const assetUrls = [...glue.matchAll(/new\s+URL\s*\(\s*['"]([^'"]+)['"]\s*,\s*import\.meta\.url\s*\)/g)].map(match => match[1]);
  assert.deepEqual(assetUrls, ['cfrm_bg.wasm'], 'Generated glue must resolve only its packaged sibling Wasm');
  assert.equal(inputs.get('pkg/cfrm_bg.wasm').subarray(0, 8).toString('hex'), '0061736d01000000', 'Expected generated Wasm module');
  evidence.package = { name: pack.name, version: pack.version, archive: pack.filename,
    sha256: sha256(archive), integrity, exports, files };
  await run('browser-harness', 'timeout', ['--kill-after=15', '300', process.execPath, join(repository, '.ci/browser-check.mjs')], repository,
    { ...process.env, BROWSER_RUNTIME_ROOT: join(installed, 'pkg') }, 330_000);
  const browser = JSON.parse(await readFile(process.env.BROWSER_EVIDENCE, 'utf8'));
  assert.equal(browser.source, evidence.source); assert.equal(browser.contract?.ok, true);
  assert.equal(browser.runtimeAssets?.source, 'override');
  assert.deepEqual(browser.runtimeAssets.files, Object.fromEntries(['cfrm.js', 'cfrm_bg.wasm']
    .map(path => [path, files['pkg/' + path]])), 'Browser must load the extracted package assets');
  evidence.browserContract = { evidence: process.env.BROWSER_EVIDENCE, count: browser.contract.count, browser: browser.browser };
  evidence.ok = true;
} catch (error) { evidence.error = String(error.stack ?? error); }
finally {
  try { await rm(scratch, { recursive: true, force: true }); }
  catch (error) { evidence.ok = false; evidence.cleanupError = String(error); }
  await writeFile(join(artifacts, 'browser-package-evidence.json'), JSON.stringify(evidence, null, 2) + '\n');
}
process.stdout.write(JSON.stringify({ ok: evidence.ok, evidence: join(artifacts, 'browser-package-evidence.json'), error: evidence.error }) + '\n');
if (!evidence.ok) process.exitCode = 1;
