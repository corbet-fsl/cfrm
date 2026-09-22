// Verify the published JavaScript shape from a clean, locked npm consumer on CI.
// Import the real SDK dependencies without constructing a prover or verifier.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

if (process.argv.length !== 3) throw new Error('Owned evidence directory required');
const repository = fileURLToPath(new URL('../', import.meta.url));
const artifacts = resolve(process.argv[2]);
await mkdir(artifacts, { recursive: true });
const scratch = await mkdtemp(join(tmpdir(), 'cfrm-package-consumer-'));
const packDirectory = join(scratch, 'pack'), consumer = join(scratch, 'consumer');
const evidence = { source: process.env.CI_COMMIT_SHA, runtime: process.version, ok: false,
  scope: 'Packed exports and real SDK import closure; proving is untested' };
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const execute = promisify(execFile);
async function run(label, binary, args, cwd, timeout = 120_000) {
  let output, failure;
  try {
    output = await execute(binary, args, { cwd, timeout, killSignal: 'SIGKILL', maxBuffer: 1024 * 1024,
      env: { ...process.env, npm_config_update_notifier: 'false' } });
  } catch (error) { output = error; failure = error; }
  await writeFile(join(artifacts, label + '.stdout.log'), String(output.stdout ?? ''));
  await writeFile(join(artifacts, label + '.stderr.log'), String(output.stderr ?? ''));
  if (failure) throw new Error(label + ' failed (' + (failure.signal ?? failure.code ?? 'subprocess error')
    + '); see retained stdout/stderr logs', { cause: failure });
  return output.stdout;
}
try {
  await mkdir(packDirectory); await mkdir(consumer);
  const manifest = JSON.parse(await readFile(join(repository, 'package.json'), 'utf8'));
  const sourceLockBytes = await readFile(join(repository, 'package-lock.json'));
  const sourceLock = JSON.parse(sourceLockBytes);
  assert.equal(sourceLock.lockfileVersion, 3, 'Source dependency lock must use npm lockfile v3');
  assert.equal(sourceLock.name, manifest.name);
  assert.equal(sourceLock.version, manifest.version);
  assert.deepEqual(sourceLock.packages[''].dependencies, manifest.dependencies, 'Manifest and source dependency snapshot must agree');
  assert.deepEqual(sourceLock.packages[''].engines, manifest.engines);
  evidence.sourceLockSha256 = sha256(sourceLockBytes);
  await writeFile(join(artifacts, 'source-package-lock.json'), sourceLockBytes);
  evidence.npm = (await run('npm-version', 'npm', ['--version'], repository)).trim();
  const packed = JSON.parse(await run('npm-pack', 'npm', ['pack', '--ignore-scripts', '--json',
    '--pack-destination', packDirectory], repository));
  assert.equal(packed.length, 1, 'Pack exactly the requested package');
  const pack = packed[0];
  assert.equal(pack.name, manifest.name); assert.equal(pack.version, manifest.version);
  assert.equal(pack.filename, basename(pack.filename), 'Pack filename must stay inside owned scratch');
  const files = new Set(pack.files.map(file => file.path));
  assert.equal(files.size, pack.files.length, 'No duplicate packed files');
  for (const file of files) {
    assert(!/(^|\/)(?:experiments?|tests?|node_modules)(\/|$)/.test(file), 'Unshipped directory in package: ' + file);
    assert(!/\.(?:rs|toml)$/.test(file) && !file.endsWith('real-proof-check.mjs'), 'CI or native source in package: ' + file);
    assert(/^(?:package\.json|LICENSE\.md|README\.md|src\/[^/]+\.js|browser\/profiles\/[^/]+\.js|runtime\/accounting\/[^/]+\.mjs|runtime\/accounting\/README\.md)$/.test(file),
      'Unexpected packed path: ' + file);
  }
  assert(files.has('LICENSE.md'), 'The packed accounting runtime must include its license');
  assert(files.has('runtime/accounting/index.mjs'), 'The accounting runtime must be packaged');
  const exports = Object.entries(manifest.exports).map(([specifier, target]) => {
    assert(specifier.startsWith('./') && typeof target === 'string' && target.startsWith('./'), 'Explicit package export required');
    assert(files.has(target.slice(2)), 'Export target missing from archive: ' + specifier);
    return manifest.name + specifier.slice(1);
  });
  assert(exports.length > 0, 'The package must expose consumer modules');
  const archivePath = join(packDirectory, pack.filename);
  const archive = await readFile(archivePath);
  const integrity = 'sha512-' + createHash('sha512').update(archive).digest('base64');
  assert.equal(pack.integrity, integrity, 'Verify packed archive integrity before installing');
  evidence.package = { name: pack.name, version: pack.version, archive: pack.filename,
    sha256: sha256(archive), integrity, files: [...files].sort() };
  await copyFile(archivePath, join(artifacts, pack.filename));

  const localArchive = 'file:../pack/' + pack.filename;
  const consumerManifest = { name: 'cfrm-packed-consumer-check', version: '0.0.0', private: true,
    type: 'module', engines: manifest.engines, dependencies: { [manifest.name]: localArchive } };
  // Keep every resolved transitive entry byte-for-byte as a JSON value. Only the
  // consumer root and its additional local cfrm tarball differ from the snapshot.
  const packages = Object.fromEntries(Object.entries(sourceLock.packages).filter(([path]) => path !== ''));
  assert(!Object.hasOwn(packages, 'node_modules/' + manifest.name), 'The source snapshot cannot already contain cfrm');
  for (const path of Object.keys(packages)) assert(path.startsWith('node_modules/'), 'Unexpected source lock package location');
  const consumerLock = { name: consumerManifest.name, version: consumerManifest.version,
    lockfileVersion: 3, requires: true, packages: {
      '': { name: consumerManifest.name, version: consumerManifest.version,
        engines: consumerManifest.engines, dependencies: consumerManifest.dependencies },
      ...packages,
      ['node_modules/' + manifest.name]: { version: manifest.version, resolved: localArchive, integrity,
        license: manifest.license, dependencies: manifest.dependencies, engines: manifest.engines },
    } };
  const consumerLockBytes = Buffer.from(JSON.stringify(consumerLock, null, 2) + '\n');
  await writeFile(join(consumer, 'package.json'), JSON.stringify(consumerManifest, null, 2) + '\n');
  await writeFile(join(consumer, 'package-lock.json'), consumerLockBytes);
  await writeFile(join(artifacts, 'consumer-package-lock.json'), consumerLockBytes);
  await run('npm-ci', 'npm', ['ci', '--ignore-scripts', '--no-audit', '--no-fund'], consumer, 600_000);
  assert((await readFile(join(consumer, 'package-lock.json'))).equals(consumerLockBytes), 'Consumer install must preserve the exact lock');
  assert((await readFile(join(repository, 'package-lock.json'))).equals(sourceLockBytes), 'Consumer check must preserve the source lock');
  const installedRoot = join(consumer, 'node_modules', manifest.name);
  assert((await readFile(join(installedRoot, 'LICENSE.md'))).equals(await readFile(join(repository, 'LICENSE.md'))), 'Installed license must match the source grant');
  const installedManifest = JSON.parse(await readFile(join(installedRoot, 'package.json'), 'utf8'));
  assert.deepEqual(installedManifest.exports, manifest.exports);
  assert.deepEqual(installedManifest.dependencies, manifest.dependencies);
  evidence.consumerLockSha256 = sha256(consumerLockBytes);
  evidence.lockPreserved = true;

  const probe = `
import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
const result = { exports: [] };
const installedRoot = resolve('node_modules') + sep;
for (const specifier of ${JSON.stringify(exports)}) {
  process.stdout.write('Importing ' + specifier + '\\n');
  assert(fileURLToPath(import.meta.resolve(specifier)).startsWith(installedRoot), 'Resolve only from the clean consumer');
  const module = await import(specifier);
  result.exports.push({ specifier, exports: Object.keys(module).sort() });
}
await writeFile(process.argv[2], JSON.stringify(result, null, 2) + '\\n');
`;
  const probePath = join(consumer, 'probe.mjs');
  await writeFile(probePath, probe);
  const importsPath = join(artifacts, 'export-imports.json');
  await run('export-imports', process.execPath, [probePath, importsPath], consumer);
  evidence.imports = JSON.parse(await readFile(importsPath, 'utf8'));

  // An eval module resolves bare imports from cwd. Use the installed accounting
  // directory so the same import conditions and package ancestry as runtime.mjs
  // select the SDKs; merely importing accounting leaves these imports deferred.
  const dependencyProbe = `
import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
const installedRoot = resolve('../../..') + sep;
const dependencies = [];
for (const [specifier, functions] of [
  ['@aztec/bb.js', ['Barretenberg', 'UltraHonkBackend', 'UltraHonkVerifierBackend']],
  ['@noir-lang/noir_js', ['Noir']],
]) {
  process.stdout.write('Importing actual dependency ' + specifier + '\\n');
  assert(fileURLToPath(import.meta.resolve(specifier)).startsWith(installedRoot), 'SDK must resolve inside the consumer node_modules');
  const module = await import(specifier);
  for (const name of functions) assert.equal(typeof module[name], 'function', specifier + ' export ' + name);
  dependencies.push({ specifier, checkedExports: functions });
}
await writeFile(process.argv[1], JSON.stringify(dependencies, null, 2) + '\\n');
`;
  const dependenciesPath = join(artifacts, 'sdk-imports.json');
  await run('sdk-imports', process.execPath, ['--input-type=module', '--eval', dependencyProbe, dependenciesPath],
    join(installedRoot, 'runtime', 'accounting'));
  evidence.dependencies = JSON.parse(await readFile(dependenciesPath, 'utf8'));
  evidence.ok = true;
} catch (error) {
  evidence.error = String(error.stack ?? error);
} finally {
  try { await rm(scratch, { recursive: true, force: true }); }
  catch (error) { evidence.ok = false; evidence.cleanupError = String(error); }
  await writeFile(join(artifacts, 'evidence.json'), JSON.stringify(evidence, null, 2) + '\n');
}
process.stdout.write(JSON.stringify({ ok: evidence.ok, evidence: join(artifacts, 'evidence.json'), error: evidence.error }) + '\n');
if (!evidence.ok) process.exitCode = 1;
