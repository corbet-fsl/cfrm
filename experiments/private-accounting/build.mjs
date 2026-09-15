// Run only on the existing CI worker. Project dependencies, no tool installation.
import { compile, createFileManager } from '@noir-lang/noir_wasm';
import { Barretenberg, BackendType, UltraHonkBackend } from '@aztec/bb.js';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import { OPTIONS } from './common.mjs';
import { checkScheme, SHA_SCHEME, POSEIDON_SCHEME, POSEIDON_SOURCE } from './hashes.mjs';
import { policyBytes, POLICY_KEYS } from './account-state/hashes.mjs';

const hash = data => createHash('sha256').update(data).digest('hex');
const hashScheme = checkScheme(process.env.HASH_SCHEME ?? SHA_SCHEME);
const accountingMode = process.env.ACCOUNTING_MODE ?? 'settlement-v1';
if (!['settlement-v1', 'account-state-v2'].includes(accountingMode)) throw new Error('Unsupported accounting mode');
if (accountingMode === 'account-state-v2' && hashScheme !== POSEIDON_SCHEME) throw new Error('Account state requires pinned Poseidon2');
const circuitDir = accountingMode === 'account-state-v2' ? 'account-state'
  : hashScheme === POSEIDON_SCHEME ? 'circuit-poseidon2' : 'circuit';
const setupLockPath = accountingMode === 'account-state-v2' ? 'account-state/setup-lock.json' : 'setup-lock.json';
let accountPolicy;
if (accountingMode === 'account-state-v2') {
  if (!process.env.ACCOUNT_POLICY_JSON) throw new Error('ACCOUNT_POLICY_JSON required; no product defaults');
  accountPolicy = JSON.parse(process.env.ACCOUNT_POLICY_JSON);
  const fields = POLICY_KEYS;
  if (!accountPolicy || Object.keys(accountPolicy).length !== fields.length || !fields.every(key => Object.hasOwn(accountPolicy, key))) throw new Error('Exact policy fields required');
  policyBytes(new Uint8Array(32), accountPolicy); // Validate explicit bounds before compilation.
}
await mkdir('public/setup', { recursive: true });
const started = performance.now();
const compiled = await compile(createFileManager(resolve(circuitDir)));
if (!compiled.program?.bytecode) throw new Error('Compiler produced no circuit');
await writeFile('public/circuit.json', JSON.stringify(compiled.program));
let peerCompiled;
if (accountingMode === 'account-state-v2') {
  peerCompiled = await compile(createFileManager(resolve('peer-reservation')));
  if (!peerCompiled.program?.bytecode) throw new Error('Compiler produced no peer circuit');
  await mkdir('public/peer-reservation', { recursive: true });
  await writeFile('public/peer-reservation/circuit.json', JSON.stringify(peerCompiled.program));
}
const api = await Barretenberg.new({ backend: BackendType.Wasm, threads: 1, skipSrsInit: true,
  memory: { initial: 2048, maximum: 32768 } }); // Units are 64KiB pages in pinned source.
try {
  const bytecode = new Uint8Array(gunzipSync(Buffer.from(compiled.program.bytecode, 'base64')));
  const stats = await api.circuitStats({ circuit: { name: 'private-accounting-spike', bytecode, verificationKey: new Uint8Array() },
    includeGatesPerOpcode: false,
    settings: { ipaAccumulation: false, oracleHashType: 'poseidon2', disableZk: false, optimizedSolidityVerifier: false } });
  // Persist compiler/backend evidence before setup can fail. These fields are
  // public circuit metadata; there is no witness or successful-proof claim.
  const circuitStats = { version: 1, accountingMode, hashScheme, compiler: '1.0.0-beta.26', backend: '5.0.0',
    circuitSha256: hash(await readFile('public/circuit.json')), stats };
  await writeFile('public/circuit-stats.json', JSON.stringify(circuitStats, null, 2) + '\n');
  const requiredPoints = Number(stats.numGatesDyadic) + 1;
  if (!Number.isSafeInteger(requiredPoints) || requiredPoints <= 1 || requiredPoints > 2 ** 20 + 1) throw new Error('Circuit exceeds bounded setup spike');
  // BB5 verifies each complete compressed G1 chunk against its in-binary hash.
  // bn254_g1_chunk_hashes.hpp pins 2^17 points ×32 bytes =4MiB per chunk.
  // bbapi_srs.cpp requires chunk alignment; the memory CRS factory requires
  // sufficient points, not a power-of-two count. Preserve the measured floor.
  const pointsPerChunk = 2 ** 17;
  const numPoints = Math.max(2 ** 19, Math.ceil(requiredPoints / pointsPerChunk) * pointsPerChunk);
  // Existing circuit bound plus at most one alignment chunk: <=36MiB G1.
  const maximumSetupPoints = 9 * pointsPerChunk;
  if (numPoints > maximumSetupPoints) throw new Error('Rounded setup exceeds resource bound');
  circuitStats.setupPlan = { requiredPoints, pointsPerChunk, numPoints, maximumSetupPoints, compressedG1Bytes: numPoints * 32 };
  await writeFile('public/circuit-stats.json', JSON.stringify(circuitStats, null, 2) + '\n');
  let peerStats;
  if (peerCompiled) {
    peerStats = await api.circuitStats({ circuit: { name: 'peer-reservation-v3',
      bytecode: new Uint8Array(gunzipSync(Buffer.from(peerCompiled.program.bytecode, 'base64'))), verificationKey: new Uint8Array() },
      includeGatesPerOpcode: false,
      settings: { ipaAccumulation: false, oracleHashType: 'poseidon2', disableZk: false, optimizedSolidityVerifier: false } });
    await writeFile('public/peer-reservation/stats.json', JSON.stringify(peerStats, null, 2) + '\n');
    if (!Number.isSafeInteger(Number(peerStats.numGatesDyadic)) || Number(peerStats.numGatesDyadic) + 1 > numPoints) throw new Error('Peer circuit exceeds the already pinned shared setup');
  }
  let locked;
  try { locked = JSON.parse(await readFile(setupLockPath, 'utf8')); }
  catch (error) { if (error.code !== 'ENOENT' || process.env.RESOLVE_SETUP !== '1') throw error; }
  if (locked && locked.numPoints !== numPoints) throw new Error('Setup size differs from pinned circuit');
  const specs = [
    { name: 'g1.dat', url: 'https://crs.aztec-cdn.foundation/g1_compressed.dat', bytes: numPoints * 32, range: true },
    { name: 'g2.dat', url: 'https://crs.aztec-cdn.foundation/g2.dat', bytes: 128, range: false },
  ];
  const setup = [];
  for (const spec of specs) {
    let bytes;
    try { bytes = await readFile('public/setup/' + spec.name); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (!bytes || bytes.length !== spec.bytes) {
      const response = await fetch(spec.url, { headers: spec.range ? { Range: `bytes=0-${spec.bytes - 1}` } : {},
        redirect: 'error', signal: AbortSignal.timeout(120_000) });
      if (!response.ok || (spec.range && response.status !== 206)) throw new Error('Public setup range fetch failed');
      const chunks = []; let size = 0;
      for await (const chunk of response.body) {
        size += chunk.length; if (size > spec.bytes) throw new Error('Public setup exceeds exact bound'); chunks.push(chunk);
      }
      bytes = Buffer.concat(chunks);
    }
    if (bytes.length !== spec.bytes) throw new Error('Public setup length mismatch');
    const record = { ...spec, sha256: hash(bytes) };
    const expected = locked?.files?.find(f => f.name === spec.name);
    if (locked && JSON.stringify(expected) !== JSON.stringify(record)) throw new Error('Pinned public setup mismatch');
    setup.push(record); await writeFile('public/setup/' + spec.name, bytes);
  }
  const setupLock = { version: 1, numPoints, files: setup };
  await api.srsInitSrs({ pointsBuf: new Uint8Array(await readFile('public/setup/g1.dat')),
    numPoints, g2Point: new Uint8Array(await readFile('public/setup/g2.dat')) });
  // Do not create a candidate pin for a setup the actual backend rejects.
  if (!locked) await writeFile(setupLockPath, JSON.stringify(setupLock, null, 2) + '\n');
  const vk = await new UltraHonkBackend(compiled.program.bytecode, api).getVerificationKey(OPTIONS);
  await writeFile('public/vk.bin', vk);
  let peerReservation;
  if (peerCompiled) {
    const peerVk = await new UltraHonkBackend(peerCompiled.program.bytecode, api).getVerificationKey(OPTIONS);
    await writeFile('public/peer-reservation/vk.bin', peerVk);
    peerReservation = { mode: 'peer-reservation-v3', publicInputs: 389,
      circuitSha256: hash(await readFile('public/peer-reservation/circuit.json')), vkSha256: hash(peerVk),
      circuitSourceSha256: hash(await readFile('peer-reservation/src/main.nr')),
      nargoSha256: hash(await readFile('peer-reservation/Nargo.toml')), stats: peerStats, sharesAccountSetup: true };
  }
  // The upstream browser bundle defaults to fetching an embedded data: URL.
  // Serve the pinned package's real WASM locally to retain connect-src 'self'.
  const backendDir = dirname(fileURLToPath(import.meta.resolve('@aztec/bb.js')));
  const browserAssets = resolve(backendDir, '..', 'browser', 'barretenberg_wasm', 'fetch_code', 'browser');
  const wasm = [];
  // This contract requires an isolated SharedArrayBuffer-capable browser. The
  // pinned loader chooses this binary even when desiredThreads is one.
  for (const name of ['barretenberg-threads']) {
    // bb.js 5.0.0 ships both browser binaries as generated data-URL modules;
    // dest/node ships only the shared-memory .wasm.gz. Read the exact published
    // literal without evaluating it or changing the installed package.
    const source = await readFile(resolve(browserAssets, name + '.js'), 'utf8');
    const embedded = /^const barretenberg = "data:application\/gzip;base64,([A-Za-z0-9+/]+={0,2})";\s*export default barretenberg;\s*$/.exec(source);
    if (!embedded) throw new Error('Pinned browser WASM module layout changed: ' + name);
    const compressed = Buffer.from(embedded[1], 'base64');
    if (compressed.toString('base64') !== embedded[1]) throw new Error('Invalid embedded browser WASM encoding');
    const data = gunzipSync(compressed, { maxOutputLength: 128 * 1024 * 1024 });
    if (data.length < 8 || !data.subarray(0, 8).equals(Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]))) throw new Error('Invalid browser WASM header');
    await writeFile('public/' + name + '.wasm', data);
    wasm.push({ name: name + '.wasm', bytes: data.length, sha256: hash(data) });
  }
  const manifest = { version: 1, compiler: '1.0.0-beta.26', backend: '5.0.0', verifierTarget: OPTIONS.verifierTarget,
    hashScheme, accountingMode, accountPolicy, peerReservation, poseidonSource: hashScheme === POSEIDON_SCHEME ? POSEIDON_SOURCE : null,
    circuitSha256: hash(await readFile('public/circuit.json')), vkSha256: hash(vk),
    circuitSourceSha256: hash(await readFile(circuitDir + '/src/main.nr')), requiredPoints, pointsPerChunk, numPoints, setup, wasm,
    ...(accountingMode === 'account-state-v2' ? { indexedSourceSha256: hash(await readFile(circuitDir + '/src/indexed.nr')) } : {}),
    compileAndSetupMs: performance.now() - started, stats, threads: 1, maximumWasmBytes: 32768 * 65536 };
  await writeFile('public/manifest.json', JSON.stringify(manifest, null, 2));
} finally { await api.destroy(); }
// Rolldown's supported override bypasses incorrect libc detection on the known
// GNU CI host. Scope it to bundling, after the proof backend has been destroyed.
const previousBinding = process.env.NAPI_RS_NATIVE_LIBRARY_PATH;
try {
  if (process.env.CFRM_BUNDLER_BINDING) process.env.NAPI_RS_NATIVE_LIBRARY_PATH = resolve(process.env.CFRM_BUNDLER_BINDING);
  const { build } = await import('vite');
  await build();
} finally {
  if (previousBinding === undefined) delete process.env.NAPI_RS_NATIVE_LIBRARY_PATH;
  else process.env.NAPI_RS_NATIVE_LIBRARY_PATH = previousBinding;
}
