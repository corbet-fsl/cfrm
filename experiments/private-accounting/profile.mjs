// CI-only inspection of an already compiled, hash-pinned public circuit.
// No compiler invocation, proof witness, SRS initialization or proving.
import { Barretenberg, BackendType } from '@aztec/bb.js';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve, isAbsolute } from 'node:path';
import { createHash } from 'node:crypto';
import { gunzipSync, inflateRawSync } from 'node:zlib';

const hash = data => createHash('sha256').update(data).digest('hex');
const circuitPath = process.env.CIRCUIT_PATH;
const expectedHash = process.env.CIRCUIT_SHA256;
const outputDir = process.env.PROFILE_ARTIFACT_DIR;
if (!circuitPath || !isAbsolute(circuitPath) || !outputDir || !isAbsolute(outputDir)
  || !/^[0-9a-f]{64}$/.test(expectedHash ?? '')) {
  throw new Error('Require absolute CIRCUIT_PATH/PROFILE_ARTIFACT_DIR and exact CIRCUIT_SHA256');
}
await mkdir(outputDir, { recursive: true });
const started = performance.now();
let api;
const evidence = { version: 1, ok: false, circuitPath, expectedHash,
  backend: '5.0.0', threads: 1, maximumWasmBytes: 32768 * 65536,
  provingPerformed: false, setupInitialized: false, witnessRead: false };

try {
  const rawCircuit = await readFile(circuitPath);
  if (rawCircuit.length > 16 * 1024 * 1024 || hash(rawCircuit) !== expectedHash) throw new Error('Compiled circuit hash or size mismatch');
  const circuit = JSON.parse(rawCircuit.toString('utf8'));
  if (typeof circuit.bytecode !== 'string' || typeof circuit.debug_symbols !== 'string') throw new Error('Missing compiled circuit/debug metadata');
  const bytecode = new Uint8Array(gunzipSync(Buffer.from(circuit.bytecode, 'base64'), { maxOutputLength: 64 * 1024 * 1024 }));
  // Pinned Noir beta.26 emits base64-encoded raw DEFLATE JSON debug symbols.
  const symbols = JSON.parse(inflateRawSync(Buffer.from(circuit.debug_symbols, 'base64'),
    { maxOutputLength: 64 * 1024 * 1024 }).toString('utf8'));
  if (symbols.debug_infos?.length !== 1) throw new Error('Profiler requires the spike single-function debug map');
  const debug = symbols.debug_infos[0];
  const locations = debug.location_tree?.locations;
  if (!Array.isArray(locations) || !debug.acir_locations || !circuit.file_map) throw new Error('Unsupported debug metadata shape');

  api = await Barretenberg.new({ backend: BackendType.Wasm, threads: 1, skipSrsInit: true,
    memory: { initial: 2048, maximum: 32768 } });
  const stats = await api.circuitStats({
    circuit: { name: 'private-accounting-spike-profile', bytecode, verificationKey: new Uint8Array() },
    includeGatesPerOpcode: true,
    settings: { ipaAccumulation: false, oracleHashType: 'poseidon2', disableZk: false, optimizedSolidityVerifier: false },
  });
  evidence.stats = stats;
  await writeFile(resolve(outputDir, 'circuit-stats.json'), JSON.stringify(stats, null, 2) + '\n');
  await writeFile(resolve(outputDir, 'debug-symbols.json'), JSON.stringify(symbols, null, 2) + '\n');
  if (!Array.isArray(stats.gatesPerOpcode) || stats.gatesPerOpcode.length !== stats.numAcirOpcodes
    || stats.gatesPerOpcode.some(n => !Number.isSafeInteger(n) || n < 0)) {
    throw new Error('Gate counts do not map one-to-one to ACIR opcode indices');
  }

  const sourceFiles = {};
  for (const [id, file] of Object.entries(circuit.file_map)) {
    if (typeof file.path !== 'string' || typeof file.source !== 'string') throw new Error('Invalid public source file');
    sourceFiles[id] = { path: file.path, sha256: hash(file.source), source: file.source };
  }
  function stackFor(opcode) {
    let location = debug.acir_locations[String(opcode)];
    if (location === undefined) return [];
    const stack = [], seen = new Set();
    while (location !== null) {
      if (!Number.isSafeInteger(location) || seen.has(location) || seen.size >= 128) throw new Error('Invalid debug location ancestry');
      seen.add(location);
      const record = locations[location];
      if (!record?.value?.span) throw new Error('Missing debug location');
      const file = sourceFiles[String(record.value.file)];
      if (file) {
        const bytes = Buffer.from(file.source, 'utf8');
        const { start, end } = record.value.span;
        if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end < start || end > bytes.length) throw new Error('Invalid debug source span');
        const prefix = bytes.subarray(0, start).toString('utf8');
        stack.push({ file: file.path, fileId: record.value.file, start, end,
          line: prefix.split('\n').length, expression: bytes.subarray(start, end).toString('utf8') });
      }
      location = record.parent;
    }
    return stack.reverse();
  }
  const groups = new Map();
  const sourceGroups = new Map();
  const mappings = stats.gatesPerOpcode.map((gates, opcode) => {
    const stack = stackFor(opcode);
    const primitiveHint = stack.some(frame => frame.file.endsWith('/ecdsa_secp256r1.nr')) ? 'p256'
      : stack.some(frame => frame.file.endsWith('/sha256.nr')) ? 'sha256'
      : stack.length ? 'other' : 'no-debug-location';
    const previous = groups.get(primitiveHint) ?? { gates: 0, opcodes: 0 };
    previous.gates += gates; previous.opcodes += 1; groups.set(primitiveHint, previous);
    const deepest = stack.at(-1);
    const key = deepest ? `${deepest.file}:${deepest.start}:${deepest.end}` : 'no-debug-location';
    const sourceGroup = sourceGroups.get(key) ?? { source: deepest ?? null, gates: 0, opcodes: 0 };
    sourceGroup.gates += gates; sourceGroup.opcodes += 1; sourceGroups.set(key, sourceGroup);
    return { opcode, gates, primitiveHint, stack };
  });
  const attributed = stats.gatesPerOpcode.reduce((sum, n) => sum + n, 0);
  evidence.mapping = {
    caveat: 'Debug-source attribution, not isolated primitive timing/memory; total gate accounting can include shared overhead.',
    gatesAttributedToOpcodes: attributed, totalMinusAttributed: stats.numGates - attributed,
    byPrimitiveHint: Object.fromEntries(groups),
    byDeepestSource: [...sourceGroups.values()].sort((a, b) => b.gates - a.gates),
  };
  await writeFile(resolve(outputDir, 'source-files.json'), JSON.stringify(sourceFiles, null, 2) + '\n');
  await writeFile(resolve(outputDir, 'opcode-source-mapping.json'), JSON.stringify(mappings, null, 2) + '\n');
  evidence.ok = true;
} catch (error) {
  evidence.error = String(error?.stack ?? error);
} finally {
  if (api) {
    try { await api.destroy(); }
    catch (error) { evidence.cleanupError = String(error); evidence.ok = false; }
  }
  evidence.elapsedMs = performance.now() - started;
  await writeFile(resolve(outputDir, 'profile-evidence.json'), JSON.stringify(evidence, null, 2) + '\n');
}
console.log(JSON.stringify({ ok: evidence.ok, circuitSha256: expectedHash,
  numGates: evidence.stats?.numGates, attribution: evidence.mapping?.byPrimitiveHint,
  outputDir, error: evidence.error, cleanupError: evidence.cleanupError }));
if (!evidence.ok) process.exitCode = 1;
