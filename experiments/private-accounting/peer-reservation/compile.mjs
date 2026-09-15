// Existing Crow worker only: no setup fetch, prover, fixture or shared output.
import { compile, createFileManager } from '@noir-lang/noir_wasm';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

if (process.argv.length !== 3) throw new Error('Usage: node peer-reservation/compile.mjs <separate-artifact-directory>');
const source = dirname(fileURLToPath(import.meta.url)), output = resolve(process.argv[2]);
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const started = performance.now();
const compiled = await compile(createFileManager(source));
if (!compiled.program?.bytecode) throw new Error('No compiled peer circuit');
const circuit = JSON.stringify(compiled.program);
await mkdir(output, { recursive: true });
await writeFile(resolve(output, 'circuit.json'), circuit);
const evidence = { mode: 'peer-reservation-v3', compiler: '1.0.0-beta.26',
  circuitSha256: hash(circuit),
  nargoSha256: hash(await readFile(resolve(source, 'Nargo.toml'))),
  circuitSourceSha256: hash(await readFile(resolve(source, 'src/main.nr'))),
  compileMs: performance.now() - started, proofExecuted: false };
await writeFile(resolve(output, 'compile.json'), JSON.stringify(evidence, null, 2) + '\n');
process.stdout.write(JSON.stringify(evidence) + '\n');
