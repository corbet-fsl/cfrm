import { loadArtifacts, withPinnedBrowserWasm } from './artifacts.mjs';
import { OPTIONS, hex, sha, unhex } from './encoding.mjs';
import { accountHashes, noirInput } from './hashes.mjs';
import { publicInputValues, statementFromInput, validateStatement } from './witness.mjs';
export { validateStatement } from './witness.mjs';

const exact = (value, keys) => value && !Array.isArray(value) && Object.keys(value).length === keys.length
  && keys.every(key => Object.hasOwn(value, key));
const equal = (a,b) => a.length === b.length && a.every((v,i) => v === b[i]);

// Shared with the real browser composition suite. Backend objects must be created
// from pinned artifacts; this low-level function does not load or select artifacts.
export async function proveAccountCandidate({ noir, backend, verifier, verificationKey, candidate, scope, maxProofBytes }) {
  const statement = structuredClone(candidate.statement), expected = await validateStatement(statement);
  if (!equal(publicInputValues(statementFromInput(candidate.input)), expected)) throw new Error('Candidate statement differs from witness');
  const start = performance.now(), executed = await noir.execute(noirInput(candidate.input));
  const provingAt = performance.now(), proof = await backend.generateProof(executed.witness, OPTIONS);
  const verifyingAt = performance.now();
  if (proof.proof.length > maxProofBytes || proof.publicInputs.length !== expected.length
      || !proof.publicInputs.every((n,i) => BigInt(n) === expected[i])) throw new Error('Prover public input mismatch');
  if (!await verifier.verifyProof({ ...proof, verificationKey }, OPTIONS)) throw new Error('Invalid generated account proof');
  return { record: { statement, proof: hex(proof.proof), proofScope: scope }, publicInputs: proof.publicInputs,
    witnessMs: provingAt - start, provingMs: verifyingAt - provingAt, verificationMs: performance.now() - verifyingAt };
}

async function runtime(options, proving) {
  const browser=typeof globalThis.window !== 'undefined' || typeof globalThis.WorkerGlobalScope !== 'undefined';
  if (browser) {
    if (globalThis.crossOriginIsolated !== true || typeof globalThis.SharedArrayBuffer !== 'function') {
      throw new Error('Browser accounting requires cross-origin isolation and shared memory');
    }
  }
  const artifacts = await loadArtifacts({...options,loadBrowserWasm:browser});
  const { Barretenberg, BackendType, UltraHonkBackend, UltraHonkVerifierBackend } = await import('@aztec/bb.js');
  const backendOptions = { backend: browser ? BackendType.WasmWorker : BackendType.Wasm,
    threads: 1, skipSrsInit: true, memory: { initial: 2048, maximum: artifacts.limits.memoryPages } };
  const api = browser
    ? await withPinnedBrowserWasm(artifacts.browserWasm, wasmPath => Barretenberg.new({ ...backendOptions, wasmPath }))
    : await Barretenberg.new(backendOptions);
  try {
    await api.srsInitSrs({ pointsBuf: artifacts.setup['g1.dat'], numPoints: artifacts.manifest.numPoints,
      g2Point: artifacts.setup['g2.dat'] });
    const verifier = new UltraHonkVerifierBackend(api);
    const scope = Object.freeze({ circuitDigest: Object.freeze(Array.from(unhex(artifacts.manifest.circuitSha256))),
      verifyingKeyDigest: Object.freeze(Array.from(unhex(artifacts.manifest.vkSha256))) });
    let busy = false, destroyed = false;
    async function exclusive(action) {
      if (busy || destroyed) throw new Error('Account runtime busy or closed');
      busy = true; try { return await action(); } finally { busy = false; }
    }
    async function verify(record) {
      if (!exact(record, ['statement','proof','proofScope']) || !exact(record.proofScope, ['circuitDigest','verifyingKeyDigest'])
          || !equal(record.proofScope.circuitDigest, scope.circuitDigest)
          || !equal(record.proofScope.verifyingKeyDigest, scope.verifyingKeyDigest)
          || typeof record.proof !== 'string' || record.proof.length === 0
          || record.proof.length > artifacts.limits.maxProofBytes * 2) throw new Error('Account proof scope/size');
      const inputs = await validateStatement(record.statement), proof = unhex(record.proof);
      if (!await verifier.verifyProof({ proof, publicInputs: inputs.map(n => '0x' + n.toString(16).padStart(64,'0')),
        verificationKey: artifacts.verificationKey }, OPTIONS)) throw new Error('Invalid account proof');
      return { verified: true, proofScope: scope };
    }
    const result = { scope, hashes: accountHashes(api), verify: record => exclusive(() => verify(record)),
      async destroy() { if (busy) throw new Error('Account runtime busy'); if (!destroyed) { destroyed = true; await api.destroy(); } } };
    if (proving) {
      const { Noir } = await import('@noir-lang/noir_js');
      const noir = new Noir(artifacts.circuit), backend = new UltraHonkBackend(artifacts.circuit.bytecode, api);
      result.prove = candidate => exclusive(async () => {
        const result = await proveAccountCandidate({ noir, backend, verifier, verificationKey: artifacts.verificationKey,
          candidate, scope, maxProofBytes: artifacts.limits.maxProofBytes });
        return result.record;
      });
    }
    return Object.freeze(result);
  } catch (error) { await api.destroy(); throw error; }
}

/** Cryptography only: AccountLedger independently enforces live policy, enrollment, clock and authorization. */
export const createAccountVerifier = options => runtime(options, false);
/** Run at the holder endpoint. Never send candidate.input or candidate.next to a server. */
export const createAccountProver = options => runtime(options, true);
