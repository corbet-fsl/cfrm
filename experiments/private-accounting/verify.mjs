// Independent verifier process boundary: accepts public proof data only.
import { readFile } from 'node:fs/promises';
import { Barretenberg, BackendType, UltraHonkVerifierBackend } from '@aztec/bb.js';
import { OPTIONS, hex, unhex, sha, memberBytes } from './common.mjs';
import { checkScheme, POSEIDON_SCHEME, fieldValue, hashesFor, deriveCheckpoint } from './hashes.mjs';
import { statementAfterVerification } from './ledger.mjs';
import { runLedgerContract } from './ledger-contract.mjs';

export async function verifyResults(result, enrolled) {
  const manifest = JSON.parse(await readFile('public/manifest.json', 'utf8'));
  if (manifest.accountingMode === 'account-state-v2') {
    const { verifyAccountResults } = await import('./account-state/verify.mjs');
    return verifyAccountResults(result, enrolled);
  }
  if (!enrolled || result.proofs?.length !== 2) throw new Error('Missing independent enrollment/proof evidence');
  const hashScheme = checkScheme(manifest.hashScheme);
  if (enrolled.hashScheme !== hashScheme || result.hashScheme !== hashScheme) throw new Error('Independent hash scheme pin mismatch');
  const vk = new Uint8Array(await readFile('public/vk.bin'));
  const circuit = new Uint8Array(await readFile('public/circuit.json'));
  if (hex(await sha(vk)) !== manifest.vkSha256 || hex(await sha(circuit)) !== manifest.circuitSha256) throw new Error('Independent verifier artifact pin mismatch');
  const api = await Barretenberg.new({ backend: BackendType.Wasm, threads: 1, skipSrsInit: true,
    memory: { initial: 2048, maximum: 32768 } });
  const checks = [];
  const check = (condition, name) => { if (!condition) throw new Error(name); checks.push(name); };
  try {
    const checkpoint = await deriveCheckpoint(enrolled, hashesFor(hashScheme, async () => api));
    check(enrolled.entries.every(entry => entry.hashScheme === hashScheme), 'independent checkpoint derives from native-verified enrollments under pinned scheme');
    // The verifier needs only the public setup. No browser witness is accepted.
    const setup = {};
    for (const record of manifest.setup) {
      const bytes = new Uint8Array(await readFile('public/setup/' + record.name));
      check(bytes.length === record.bytes && hex(await sha(bytes)) === record.sha256, 'independent setup pin ' + record.name);
      setup[record.name] = bytes;
    }
    await api.srsInitSrs({ pointsBuf: setup['g1.dat'], numPoints: manifest.numPoints, g2Point: setup['g2.dat'] });
    const verifier = new UltraHonkVerifierBackend(api);
    const decode = value => {
      if (value.publicInputs?.length !== 193 || typeof value.proof !== 'string' || value.proof.length > 2_000_000) throw new Error('Public proof bounds');
      const values = value.publicInputs.map(x => BigInt(x));
      if (values.slice(0, 192).some(x => x < 0n || x > 255n)) throw new Error('Public byte range');
      const bytes = Uint8Array.from(values.slice(0, 192), Number);
      if (hashScheme === POSEIDON_SCHEME) {
        for (const start of [32, 96, 128, 160]) fieldValue(bytes.slice(start, start + 32));
      }
      return { proof: unhex(value.proof), publicInputs: value.publicInputs, verificationKey: vk,
        community: hex(bytes.slice(0, 32)), root: hex(bytes.slice(32, 64)), owner: hex(bytes.slice(64, 96)),
        old: hex(bytes.slice(96, 128)), next: hex(bytes.slice(128, 160)), marker: hex(bytes.slice(160, 192)), now: values[192] };
    };
    const proofs = result.proofs.map(decode);
    const started = performance.now();
    for (let i = 0; i < proofs.length; i++) {
      const proof = proofs[i];
      check(proof.community === enrolled.community && proof.root === hex(checkpoint.root) && proof.now === 100n, 'verifier independently pins scope/checkpoint/time ' + i);
      check(proof.owner === hex(memberBytes(enrolled.entries[i].admission.memberId)), 'named proof owner matches independently verified enrollment ' + i);
      check(await verifier.verifyProof(proof, OPTIONS), 'independent cryptographic verification role ' + i);
    }
    const valid = proofs[0];
    const corrupted = { ...valid, proof: valid.proof.slice() }; corrupted.proof[0] ^= 1;
    async function rejects(value) { try { return !(await verifier.verifyProof(value, OPTIONS)); } catch { return true; } }
    check(await rejects(corrupted), 'independent verifier rejects changed proof bytes');
    for (const [label, position] of [['owner', 64], ['old commitment', 96], ['successor', 128], ['marker', 160], ['checkpoint', 32]]) {
      const changed = { ...valid, publicInputs: [...valid.publicInputs] };
      changed.publicInputs[position] = '0x' + ((BigInt(changed.publicInputs[position]) + 1n) % 256n).toString(16).padStart(64, '0');
      check(await rejects(changed), 'independent verifier rejects changed ' + label);
    }
    check(await verifier.verifyProof(valid, OPTIONS), 'independent verifier still accepts valid proof after malformed inputs');
    const cryptographicVerificationMs = performance.now() - started;
    // Only real verifier-accepted public statements cross this trusted boundary.
    // SQLite tests retain synthetic pre-reserved genesis and report injected
    // storage mutations separately from cryptographic verification evidence.
    const storageStarted = performance.now();
    const ledger = await runLedgerContract(proofs.map(proof => statementAfterVerification(proof, {
      hashScheme, circuitSha256: manifest.circuitSha256, verificationKeySha256: manifest.vkSha256,
    })));
    ledger.elapsedMs = performance.now() - storageStarted;
    checks.push(...ledger.checks);
    check(proofs[0].marker !== proofs[1].marker, 'different scenario proofs expose different markers');
    return { checks, ledger, cryptographicVerificationMs, elapsedMs: performance.now() - started, verifierTarget: OPTIONS.verifierTarget, hashScheme,
      witnessReceived: false, genesis: 'synthetic pre-reserved opening; production genesis is not implemented' };
  } finally { await api.destroy(); }
}
