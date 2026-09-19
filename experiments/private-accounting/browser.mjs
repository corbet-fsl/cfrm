import { Noir } from '@noir-lang/noir_js';
import { Barretenberg, BackendType, UltraHonkBackend, UltraHonkVerifierBackend } from '@aztec/bb.js';
import { COMMUNITY_NAME, OPTIONS, hex, zeros, random, sha, be, memberBytes,
  receiptBytes, canonicalSignature } from './common.mjs';
import { checkScheme, SHA_SCHEME, POSEIDON_SCHEME, FR_MODULUS, fieldValue, limbs32, hashesFor, deriveCheckpoint } from './hashes.mjs';

const metrics = { checks: [], stages: [], proofs: [], userAgent: navigator.userAgent, threads: 1,
  maximumWasmBytes: 32768 * 65536, endJsHeapBytes: null, peakWasmBytes: null };
window.accountingProgress = metrics;
const assert = (condition, label) => { if (!condition) throw new Error(label); metrics.checks.push(label); };
const stage = name => { metrics.stages.push({ name, atMs: performance.now() }); };
const post = async command => {
  const response = await fetch('/fixture', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(command) });
  if (!response.ok) throw new Error('Public enrollment bridge failed'); return response.json();
};
const bytes = async url => new Uint8Array(await (await fetch(url)).arrayBuffer());
const arr = value => Array.from(value);
const circuitInput = value => Object.fromEntries(Object.entries(value).map(([k, v]) => [k,
  v instanceof Uint8Array ? arr(v) : Array.isArray(v) ? v.map(arr) : typeof v === 'number' ? String(v) : v]));

async function main() {
  assert(crossOriginIsolated && typeof SharedArrayBuffer !== 'undefined', 'browser supports isolated shared WASM memory');
  const manifest = await (await fetch('/manifest.json')).json();
  const rawCircuit = await bytes('/circuit.json');
  assert(hex(await sha(rawCircuit)) === manifest.circuitSha256, 'browser circuit matches build manifest');
  const circuit = JSON.parse(new TextDecoder().decode(rawCircuit));
  stage('initialize-browser-prover');
  assert(manifest.wasm?.length === 1 && manifest.wasm[0].name === 'barretenberg-threads.wasm', 'manifest pins only the selected shared-memory binary');
  for (const record of manifest.wasm) {
    const data = await bytes('/' + record.name);
    assert(data.length === record.bytes && hex(await sha(data)) === record.sha256, 'pinned same-origin WASM ' + record.name);
  }
  const verificationKey = await bytes('/vk.bin');
  assert(hex(await sha(verificationKey)) === manifest.vkSha256, 'browser verifier uses the pinned build verification key');
  const api = await Barretenberg.new({ backend: BackendType.WasmWorker, threads: 1, skipSrsInit: true,
    // The pinned browser loader inserts '-threads' when shared memory is
    // available, resolving this base path to /barretenberg-threads.wasm.
    wasmPath: '/barretenberg.wasm', memory: { initial: 2048, maximum: 32768 } });
  let released=false;
  const releaseBackend=async()=>{if(!released){released=true;await api.destroy();}};
  try {
  if (manifest.accountingMode === 'account-state-v2') {
    const { runAccountState } = await import('./account-state/browser.mjs');
    return await runAccountState({ api, circuit, manifest, verificationKey, post, bytes, metrics, assert, stage, releaseBackend });
  }
  const hashScheme = checkScheme(manifest.hashScheme);
  metrics.hashScheme = hashScheme;
  const hashes = hashesFor(hashScheme, async () => api);
  const { secretHash, leaf, state, marker } = hashes;
  const community = await sha(new TextEncoder().encode(COMMUNITY_NAME));
  const holders = [];
  for (let i = 0; i < 4; i++) {
    const key = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key.publicKey));
    const secret = random();
    holders.push({ key, raw: raw.slice(1), secret, secretHash: await secretHash(community, secret) });
  }
  stage('public-root-delegation');
  const enrolled = await post({ action: 'enroll', hashScheme, keys: holders.map(h => ({ accountKey: hex(h.raw), secretHash: hex(h.secretHash) })) });
  assert(enrolled.ok, 'real Ed25519 root/device delegation accepted by Rust');
  const config = enrolled.value;
  assert(config.community === hex(community), 'community digest matches pinned scope');
  const entries = config.entries;
  for (let i = 0; i < 4; i++) {
    holders[i].id = memberBytes(entries[i].admission.memberId);
    assert(entries[i].accountKey === hex(holders[i].raw) && entries[i].secretHash === hex(holders[i].secretHash), 'enrollment binds requested public accounting authority ' + i);
  }
  const checkpoint = await deriveCheckpoint(config, hashes);
  const { leaves, branches } = checkpoint;
  assert(hex(checkpoint.community) === config.community && leaves.length === 4 && checkpoint.root.length === 32,
    'browser derives its checkpoint from Rust-verified enrollments');
  for (const [label, mutate] of [
    ['altered delegated key', e => { e[1].accountKey = e[2].accountKey; }],
    ['altered accounting owner', e => { e[1].admission.memberId = e[2].admission.memberId; }],
    ['issuer signature cannot authorize member device', e => { e[1].authorization.signature = e[1].admission.signature; }],
    ['changed registered state secret', e => { e[1].secretHash = e[2].secretHash; }],
    ['duplicate enrolled permanent identity', e => { e[1] = structuredClone(e[0]); }],
  ]) {
    const altered = structuredClone(entries); mutate(altered);
    assert(!(await post({ action: 'verify', hashScheme, entries: altered })).ok, label);
  }
  const otherScheme = hashScheme === SHA_SCHEME ? POSEIDON_SCHEME : SHA_SCHEME;
  const reinterpreted = structuredClone(entries);
  for (const entry of reinterpreted) entry.hashScheme = otherScheme;
  assert(!(await post({ action: 'verify', hashScheme: otherScheme, entries: reinterpreted })).ok, 'signed enrollment cannot be reinterpreted under another hash scheme');
  if (hashScheme === POSEIDON_SCHEME) {
    assert(config.root === null, 'Rust returns verified original entries without a supplied Poseidon checkpoint');
    const invalidKeys = holders.map(h => ({ accountKey: hex(h.raw), secretHash: hex(h.secretHash) }));
    invalidKeys[0].secretHash = hex(be(FR_MODULUS, 32));
    assert(!(await post({ action: 'enroll', hashScheme, keys: invalidKeys })).ok, 'native enrollment rejects noncanonical Poseidon field');
    let rejected = false;
    try { fieldValue(be(FR_MODULUS, 32)); } catch { rejected = true; }
    assert(rejected, 'JS hash adapter rejects field-modulus encoding');
    const id = holders[0].id;
    const number = BigInt('0x' + hex(id));
    const alias = be(number + FR_MODULUS < 1n << 256n ? number + FR_MODULUS : number - FR_MODULUS, 32);
    assert(limbs32(id).some((v, i) => v !== limbs32(alias)[i]), 'bytes32 identifiers retain distinct limbs despite field-modulus congruence');
    const originalLeaf = await leaf(community, id, holders[0].raw, holders[0].secretHash, 80, 1000);
    const aliasLeaf = await leaf(community, alias, holders[0].raw, holders[0].secretHash, 80, 1000);
    assert(hex(originalLeaf) !== hex(aliasLeaf), 'commitment binds full identifier above the field modulus');
  }
  const path = i => [leaves[i ^ 1], branches[(i >> 1) ^ 1]];
  const noir = new Noir(circuit);
  async function witness(ownerIndex, peerIndex, role, kind, issued = 100, nonceOverride) {
    const owner = holders[ownerIndex], peer = holders[peerIndex];
    const nonce = nonceOverride ?? random(), group = random(), oldBlind = random(), newBlind = random();
    const balance = 7, reserved = 2; // Synthetic opening, not product policy.
    const responder = role === 0 ? peer : owner, other = role === 0 ? owner : peer;
    const signature = canonicalSignature(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, responder.key.privateKey,
      receiptBytes(community, responder.id, other.id, nonce, group, kind, issued)));
    return {
      community, enrollment_root: checkpoint.root, owner: owner.id,
      old_state: await state(community, owner.id, owner.secretHash, balance, role, peer.id, nonce, group, reserved, oldBlind),
      new_state: await state(community, owner.id, owner.secretHash, balance + reserved, 0, zeros(), zeros(), zeros(), 0, newBlind),
      spent_marker: await marker(community, owner.secret, owner.id, peer.id, nonce), now: 100,
      owner_secret: owner.secret, owner_key: owner.raw, owner_start: 80, owner_end: 1000, owner_path: path(ownerIndex), owner_index: ownerIndex,
      peer: peer.id, peer_key: peer.raw, peer_secret_hash: peer.secretHash, peer_start: 80, peer_end: 1000, peer_path: path(peerIndex), peer_index: peerIndex,
      balance, reserved, role, nonce, group, old_blind: oldBlind, new_blind: newBlind, kind, issued, signature,
    };
  }
  const valid = await witness(0, 1, 0, 1);
  stage('witness-negatives');
  const positives = [valid, await witness(1, 0, 1, 2)];
  const negative = [
    ['wrong hidden receipt owner', v => { v.peer = holders[2].id; }],
    ['wrong hidden enrolled key', v => { v.peer_key = holders[2].raw; }],
    ['borrowed membership path', v => { v.peer_path = path(2); v.peer_index = 2; }],
    ['wrong owner accounting secret', v => { v.owner_secret = holders[2].secret; }],
    ['self receipt', v => { v.peer = v.owner; }],
    ['opposite role reuse', v => { v.role = 1; }],
    ['changed nonce', v => { v.nonce[0] ^= 1; }],
    ['changed group', v => { v.group[0] ^= 1; }],
    ['changed signed decision', v => { v.kind = 2; }],
    ['forged receipt signature', v => { v.signature[0] ^= 1; }],
    ['inflated reserve', v => { v.reserved += 1; }],
    ['changed old state', v => { v.old_state[0] ^= 1; }],
    ['changed successor', v => { v.new_state[0] ^= 1; }],
    ['changed replay marker', v => { v.spent_marker[0] ^= 1; }],
    ['expired enrollment', v => { v.now = 1000; }],
  ];
  if (hashScheme === POSEIDON_SCHEME) {
    negative.push(['noncanonical field sibling', v => { v.peer_path[0] = be(FR_MODULUS, 32); }]);
    negative.push(['noncanonical secret commitment', v => { v.peer_secret_hash = be(FR_MODULUS, 32); }]);
    negative.push(['field-congruent hidden identity substitution', v => {
      const id = BigInt('0x' + hex(v.peer));
      v.peer = be(id + FR_MODULUS < 1n << 256n ? id + FR_MODULUS : id - FR_MODULUS, 32);
    }]);
  }
  for (const [label, mutate] of negative) {
    const value = structuredClone(valid); mutate(value);
    let rejected = false; try { await noir.execute(circuitInput(value)); } catch { rejected = true; }
    assert(rejected, label);
  }
  for (const [label, value] of [
    ['genuinely signed backdated receipt', await witness(0, 1, 0, 1, 79)],
    ['recipient self-declared answer', await witness(1, 0, 1, 1)],
  ]) {
    let rejected = false; try { await noir.execute(circuitInput(value)); } catch { rejected = true; }
    assert(rejected, label);
  }
  for (const [label, signer, credited] of [
    ['valid signature from a different enrolled member', holders[2], holders[0]],
    ['valid receipt credits a different owner', holders[1], holders[2]],
  ]) {
    const value = structuredClone(valid);
    value.signature = canonicalSignature(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signer.key.privateKey,
      receiptBytes(community, signer.id, credited.id, value.nonce, value.group, value.kind, value.issued)));
    let rejected = false; try { await noir.execute(circuitInput(value)); } catch { rejected = true; }
    assert(rejected, label);
  }
  if (hashScheme === POSEIDON_SCHEME) {
    // The signature genuinely authenticates the changed nonce; only exact
    // commitment/event linkage can reject a mistaken whole-field reduction.
    const value = await witness(0, 1, 0, 1, 100, be(7, 32));
    value.nonce = be(FR_MODULUS + 7n, 32);
    value.signature = canonicalSignature(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, holders[1].key.privateKey,
      receiptBytes(community, holders[1].id, holders[0].id, value.nonce, value.group, value.kind, value.issued)));
    let rejected = false; try { await noir.execute(circuitInput(value)); } catch { rejected = true; }
    assert(rejected, 'genuinely re-signed field-congruent nonce cannot reuse old state or event marker');
  }
    const setup = {};
    for (const record of manifest.setup) {
      const data = await bytes('/setup/' + record.name);
      assert(data.length === record.bytes && hex(await sha(data)) === record.sha256, 'pinned local setup ' + record.name);
      setup[record.name] = data;
    }
    await api.srsInitSrs({ pointsBuf: setup['g1.dat'], numPoints: manifest.numPoints, g2Point: setup['g2.dat'] });
    const backend = new UltraHonkBackend(circuit.bytecode, api);
    const verifier = new UltraHonkVerifierBackend(api);
    for (let i = 0; i < positives.length; i++) {
      stage('prove-' + i);
      const executionStart = performance.now();
      const executed = await noir.execute(circuitInput(positives[i]));
      const witnessMs = performance.now() - executionStart;
      const provingStart = performance.now();
      const proof = await backend.generateProof(executed.witness, OPTIONS);
      const provingMs = performance.now() - provingStart;
      const verificationStart = performance.now();
      assert(await verifier.verifyProof({ ...proof, verificationKey }, OPTIONS), 'browser accepts valid role ' + i);
      const verificationMs = performance.now() - verificationStart;
      // These public values are the only proof data crossing the browser boundary.
      metrics.proofs.push({ proof: hex(proof.proof), publicInputs: proof.publicInputs,
        proofBytes: proof.proof.length, witnessMs, provingMs, verificationMs, verificationIncludesKeyGeneration: false });
    }
    const one = positives[0];
    const reverse = await marker(community, holders[1].secret, holders[1].id, holders[0].id, one.nonce);
    assert(hex(reverse) !== hex(one.spent_marker), 'hash comparison: same nonce and opposite owners have different markers');
    metrics.endJsHeapBytes = performance.memory?.usedJSHeapSize ?? null;
    metrics.memoryMeasurement = 'Local JS heap at end; exact peak WASM memory is unknown; see harness process-family samples separately';
    metrics.downloadBytes = performance.getEntriesByType('resource').reduce((n, r) => n + r.encodedBodySize, 0);
    metrics.manifest = manifest;
    return { ok: true, ...metrics };
  } finally { await releaseBackend(); }
}
window.accountingDone = main().catch(error => ({ ok: false, ...metrics, error: String(error?.stack ?? error) }));
