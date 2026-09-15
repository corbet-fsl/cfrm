// Trusted Node boundary: public proofs only, original enrollments verified by
// the separate Rust/cmsg fixture, policy/time/artifact pins chosen by the host.
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { Barretenberg, BackendType, UltraHonkVerifierBackend } from '@aztec/bb.js';
import { OPTIONS, hex, unhex, sha } from '../common.mjs';
import { fieldValue } from '../hashes.mjs';
import { ACCOUNT_MODE, accountHashes, checkpointFromVerified, policyDigest, statePolicyDigest, POLICY_KEYS } from './hashes.mjs';
import { publicInputValues, PUBLIC_INPUT_COUNT, validityHorizon } from './witness.mjs';

const statementKeys = ['protocolVersion','community','owner','policyDigest','enrollmentRoot','now','validUntil','genesis',
  'previousVersion','nextVersion','previousState','nextState','settlementMarker','policy'];
const policyKeys = POLICY_KEYS;
const exact = (value, keys) => value && !Array.isArray(value) && Object.keys(value).length === keys.length
  && keys.every(key => Object.hasOwn(value, key));
const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const digestBytes = value => {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) throw new Error('Invalid trusted digest');
  return unhex(value);
};

export async function createAccountVerifier(manifestPath, trusted) {
  const directory = dirname(resolve(manifestPath));
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  if (manifest.accountingMode !== ACCOUNT_MODE || manifest.hashScheme !== 'poseidon2-bn254-fixed-128-v1'
      || !exact(manifest.accountPolicy, policyKeys)) throw new Error('Unpinned account-state mode/policy');
  if (!trusted || !Array.isArray(trusted.acceptedTimes) || !trusted.acceptedTimes.length
      || trusted.acceptedTimes.length > 32 || !trusted.acceptedTimes.every(t => Number.isSafeInteger(t) && t > 0)) throw new Error('Trusted verification times required');
  const community = digestBytes(trusted.community), allowedTimes = new Set(trusted.acceptedTimes);
  const immutable = await statePolicyDigest(community, manifest.accountPolicy);
  const policies = trusted.acceptedPolicies ?? [manifest.accountPolicy];
  if (!Array.isArray(policies) || !policies.length || policies.length > 16) throw new Error('Trusted policy history bound');
  const approved = [];
  for (const policy of policies) {
    if (!exact(policy, policyKeys) || !equal(await statePolicyDigest(community, policy), immutable)) throw new Error('Trusted policy history changed immutable terms');
    approved.push({ policy, digest: await policyDigest(community, policy) });
  }
  const vk = new Uint8Array(await readFile(resolve(directory, 'vk.bin')));
  const circuit = new Uint8Array(await readFile(resolve(directory, 'circuit.json')));
  if (hex(await sha(vk)) !== manifest.vkSha256 || hex(await sha(circuit)) !== manifest.circuitSha256) throw new Error('Independent artifact pin mismatch');
  const scope = { circuitDigest: Array.from(digestBytes(manifest.circuitSha256)),
    verifyingKeyDigest: Array.from(digestBytes(manifest.vkSha256)) };
  const api = await Barretenberg.new({ backend: BackendType.Wasm, threads: 1, skipSrsInit: true,
    memory: { initial: 2048, maximum: 32768 } });
  try {
    const checkpoint = await checkpointFromVerified(community, trusted.entries, accountHashes(api));
    const owners = new Set(checkpoint.entries.map(entry => hex(entry.member)));
    const setup = {};
    for (const record of manifest.setup) {
      if (!['g1.dat','g2.dat'].includes(record.name)) throw new Error('Unexpected setup artifact');
      const data = new Uint8Array(await readFile(resolve(directory, 'setup', record.name)));
      if (data.length !== record.bytes || hex(await sha(data)) !== record.sha256) throw new Error('Independent setup pin mismatch');
      setup[record.name] = data;
    }
    await api.srsInitSrs({ pointsBuf: setup['g1.dat'], numPoints: manifest.numPoints, g2Point: setup['g2.dat'] });
    const verifier = new UltraHonkVerifierBackend(api);
    return {
      scope, manifest, checkpoint,
      async verify(record) {
        const s = record.statement;
        if (!exact(s, statementKeys) || !exact(s.policy, policyKeys)) throw new Error('Statement field set');
        const values = publicInputValues(s);
        if (values.length !== PUBLIC_INPUT_COUNT || BigInt(s.validUntil) !== validityHorizon(s.now, manifest.accountPolicy)
            || !equal(s.community, Array.from(community))
            || !owners.has(hex(Uint8Array.from(s.owner))) || !allowedTimes.has(s.now)
            || !approved.some(entry => policyKeys.every(k => s.policy[k] === entry.policy[k]) && equal(s.policyDigest, entry.digest))
            || fieldValue(Uint8Array.from(s.enrollmentRoot)) !== checkpoint.root) throw new Error('Independent scope/policy/time/checkpoint mismatch');
        for (const name of ['previousState','nextState','settlementMarker']) fieldValue(Uint8Array.from(s[name]));
        if (fieldValue(Uint8Array.from(s.nextState)) === 0n) throw new Error('Zero successor');
        if (s.genesis ? s.previousVersion !== 0 || s.nextVersion !== 0 || s.previousState.some(Boolean) || s.settlementMarker.some(Boolean)
          : s.nextVersion !== s.previousVersion + 1 || !s.previousState.some(Boolean)) throw new Error('Version/genesis shape');
        if (record.proofScope && (!exact(record.proofScope, ['circuitDigest','verifyingKeyDigest'])
            || !equal(record.proofScope.circuitDigest, scope.circuitDigest)
            || !equal(record.proofScope.verifyingKeyDigest, scope.verifyingKeyDigest))) throw new Error('Proof scope mismatch');
        if (typeof record.proof !== 'string' || record.proof.length > 2_000_000
            || !/^(?:[0-9a-f]{2})+$/.test(record.proof)) throw new Error('Proof byte bound');
        const publicInputs = values.map(n => '0x' + n.toString(16).padStart(64, '0'));
        if (record.publicInputs && (record.publicInputs.length !== values.length
            || !record.publicInputs.every((value, index) => BigInt(value) === values[index]))) throw new Error('Supplied public inputs differ from statement');
        if (!await verifier.verifyProof({ proof: unhex(record.proof), publicInputs, verificationKey: vk }, OPTIONS)) throw new Error('Invalid account-state proof');
        return { verified: true, proofScope: scope };
      },
      destroy: () => api.destroy(),
    };
  } catch (error) { await api.destroy(); throw error; }
}

export async function verifyAccountResults(result, trusted) {
  if (result.accountingMode !== ACCOUNT_MODE || !Array.isArray(result.proofs)
      || result.proofs.length < 4 || result.proofs.length > 32) throw new Error('Account proof chain bound');
  const verifier = await createAccountVerifier(resolve('public/manifest.json'), trusted);
  const checks = [], began = performance.now();
  try {
    for (let i = 0; i < result.proofs.length; i++) {
      await verifier.verify(result.proofs[i]); checks.push('independent account proof ' + i);
    }
    const positive = result.proofs[0];
    const rejects = async (value, label) => {
      let rejected = false; try { await verifier.verify(value); } catch { rejected = true; }
      if (!rejected) throw new Error(label); checks.push(label);
    };
    for (const name of ['owner','policyDigest','enrollmentRoot','previousState','nextState','settlementMarker']) {
      const value = structuredClone(positive); value.statement[name][0] ^= 1;
      await rejects(value, 'independent rejects changed ' + name);
    }
    const invalidTime = structuredClone(positive); invalidTime.statement.now += 1;
    await rejects(invalidTime, 'independent rejects unapproved time');
    const invalidHorizon = structuredClone(positive); invalidHorizon.statement.validUntil += 1;
    await rejects(invalidHorizon, 'independent rejects a private or stale proof validity horizon');
    const invalidPolicy = structuredClone(positive); invalidPolicy.statement.policy.initialCredit += 1;
    await rejects(invalidPolicy, 'independent rejects unpinned policy');
    for (const name of ['circuitDigest','verifyingKeyDigest']) {
      const alteredScope = structuredClone(positive); alteredScope.proofScope = structuredClone(verifier.scope);
      alteredScope.proofScope[name][0] ^= 1;
      await rejects(alteredScope, 'independent rejects a different ' + name + ' after policy implementation changes');
    }
    const corrupted = structuredClone(positive); corrupted.proof = (corrupted.proof.startsWith('00') ? '01' : '00') + corrupted.proof.slice(2);
    await rejects(corrupted, 'independent rejects changed proof');
    await verifier.verify(positive); checks.push('independent positive after malformed inputs');
    return { checks, elapsedMs: performance.now() - began, witnessReceived: false,
      accountingMode: ACCOUNT_MODE, genesis: 'cryptographically proved empty account; uniqueness/retry/CAS requires the durable host ledger' };
  } finally { await verifier.destroy(); }
}
