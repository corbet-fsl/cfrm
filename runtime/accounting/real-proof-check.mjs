// CI: verify existing public browser proofs using the shipped runtime, not a mock.
// Usage: node real-proof-check.mjs /absolute/config.json /absolute/browser-evidence.json
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createAccountVerifier } from './runtime.mjs';
import { nodeArtifactOptions } from './node-verifier.mjs';

const [config,evidencePath]=process.argv.slice(2);
if (!config || !evidencePath) throw new Error('Trusted configuration and public browser evidence required');
const evidence=JSON.parse(await readFile(evidencePath,'utf8'));
assert.equal(evidence.contract?.ok,true);
const options=await nodeArtifactOptions(config);
const verifier=await createAccountVerifier(options);
let checked=0;
try {
  assert(evidence.contract.runtimeFactory?.record,'Actual browser runtime factory evidence required');
  assert.equal(evidence.contract.runtimeFactory.manifestSha256,options.manifestSha256);
  for(const item of [...evidence.contract.proofs,evidence.contract.runtimeFactory.record]) {
    const record={statement:item.statement,proof:item.proof,proofScope:verifier.scope};
    assert.equal((await verifier.verify(record)).verified,true);checked++;
    const bad=structuredClone(record);bad.proof=(bad.proof.startsWith('00')?'01':'00')+bad.proof.slice(2);
    await assert.rejects(verifier.verify(bad));
    const scope=structuredClone(record);scope.proofScope.circuitDigest[0]^=1;
    await assert.rejects(verifier.verify(scope));
  }
  assert(checked>0);
  process.stdout.write(JSON.stringify({ok:true,realAccountProofs:checked,scenarioAccountProofs:evidence.contract.proofs.length,
    factoryProofs:1,corruptionAndScopeRejections:checked*2})+'\n');
} finally {await verifier.destroy();}
