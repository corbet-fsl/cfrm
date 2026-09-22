// CI: verify existing public browser proofs using the shipped runtime, not a mock.
// Usage: node real-proof-check.mjs /absolute/config.json /absolute/browser-evidence.json
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createAccountVerifier } from './runtime.mjs';
import { nodeArtifactOptions } from './node-verifier.mjs';

// Shared CI check for retained public records. Callers must separately establish
// their evidence provenance; this helper makes no browser-completion claim.
export async function verifyPublicProofRecords(options, records) {
  assert(Array.isArray(records) && records.length > 0 && records.length <= 33);
  const verifier=await createAccountVerifier(options);
  let checked=0;
  try {
    for(const item of records) {
      const record={statement:item.statement,proof:item.proof,proofScope:verifier.scope};
      assert.equal((await verifier.verify(record)).verified,true);checked++;
      const bad=structuredClone(record);bad.proof=(bad.proof.startsWith('00')?'01':'00')+bad.proof.slice(2);
      await assert.rejects(verifier.verify(bad));
      const scope=structuredClone(record);scope.proofScope.circuitDigest[0]^=1;
      await assert.rejects(verifier.verify(scope));
    }
    return {ok:true,realAccountProofs:checked,corruptionAndScopeRejections:checked*2};
  } finally {await verifier.destroy();}
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [config,evidencePath]=process.argv.slice(2);
  if (!config || !evidencePath) throw new Error('Trusted configuration and public browser evidence required');
  const evidence=JSON.parse(await readFile(evidencePath,'utf8'));
  assert.equal(evidence.contract?.ok,true);
  const options=await nodeArtifactOptions(config);
  assert(evidence.contract.runtimeFactory?.record,'Actual browser runtime factory evidence required');
  assert.equal(evidence.contract.runtimeFactory.manifestSha256,options.manifestSha256);
  const result=await verifyPublicProofRecords(options,[...evidence.contract.proofs,evidence.contract.runtimeFactory.record]);
  process.stdout.write(JSON.stringify({...result,scenarioAccountProofs:evidence.contract.proofs.length,factoryProofs:1})+'\n');
}
