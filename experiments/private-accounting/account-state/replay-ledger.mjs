// CI-only continuation from hash-pinned public evidence. Never rewrite the
// original browser result or claim that this process executed a browser/prover.
import assert from 'node:assert/strict';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { verifyResults } from '../verify.mjs';
import { runRustAccountLedgerContract } from './ledger-contract.mjs';
import { verifyPublicProofRecords } from '../../../runtime/accounting/real-proof-check.mjs';
import { nodeArtifactOptions } from '../../../runtime/accounting/node-verifier.mjs';

const root = process.env.REUSE_ARTIFACT_DIR;
const scenario = process.env.ACCOUNT_SCENARIOS;
const source = process.env.BROWSER_BUNDLE_SHA;
assert(root && ['answer','close'].includes(scenario));
assert.match(source ?? '', /^[0-9a-f]{40}$/);
assert.match(process.env.REUSE_ARTIFACT_SHA256 ?? '', /^[0-9a-f]{64}$/);
const digest = async path => createHash('sha256').update(await readFile(path)).digest('hex');
const json = async path => JSON.parse(await readFile(path, 'utf8'));
// The shared shell runner verifies every entry before extracting any artifact.
assert.equal(await digest(resolve(root, 'SHA256SUMS')), process.env.REUSE_ARTIFACT_SHA256);
const manifestPath = resolve('public/manifest.json');
const manifest = await json(manifestPath), manifestSha256 = await digest(manifestPath);
assert.equal(manifestSha256, await digest(resolve(root, 'manifest.json')));
assert.equal(manifest.accountingMode, 'account-state-v2');
assert.equal(manifest.hashScheme, 'poseidon2-bn254-fixed-128-v1');
assert.equal(manifest.circuitSourceSha256, await digest('account-state/src/main.nr'));
assert.equal(manifest.indexedSourceSha256, await digest('account-state/src/indexed.nr'));
assert.deepEqual(manifest.accountPolicy, JSON.parse(process.env.ACCOUNT_POLICY_JSON));
const revisions = [...(await readFile('../../.ci/archives.toml', 'utf8')).matchAll(/^revision = "([0-9a-f]{40})"$/gm)];
assert.equal(revisions.length, 1);
assert.equal((await readFile(resolve(root, 'cmsg-source-revision.txt'), 'utf8')).trim(), revisions[0][1]);

const priorPath = resolve(root, scenario, 'browser-evidence.json');
const prior = await json(priorPath);
function cleanBrowserEvidence(value, expectedScenario) {
  assert.equal(value.source, source);
  assert.equal(value.checkPhase, 'proof');
  assert.equal(value.accountingMode, 'account-state-v2');
  assert.equal(value.hashScheme, manifest.hashScheme);
  assert.equal(value.accountScenario, expectedScenario);
  assert.deepEqual(value.browserErrors, []);
  assert.deepEqual(value.forbiddenRequests, []);
  assert.equal(value.cleanupErrors, undefined);
  assert.equal(value.liveLedger?.witnessReceived, false);
}
cleanBrowserEvidence(prior, scenario);
let result, factoryEvidence;
if (scenario === 'close') {
  // This specific interrupted phase retains the entire accepted Close chain.
  // Its remaining page work was an independent factory genesis demonstration.
  assert.equal(prior.ok, false);
  assert.equal(prior.error, 'Error: Bounded browser proof/ledger deadline');
  assert.equal(prior.fixtureStderr, '');
  assert.equal(prior.contract, undefined);
  result = prior.partial;
  assert.equal(result?.ok, undefined);
  assert.equal(result.runtimeFactory, undefined);
  assert.equal(result.stages.at(-1)?.name, 'production-runtime-factory');
  assert.equal(result.checks.length, 246);
  assert.equal(result.checks.at(-1), 'production factory compiles the verified immutable Wasm without a second network fetch');
  const answer = await json(resolve(root, 'answer/browser-evidence.json'));
  cleanBrowserEvidence(answer, 'answer');
  assert.equal(answer.ok, true);
  assert.equal(answer.contract?.ok, true);
  assert.equal(answer.contract.proofs.length, 10);
  assert.deepEqual(answer.contract.manifest, manifest);
  factoryEvidence = answer;
} else {
  assert.equal(prior.ok, true);
  assert.equal(prior.contract?.ok, true);
  assert.deepEqual(prior.contract.manifest, manifest);
  result = prior.contract;
  factoryEvidence = prior;
}
assert.equal(result.accountingMode, 'account-state-v2');
assert.equal(result.accountScenario, scenario);
const expectedProofs = scenario === 'close' ? 12 : 10;
assert.equal(result.proofs.length, expectedProofs);
assert.equal(result.peerReservations.length, 2);
assert.equal(prior.liveLedger.applies, expectedProofs);
assert.equal(result.checkpointRecovery?.followingActivationProved, true);
assert.equal(result.checkpointRecovery.privateCheckpointExported, false);
assert(result.checks.includes('native cmsg verifies original Active proofs after tuning and preserves their original release deadline'));
assert(result.checks.includes('Rust verifies browser-signed actual cmsg receipt'));

// This roster and issuer configuration were written by the host's native
// enrollment bridge, independently of the browser's public proof records.
const scenarioRoot = resolve(root, scenario);
const dirs = (await readdir(scenarioRoot)).filter(name => name.startsWith('live-ledger-'));
assert.equal(dirs.length, 1, 'one independently retained native enrollment required');
const retained = resolve(scenarioRoot, dirs[0]);
const trusted = await json(resolve(retained, 'enrollment.json'));
const config = await json(resolve(retained, 'config.json'));
const tunedPolicy = {...manifest.accountPolicy, abandonAfter:900};
assert.deepEqual(trusted.acceptedTimes, [100,300,600]);
assert.deepEqual(trusted.acceptedPolicies, [manifest.accountPolicy,tunedPolicy]);
assert.deepEqual(config.policy.account, tunedPolicy);
assert.equal(config.checkpoints.length, 1);
assert.equal(config.checkpoints[0].slot, 0);
assert.deepEqual(config.proofScope, {
  circuitDigest:Array.from(Buffer.from(manifest.circuitSha256,'hex')),
  verifyingKeyDigest:Array.from(Buffer.from(manifest.vkSha256,'hex')),
});
for (const proof of result.proofs) assert.deepEqual(proof.statement.enrollmentRoot, config.checkpoints[0].root);
assert.equal(prior.liveLedger.tuning.beforeProofIndex, scenario === 'close' ? 8 : 7);
assert.deepEqual(prior.liveLedger.tuning.policy, tunedPolicy);
const enrolled = {...trusted, synthetic:true, waitingPeriodTuning:prior.liveLedger.tuning,
  trust:{community_id:config.communityId, policy_digest:config.admissionPolicyDigest, issuer_public_key:config.issuerPublicKey}};
process.env.ACCOUNT_SCENARIO = scenario;

const factory = factoryEvidence.contract.runtimeFactory;
assert(factory?.record);
assert.equal(factory.manifestSha256, manifestSha256);
assert.equal(factory.privateWitnessExported, false);
assert.equal(factory.ledgerSubmitted, false);
assert.equal(factory.wasmNetworkFetches, 1);
assert.equal(factory.wasmBlobFetches, 1);
const evidence = {source:process.env.CI_COMMIT_SHA, reusedSource:source,
  reusedArtifactSha256:process.env.REUSE_ARTIFACT_SHA256, reusedBrowserEvidenceSha256:await digest(priorPath),
  manifestSha256, syntheticFixture:true,
  trustedNativeEnrollmentSha256:await digest(resolve(retained, 'enrollment.json')),
  trustedLedgerConfigSha256:await digest(resolve(retained, 'config.json')),
  trustedEnrollmentRoot:Buffer.from(config.checkpoints[0].root).toString('hex'),
  waitingPeriodTuning:prior.liveLedger.tuning,
  accountingMode:'account-state-v2', accountScenario:scenario, browserExecuted:false, browserComplete:prior.ok,
  proofsGenerated:0, priorBrowserError:prior.error ?? null, retainedBrowserChecks:result.checks.length,
  retainedPeerProofs:result.peerReservations.length, retainedLiveLedgerApplies:prior.liveLedger.applies,
  factoryEvidence:{scenario:factoryEvidence.accountScenario, source:factoryEvidence.source,
    browserEvidenceSha256:await digest(resolve(root, factoryEvidence.accountScenario, 'browser-evidence.json')),
    manifestSha256, browserComplete:true, proofGeneratedHere:false}, ok:false};
try {
  evidence.independent = await verifyResults(result, enrolled);
  evidence.ledger = await runRustAccountLedgerContract(result, enrolled);
  const runtimeConfig = resolve(process.env.ACCOUNTING_ARTIFACT_DIR, 'runtime-verifier-config.json');
  await writeFile(runtimeConfig, JSON.stringify({directory:resolve('public'), manifestSha256,
    limits:{maxProofBytes:20000,memoryPages:32768}},null,2)+'\n');
  evidence.runtimeVerifier = {...await verifyPublicProofRecords(await nodeArtifactOptions(runtimeConfig), [...result.proofs,factory.record]),
    scenarioAccountProofs:result.proofs.length, factoryProofs:1, factorySourceScenario:factoryEvidence.accountScenario};
  evidence.ok = true;
} catch (error) { evidence.error = String(error); process.exitCode = 1; }
await writeFile(resolve(process.env.ACCOUNTING_ARTIFACT_DIR, 'ledger-evidence.json'), JSON.stringify(evidence,null,2)+'\n');
console.log(JSON.stringify(evidence));
