// CI-only reuse of hash-pinned public evidence. No browser execution is claimed.
import assert from 'node:assert/strict';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { runRustAccountLedgerContract } from './ledger-contract.mjs';

const root = process.env.REUSE_ARTIFACT_DIR;
const manifest = JSON.parse(await readFile('public/manifest.json'));
const digest = async path => createHash('sha256').update(await readFile(path)).digest('hex');
assert.equal(manifest.circuitSourceSha256, await digest('account-state/src/main.nr'));
assert.equal(manifest.indexedSourceSha256, await digest('account-state/src/indexed.nr'));
assert.deepEqual(manifest.accountPolicy, JSON.parse(process.env.ACCOUNT_POLICY_JSON));
const prior = JSON.parse(await readFile(resolve(root, 'answer/browser-evidence.json')));
assert.equal(prior.contract.ok, true);
assert.equal(prior.accountScenario, 'answer');
const dirs = (await readdir(resolve(root, 'answer'))).filter(name => name.startsWith('rust-account-ledger-'));
assert.equal(dirs.length, 1, 'one independently retained native enrollment required');
const retained = resolve(root, 'answer', dirs[0]);
const trusted = JSON.parse(await readFile(resolve(retained, 'trusted-enrollment.json')));
const config = JSON.parse(await readFile(resolve(retained, 'config.json')));
const enrolled = {...trusted, synthetic:true, trust:{community_id:config.communityId,
  policy_digest:config.admissionPolicyDigest, issuer_public_key:config.issuerPublicKey}};
const evidence = {source:process.env.CI_COMMIT_SHA, reusedSource:prior.source,
  reusedArtifactSha256:process.env.REUSE_ARTIFACT_SHA256, browserExecuted:false, ok:false};
try {
  evidence.ledger = await runRustAccountLedgerContract(prior.contract, enrolled);
  evidence.ok = true;
} catch (error) { evidence.error = String(error); process.exitCode = 1; }
await writeFile(resolve(process.env.ACCOUNTING_ARTIFACT_DIR, 'ledger-evidence.json'), JSON.stringify(evidence,null,2));
console.log(JSON.stringify(evidence));
