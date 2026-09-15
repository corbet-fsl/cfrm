// Real cmsg owner signatures -> Rust ledger -> independently pinned BB verifier.
// Test-only operator identity/clock; no witness openings cross this boundary.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { appendFile, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createHash, createPrivateKey, createPublicKey, verify as verifyEd25519 } from 'node:crypto';

const sha = bytes => createHash('sha256').update(bytes).digest();
const fromHex = value => {
  if (typeof value !== 'string' || !/^(?:[0-9a-f]{2})+$/.test(value)) throw new Error('Canonical hex required');
  return Buffer.from(value, 'hex');
};
const u64 = n => { const bytes = Buffer.alloc(8); bytes.writeBigUInt64BE(BigInt(n)); return bytes; };

export async function runRustAccountLedgerContract(result, enrolled) {
  const binary = process.env.ACCOUNTING_LEDGER_FIXTURE;
  const artifactRoot = process.env.ACCOUNTING_ARTIFACT_DIR;
  if (!binary || !artifactRoot || !Array.isArray(result.proofs) || result.proofs.length < 4) {
    throw new Error('Real ledger fixture and chronological public proofs required');
  }
  await mkdir(artifactRoot, { recursive: true });
  const dir = await mkdtemp(resolve(artifactRoot, 'rust-account-ledger-'));
  const manifestPath = resolve('public/manifest.json');
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  const scope = { circuitDigest: Array.from(fromHex(manifest.circuitSha256)),
    verifyingKeyDigest: Array.from(fromHex(manifest.vkSha256)) };
  // Returned by the independently retained native fixture, never taken from a
  // browser-supplied roster/root or from a proof's claimed configuration.
  assert.equal(enrolled.synthetic, true);
  assert.deepEqual(enrolled.acceptedTimes, [100,300,600]);
  const tunedPolicy = { ...manifest.accountPolicy, abandonAfter: 900 };
  assert.deepEqual(enrolled.acceptedPolicies, [manifest.accountPolicy, tunedPolicy]);
  const tuningIndex = process.env.ACCOUNT_SCENARIO === 'answer' ? 7 : process.env.ACCOUNT_SCENARIO === 'close' ? 8 : -1;
  assert.ok(tuningIndex > 0);
  assert.equal(enrolled.waitingPeriodTuning?.beforeProofIndex, tuningIndex);
  assert.deepEqual(enrolled.waitingPeriodTuning.policy, tunedPolicy);
  assert.equal(enrolled.waitingPeriodTuning.tuning.revision, 1);
  assert.equal(enrolled.waitingPeriodTuning.tuning.seconds, 900);
  const trustedPath = resolve(dir, 'trusted-enrollment.json');
  await writeFile(trustedPath, JSON.stringify({community: enrolled.community,
    entries: enrolled.entries, acceptedTimes: enrolled.acceptedTimes, acceptedPolicies: enrolled.acceptedPolicies}));
  const { createAccountVerifier } = await import('./verify.mjs');
  const verifier = await createAccountVerifier(manifestPath, {
    community: enrolled.community, entries: enrolled.entries, acceptedTimes: enrolled.acceptedTimes, acceptedPolicies: enrolled.acceptedPolicies,
  });
  let root;
  try { root = Array.from(Buffer.from(verifier.checkpoint.root.toString(16).padStart(64,'0'), 'hex')); }
  finally { await verifier.destroy(); }
  const configPath = resolve(dir, 'config.json');
  const database = resolve(dir, 'accounts.sqlite');
  const trust = enrolled.trust;
  const config = { communityId: trust.community_id, admissionPolicyDigest: trust.policy_digest,
    issuerPublicKey: trust.issuer_public_key,
    policy: { account: manifest.accountPolicy, maxAuthorizationSeconds: 100,
      maxProofBytes: 1_000_000, checkpointPeriodSeconds: 1000 },
    proofScope: scope, checkpoints: [{slot: 0, root}] };
  await writeFile(configPath, JSON.stringify(config));
  const args = [configPath, database, resolve('account-state/verify-request.mjs'), manifestPath,
    trustedPath, 'account-state-v2'];
  const checks = []; let childProcesses = 0;
  const checked = (condition, message) => { assert.ok(condition, message); checks.push(message); };
  async function invoke(input, drop = false) {
    const invocation = ++childProcesses, began = performance.now();
    const child = spawn(binary, drop ? [...args, 'drop-response'] : args,
      {stdio:['pipe','pipe','pipe'], detached:true});
    let stdout = '', stderr = '', timedOut = false, oversized = false;
    const kill = signal => { try { process.kill(-child.pid, signal); } catch {} };
    const deadline = setTimeout(() => { timedOut = true; kill('SIGTERM'); }, 125_000);
    const force = setTimeout(() => kill('SIGKILL'), 130_000);
    child.stdout.on('data', bytes => { stdout += bytes; if (stdout.length > 1_000_000) { oversized = true; kill('SIGTERM'); } });
    child.stderr.on('data', bytes => { stderr = (stderr + bytes).slice(-16_384); });
    const completed = new Promise((accept, reject) => {
      child.once('error', reject); child.once('close', (code, signal) => accept({code,signal}));
      child.stdin.on('error', error => { if (error.code !== 'EPIPE') reject(error); });
    });
    child.stdin.end(JSON.stringify(input));
    try {
      const {code,signal} = await completed;
      if (timedOut || oversized || signal) throw new Error('Native ledger fixture deadline/output bound: '+stderr);
      if (drop && code === 0 && stdout === '') return {dropped:true};
      let response;
      try { response = JSON.parse(stdout); } catch { throw new Error('Native ledger fixture response: '+stderr); }
      if ((code === 0) !== (response.ok === true)) throw new Error('Native ledger fixture exit/response mismatch: '+stderr);
      await appendFile(resolve(dir, 'fixture-outcomes.jsonl'), JSON.stringify({invocation,
        action:input.action, ok:response.ok, error:response.error, elapsedMs:performance.now()-began})+'\n');
      return response;
    } finally { clearTimeout(deadline); clearTimeout(force); }
  }
  const originals = new Map(enrolled.entries.map(entry => [entry.memberId, entry.originalDelegation]));
  function command(record, alternate = false) {
    const auth = alternate ? record.alternateRequestAuthorization : record.requestAuthorization;
    if (!auth) throw new Error('Missing contemporaneous real cmsg owner signature');
    const owner = Buffer.from(record.statement.owner).toString('base64url');
    const d = originals.get(owner);
    if (!d) throw new Error('Proof owner missing independently verified root');
    assert.deepEqual(auth.circuitDigest, scope.circuitDigest);
    assert.deepEqual(auth.verifyingKeyDigest, scope.verifyingKeyDigest);
    return { action:'apply', grant:d.admission, authorization:d.authorization,
      request:{ statement:record.statement, requestId:auth.requestId, proofScope:scope,
        chatPublicKey:auth.chatPublicKey, issuedAt:auth.issuedAt, expiresAt:auth.expiresAt,
        proof:Array.from(fromHex(record.proof)), signature:auth.signature }, now:record.statement.now };
  }
  const operator = createPublicKey(createPrivateKey({key:Buffer.concat([
    Buffer.from('302e020100300506032b657004220420','hex'), Buffer.alloc(32,0x4c)]), format:'der', type:'pkcs8'}));
  function verifyAcceptance(acceptance, input, prepared) {
    assert.deepEqual(acceptance.statement, input.request.statement);
    assert.deepEqual(acceptance.requestId, input.request.requestId);
    assert.deepEqual(acceptance.proofScope, scope);
    assert.equal(acceptance.acceptedAt, input.now);
    const digest = sha(Buffer.concat([fromHex(prepared.signingBytes),Buffer.from(input.request.signature,'base64url')]));
    assert.deepEqual(acceptance.requestDigest, Array.from(digest));
    const bytes = Buffer.concat([Buffer.from('cfrm.account.acceptance.v1\0'),
      Buffer.from(acceptance.requestId),digest,Buffer.from(scope.circuitDigest),Buffer.from(scope.verifyingKeyDigest),
      u64(acceptance.acceptedAt),fromHex(prepared.statementDigest)]);
    assert.ok(verifyEd25519(null,bytes,operator,Buffer.from(acceptance.signature,'base64url')));
  }
  const started = performance.now();
  let raced = false, last;
  for (let i = 0; i < result.proofs.length; i++) {
    const record = result.proofs[i], input = command(record);
    assert.deepEqual(record.statement.policy, i < tuningIndex ? manifest.accountPolicy : tunedPolicy);
    if (i === tuningIndex) {
      // Host-recorded fixed fixture action; a proof's policy cannot authorize
      // its own runtime change. The real ledger performs the durable CAS.
      const tuned = await invoke({action:'tuneWaitingPeriod',expectedRevision:0,seconds:900,now:100});
      checked(tuned.ok, 'actual durable waiting-period tuning precedes the first changed-policy proof');
      assert.deepEqual(tuned.value.policy,tunedPolicy);
      assert.deepEqual(tuned.value.tuning,enrolled.waitingPeriodTuning.tuning);
      const oldRetry = await invoke(last.input);
      checked(oldRetry.ok, 'exact accepted old-policy retry remains recoverable after tuning');
      assert.deepEqual(oldRetry.value,last.acceptance);
      checked(!(await invoke(command(result.proofs[i-1],true))).ok, 'unused signed old-policy request cannot commit after tuning');
    }
    const prepared = await invoke({action:'prepare', request:input.request});
    assert.equal(prepared.ok, true);
    assert.equal(prepared.value.statementDigest, Buffer.from(record.requestAuthorization.statementDigest).toString('hex'));
    assert.equal(prepared.value.proofDigest, Buffer.from(record.requestAuthorization.proofDigest).toString('hex'));
    let response, acceptedInput = input;
    if (!record.statement.genesis && !raced) {
      const alternate = command(record,true);
      assert.notDeepEqual(input.request.requestId,alternate.request.requestId);
      const outcomes = await Promise.all([invoke(input),invoke(alternate)]);
      checked(outcomes.filter(value => value.ok).length === 1 && outcomes.filter(value => value.error === 'Replay').length === 1,
        'independent Rust processes accept exactly one of two valid owner-signed successors: '+
          JSON.stringify(outcomes.map(({ok,error}) => ({ok,error}))));
      const winner = outcomes[0].ok ? 0 : 1; response = outcomes[winner]; acceptedInput = winner ? alternate : input;
      raced = true;
    } else if (i === result.proofs.length - 1) {
      checked((await invoke(input,true)).dropped === true, 'Rust process exits after durable commit before response');
      response = await invoke(input);
      checked(response.ok, 'exact retry recovers committed acceptance after process exit');
    } else {
      response = await invoke(input);
    }
    assert.equal(response.ok, true, 'real Rust ledger accepts chronological proof '+i+': '+response.error);
    const winnerPrepared = acceptedInput === input ? prepared.value
      : (await invoke({action:'prepare',request:acceptedInput.request})).value;
    verifyAcceptance(response.value,acceptedInput,winnerPrepared);
    checks.push('actual cmsg signature, BB proof and durable acceptance '+i);
    if (record.statement.genesis) {
      const duplicate = await invoke(command(record,true));
      checked(duplicate.error === 'Replay', 'second independently signed genesis is rejected '+i);
    }
    last = {input:acceptedInput,acceptance:response.value};
  }
  checked(raced, 'real proof chain exercised independent-process race');
  // Last fixture transition belongs to the still-eligible original recipient.
  const retry = structuredClone(last.input); retry.now = retry.request.expiresAt + 1;
  assert.ok(retry.now < retry.grant.expiresAt && retry.now < retry.authorization.expiresAt);
  const retried = await invoke(retry);
  checked(retried.ok, 'accepted request remains recoverable after request expiry');
  assert.deepEqual(retried.value,last.acceptance);
  const altered = structuredClone(retry); altered.request.proof[0] ^= 1;
  checked((await invoke(altered)).error === 'Signature', 'changed proof cannot reuse cached owner authorization');
  // Direct real-verifier check ensures a malformed proof cannot pass the Rust
  // provider boundary even when request-signature checks are outside this call.
  const invalid = Array.from(fromHex(result.proofs[0].proof)); invalid[0] ^= 1;
  checked((await invoke({action:'verify',statement:result.proofs[0].statement,proof:invalid})).error === 'CryptoProvider',
    'Rust verifier process rejects corrupted actual proof');
  return {checks,childProcesses,elapsedMs:performance.now()-started,
    verifier:'pinned Node/BB verifier invoked by Rust, same cryptographic engine as browser',
    genesis:'actual proved empty accounts; lifetime uniqueness enforced by Rust SQLite ledger',
    clock:'explicit synthetic fixture times; time races are covered separately by Rust unit tests',
    witnessReceived:false};
}
