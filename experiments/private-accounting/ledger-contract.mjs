// Durable storage contract. Crypto verification happens before entry; injected
// mutations below test storage checks, never claim cryptographic acceptance.
import { DatabaseSync } from 'node:sqlite';
import { fork } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { ExperimentalLedger, immutableStatement, ledgerRequest } from './ledger.mjs';

const flip = value => (value[0] === '0' ? '1' : '0') + value.slice(1);
const workerFile = fileURLToPath(new URL('./ledger-worker.mjs', import.meta.url));

function worker(path, now) {
  const child = fork(workerFile, [path, String(now)], { execArgv: [], stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
  let readyResolve, readyReject, doneResolve, doneReject, closedResolve, result, startReady = false, settled = false;
  const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  const done = new Promise((resolve, reject) => { doneResolve = resolve; doneReject = reject; });
  const closed = new Promise(resolve => { closedResolve = resolve; });
  // A child may fail before the caller awaits the second promise.
  ready.catch(() => {}); done.catch(() => {});
  const abort = error => { readyReject(error); doneReject(error); child.kill('SIGKILL'); };
  const timeout = setTimeout(() => abort(new Error('Ledger worker deadline')), 15000);
  child.stderr.on('data', () => {}); // SQLite experimental warnings are not evidence.
  child.once('error', abort);
  child.on('message', message => {
    if (message?.type === 'ready' && !startReady) { startReady = true; readyResolve(); }
    else if (message?.type === 'result' && startReady && !result) result = message;
    else abort(new Error('Ledger worker protocol'));
  });
  child.once('close', (code, signal) => {
    clearTimeout(timeout); settled = true; closedResolve();
    if (!startReady || code !== 0 || signal) { const error = new Error('Ledger worker failed'); readyReject(error); doneReject(error); }
    else doneResolve(result ?? null);
  });
  return {
    ready, done, pid: child.pid,
    apply(request, crashAfterCommit = false) {
      child.send({ type: 'apply', request, crashAfterCommit }, error => { if (error) abort(error); });
    },
    async stop() {
      if (!settled) child.kill('SIGKILL');
      await closed;
    },
  };
}

export async function runLedgerContract(verifiedStatements) {
  if (!Array.isArray(verifiedStatements) || verifiedStatements.length !== 2) throw new Error('Expected two verified statements');
  const statements = verifiedStatements.map(immutableStatement);
  if (statements[0].owner === statements[1].owner || statements[0].now !== statements[1].now) throw new Error('Fixture owner/time mismatch');
  const directory = await mkdtemp(join(tmpdir(), 'cfrm-ledger-'));
  const checks = [], workers = [];
  let ledger;
  const check = (condition, label) => { if (!condition) throw new Error(label); checks.push(label); };
  const rejects = (operation, code, label) => {
    let seen;
    try { operation(); } catch (error) { seen = error.message; }
    check(seen === 'AccountingLedger:' + code, label);
  };
  const open = (path, now) => new ExperimentalLedger(path, { now });
  const status = (db, s) => db.status(s.community, s.owner);
  const first = statements[0], second = statements[1], now = first.now;
  const path = join(directory, 'ledger.sqlite');
  try {
    ledger = open(path, now);
    for (const statement of statements) ledger.seedSynthetic(statement);
    rejects(() => ledger.seedSynthetic(first), 'GenesisExists', 'storage: synthetic genesis cannot be repeated');
    const request = ledgerRequest(first, 0);
    check(Object.isFrozen(request) && Object.isFrozen(request.statement), 'storage: public request and statement snapshots are immutable');
    for (const field of ['community', 'owner', 'checkpoint', 'circuitSha256', 'verificationKeySha256']) {
      const mutated = ledgerRequest({ ...first, [field]: flip(first[field]) }, 0);
      rejects(() => ledger.accept(mutated), ['community', 'owner'].includes(field) ? 'UnknownAccount' : 'ScopeMismatch',
        'storage-only injection: changed ' + field + ' rejected');
    }
    const scheme = first.hashScheme === 'sha256-v1' ? 'poseidon2-bn254-fixed-128-v1' : 'sha256-v1';
    rejects(() => ledger.accept(ledgerRequest({ ...first, hashScheme: scheme }, 0)), 'ScopeMismatch', 'storage-only injection: changed hash scheme rejected');
    rejects(() => ledger.accept(ledgerRequest(first, 1)), 'StateConflict', 'storage: matching commitment with wrong version rejected');
    rejects(() => ledger.accept(ledgerRequest({ ...first, old: flip(first.old) }, 0)), 'StateConflict', 'storage-only injection: matching version with wrong commitment rejected');
    rejects(() => ledger.accept(ledgerRequest({ ...first, now: now + 1 }, 0)), 'StatementTime', 'storage-only injection: statement time differs from trusted fixture clock');
    rejects(() => ledgerRequest(first, Number.MAX_SAFE_INTEGER), 'VersionBounds', 'storage: successor version overflow fails closed');
    const accepted = ledger.accept(request);
    check(!accepted.cached && JSON.parse(accepted.response).nextVersion === 1, 'storage: actual verified statement commits one successor');
    check(ledger.accept(request).response === accepted.response, 'storage: exact request retry returns identical cached response bytes');
    for (const field of ['next', 'marker', 'proofSha256', 'publicInputsSha256', 'checkpoint']) {
      rejects(() => ledger.accept(ledgerRequest({ ...first, [field]: flip(first[field]) }, 0, request.requestId)),
        'RequestIdReuse', 'storage-only injection: reused request ID with changed ' + field + ' rejected');
    }
    rejects(() => ledger.accept(ledgerRequest(first, 1, request.requestId)), 'RequestIdReuse', 'storage: changed version under accepted request ID rejected');
    rejects(() => ledger.accept(ledgerRequest(first, 0)), 'StateConflict', 'storage: verified proof replay with a new random request ID rejected');
    // Inject a hypothetical later statement only at the trusted STORAGE boundary
    // to isolate marker uniqueness after satisfying the version/old-state checks.
    rejects(() => ledger.accept(ledgerRequest({ ...first, old: first.next, next: flip(first.next) }, 1)),
      'MarkerSpent', 'storage-only injection: consumed owner marker cannot support a later successor');
    const saved = status(ledger, first);
    check(saved.version === 1 && saved.commitment === first.next && saved.markers === 1 && saved.requests === 1,
      'storage: rejected retries leave exactly one state, marker and cached acceptance');
    ledger.close(); ledger = open(path, now);
    const retried = ledger.accept(request);
    check(retried.cached && retried.response === accepted.response, 'storage: reopen preserves exact acceptance and retry identity');

    // Force a failure after marker insertion and before account update. The
    // ledger exposes no fault-injection callback; this is an isolated SQL fixture.
    const fault = new DatabaseSync(path);
    try { fault.exec("CREATE TRIGGER fixture_abort BEFORE UPDATE ON accounts BEGIN SELECT RAISE(ABORT, 'fixture-write-failure'); END;"); }
    finally { fault.close(); }
    const secondRequest = ledgerRequest(second, 0);
    let failed = false;
    try { ledger.accept(secondRequest); } catch { failed = true; }
    check(failed, 'storage fault injection: write failure aborts transaction');
    const rolledBack = status(ledger, second);
    check(rolledBack.version === 0 && rolledBack.commitment === second.old && rolledBack.markers === 0 && rolledBack.requests === 0,
      'storage fault injection: failed transaction exposes no partial marker/state/cache');
    const repair = new DatabaseSync(path);
    try { repair.exec('DROP TRIGGER fixture_abort;'); } finally { repair.close(); }
    ledger.close(); ledger = undefined;

    const lostReply = worker(path, now); workers.push(lostReply);
    await lostReply.ready; lostReply.apply(secondRequest, true);
    check(await lostReply.done === null, 'storage: independent process exits after commit without returning acceptance');
    ledger = open(path, now);
    const recovered = ledger.accept(secondRequest);
    check(recovered.cached && JSON.parse(recovered.response).requestDigest === secondRequest.requestDigest,
      'storage: lost-response recovery finds exact committed request after process restart');
    check(status(ledger, second).markers === 1 && status(ledger, second).requests === 1,
      'storage: lost-response retry does not consume another marker');
    ledger.close(); ledger = open(path, now + 1);
    check(ledger.accept(request).response === accepted.response, 'storage: cached acceptance survives a later trusted clock value');
    rejects(() => open(path, now), 'ClockRollback', 'storage: persisted clock high-water rejects startup rollback');
    ledger.close(); ledger = undefined;

    // Same real verified successor, distinct requests. This is process/storage
    // concurrency evidence, not two freshly proved divergent successor states.
    const racePath = join(directory, 'race.sqlite');
    ledger = open(racePath, now); ledger.seedSynthetic(first); ledger.close(); ledger = undefined;
    const left = worker(racePath, now), right = worker(racePath, now); workers.push(left, right);
    await Promise.all([left.ready, right.ready]);
    check(left.pid !== right.pid, 'storage: competing requests run in distinct operating-system processes');
    const leftRequest = ledgerRequest(first, 0), rightRequest = ledgerRequest(first, 0);
    check(leftRequest.requestId !== rightRequest.requestId, 'storage: competitors have independent random retry IDs');
    left.apply(leftRequest); right.apply(rightRequest);
    const outcomes = await Promise.all([left.done, right.done]);
    check(outcomes.filter(result => result?.ok && !result.cached).length === 1
      && outcomes.filter(result => result?.code === 'AccountingLedger:StateConflict').length === 1,
      'storage: concurrent independent processes accept at most one successor');
    const winner = outcomes[0].ok ? leftRequest : rightRequest;
    ledger = open(racePath, now);
    check(status(ledger, first).version === 1 && status(ledger, first).markers === 1 && status(ledger, first).requests === 1,
      'storage: concurrent winner atomically owns state, marker and acceptance');
    check(ledger.accept(winner).cached, 'storage: concurrent winner remains retryable after both workers exit');
    ledger.close(); ledger = undefined;

    const corruptPath = join(directory, 'invalid-version.sqlite');
    ledger = open(corruptPath, now); ledger.seedSynthetic(first); ledger.close(); ledger = undefined;
    const corrupt = new DatabaseSync(corruptPath);
    try { corrupt.exec('PRAGMA ignore_check_constraints=ON; UPDATE accounts SET version=-1;'); }
    finally { corrupt.close(); }
    rejects(() => open(corruptPath, now), 'DurableVersionOrClock', 'storage fault injection: invalid durable version rejected on startup');
    return { checks, backend: 'node:sqlite / SQLite WAL synchronous=FULL',
      verifiedStatementCount: statements.length, independentWorkerCount: workers.length,
      race: 'same cryptographically verified successor, independent random request IDs in two processes',
      genesis: 'synthetic pre-reserved states; genesis and reservation proofs remain unimplemented',
      scope: 'immutable owner/community/scheme/circuit/checkpoint fixture; no policy/checkpoint migration',
      recovery: 'process exit/reopen evidence; not a power-loss or malicious-operator rollback guarantee' };
  } finally {
    ledger?.close();
    await Promise.all(workers.map(child => child.stop()));
    await rm(directory, { recursive: true, force: true });
  }
}
