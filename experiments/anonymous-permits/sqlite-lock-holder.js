// Synthetic test worker only; no service, external input or persistent process.
import { DatabaseSync } from 'node:sqlite';
import { parentPort, workerData } from 'node:worker_threads';

const shared = new Int32Array(workerData.shared);
const db = new DatabaseSync(workerData.path);
let transactionOpen = false;
try {
  db.exec('PRAGMA busy_timeout=5000');
  db.exec('BEGIN IMMEDIATE');
  transactionOpen = true;
  Atomics.store(shared, 2, 1);
  parentPort.postMessage('locked');
  // A bounded synchronization wait, not a timing sleep. The test signals only
  // after the issuer's pre-check and immediately before its real ledger call.
  if (Atomics.wait(shared, 0, 0, 15_000) === 'timed-out') {
    throw new Error('The test did not release the SQLite writer');
  }
  Atomics.store(shared, 1, workerData.releasedAt);
  db.exec('COMMIT');
  transactionOpen = false;
  Atomics.store(shared, 2, 2);
} finally {
  if (transactionOpen) db.exec('ROLLBACK');
  db.close();
  parentPort.close();
}
