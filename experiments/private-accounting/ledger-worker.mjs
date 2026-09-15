// Private IPC worker for storage-concurrency evidence, not a proof verifier or
// public service. Parent supplies already verified immutable public statements.
import { ExperimentalLedger } from './ledger.mjs';

let ledger;
try {
  ledger = new ExperimentalLedger(process.argv[2], { now: Number(process.argv[3]) });
  process.send({ type: 'ready' });
} catch {
  process.send?.({ type: 'startup-failure' }, () => process.exit(1));
}
process.on('disconnect', () => { ledger?.close(); process.exit(0); });
process.once('message', message => {
  let outcome;
  try {
    if (!ledger || message?.type !== 'apply' || typeof message.crashAfterCommit !== 'boolean') throw new Error('WorkerProtocol');
    const result = ledger.accept(message.request);
    // Simulate a process disappearing after durable commit but before replying.
    if (message.crashAfterCommit) process.exit(0);
    outcome = { type: 'result', ok: true, ...result };
  } catch (error) {
    outcome = { type: 'result', ok: false,
      code: /^AccountingLedger:[A-Za-z]+$/.test(error.message) ? error.message : 'StorageFailure' };
  }
  ledger?.close();
  process.send?.(outcome, () => process.disconnect());
});
