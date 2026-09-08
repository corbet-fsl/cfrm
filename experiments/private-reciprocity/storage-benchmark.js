import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openAcknowledgementLedger } from './acknowledgement.js';

// Storage-only benchmark: these are explicitly synthetic scalar records, not
// 10,000 freshly proved acknowledgements or a cryptographic throughput claim.
const directory = mkdtempSync(join(tmpdir(), 'cfrm-ack-storage-'));
const store = openAcknowledgementLedger(join(directory, 'ack.sqlite'));
try {
  const empty = store.counts();
  const context = { scope: '1', notBefore: 1, expiresAt: 1000 };
  for (let i = 1; i <= 10000; i++) store.accept(context, String(i), () => 2);
  const filled = store.counts();
  console.log(JSON.stringify({ measurement: 'synthetic-nullifier-storage', empty, filled,
    incrementalPageBytesPerRecord: (filled.sqlitePageBytes - empty.sqlitePageBytes) / 10000 }));
} finally {
  store.close();
  rmSync(directory, { recursive: true, force: true });
}
