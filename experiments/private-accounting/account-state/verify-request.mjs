// One trusted host invocation. No browser-selected files or remote proving.
import { readFile } from 'node:fs/promises';
import { createAccountVerifier } from './verify.mjs';

// Keep machine-readable stdout exclusively for the bounded verifier verdict.
console.log = (...args) => process.stderr.write(args.map(String).join(' ') + '\n');
let verifier;
try {
  if (process.argv.length !== 4) throw new Error('Trusted manifest and verified-enrollment paths required');
  const chunks = []; let length = 0;
  for await (const chunk of process.stdin) {
    length += chunk.length; if (length > 2_000_000) throw new Error('Request byte bound'); chunks.push(chunk);
  }
  const request = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (!request || Object.keys(request).length !== 3 || !['statement','proof','proofScope'].every(k => Object.hasOwn(request, k))) throw new Error('Verifier request field set');
  const trustedRaw = await readFile(process.argv[3]);
  if (trustedRaw.length > 4_000_000) throw new Error('Verified enrollment file bound');
  verifier = await createAccountVerifier(process.argv[2], JSON.parse(trustedRaw));
  const verdict = await verifier.verify(request);
  process.stdout.write(JSON.stringify(verdict) + '\n');
} catch (error) {
  process.stderr.write(String(error?.message ?? error) + '\n'); process.exitCode = 1;
} finally { await verifier?.destroy(); }
