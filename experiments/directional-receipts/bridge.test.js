import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { NativeBridge } from './composition-driver.js';

// Fixed synthetic protocol peer. It waits for stdin EOF before its terminal
// action, so the valid final RPC is definitely observed before close() begins.
// No shell, user payload, external service or unowned process is involved.
const childSource = mode => `#!${process.execPath}
const mode = ${JSON.stringify(mode)};
let buffer = '';
let replied = false;
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => {
  buffer += chunk;
  if (buffer.length > 32768) process.exit(20);
  const newline = buffer.indexOf('\\n');
  if (newline < 0) return;
  if (replied || newline !== buffer.length - 1) process.exit(21);
  let request;
  try { request = JSON.parse(buffer.slice(0, newline)); }
  catch { process.exit(22); }
  replied = true;
  process.stdout.write(JSON.stringify({id: request.id, ok: true, result: {accepted: true}}) + '\\n');
});
process.stdin.on('end', () => {
  if (!replied) process.exit(23);
  if (mode === 'nonzero') process.exit(17);
  if (mode === 'signal') { process.kill(process.pid, 'SIGTERM'); return; }
  if (mode === 'trailing') { process.stdout.write('fixed malformed trailer\\n'); return; }
});
`;

function ownedBridge(t, mode) {
  const directory = mkdtempSync(join(tmpdir(), 'cfrm-bridge-contract-'));
  const executable = join(directory, 'synthetic-peer');
  let bridge;
  t.after(async () => {
    try {
      // The test body checks success/rejection. Cleanup always reaps the exact
      // owned child, including after an intentionally failed assertion.
      if (bridge) await bridge.close().catch(() => {});
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });
  writeFileSync(executable, childSource(mode), { mode: 0o700 });
  const previous = process.env.CMSG_RELEASE_HARNESS;
  try {
    process.env.CMSG_RELEASE_HARNESS = executable;
    bridge = new NativeBridge();
  } finally {
    if (previous === undefined) delete process.env.CMSG_RELEASE_HARNESS;
    else process.env.CMSG_RELEASE_HARNESS = previous;
  }
  return bridge;
}

const options = { timeout: 10000 };
async function finalSuccess(bridge) {
  const response = await bridge.call('probe', {});
  assert.ok(response?.accepted === true && Object.keys(response).length === 1,
    'The final synthetic RPC succeeds before shutdown behavior is tested');
}

test('bridge shutdown accepts a clean exit after its final successful response', options, async t => {
  const bridge = ownedBridge(t, 'clean');
  await finalSuccess(bridge);
  await bridge.close();
  await bridge.close();
});

test('bridge shutdown rejects a nonzero child exit after its final successful response', options, async t => {
  const bridge = ownedBridge(t, 'nonzero');
  await finalSuccess(bridge);
  await assert.rejects(bridge.close(), 'A final response does not override the child failure');
  await assert.rejects(bridge.close(), 'Repeated cleanup preserves the same terminal failure');
});

test('bridge shutdown rejects a child signal after its final successful response', options, async t => {
  const bridge = ownedBridge(t, 'signal');
  await finalSuccess(bridge);
  await assert.rejects(bridge.close(), 'A final response does not override signal termination');
});

test('bridge shutdown rejects trailing malformed output after its final successful response', options, async t => {
  const bridge = ownedBridge(t, 'trailing');
  await finalSuccess(bridge);
  await assert.rejects(bridge.close(), 'Late protocol failure remains observable after the child is reaped');
});
