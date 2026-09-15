// CI-only process boundary. All executable paths/arguments are selected by the
// trusted harness; JSON is stdin data, never shell text. No private witnesses.
import { spawn } from 'node:child_process';

export function nativeProcess(binary, args, input, active = new Set()) {
  const encoded = JSON.stringify(input);
  if (Buffer.byteLength(encoded) > 2_000_000) throw new Error('Native fixture input bound');
  const child = spawn(binary, args, { stdio: ['pipe','pipe','pipe'], detached: true });
  const completion = new Promise((resolve, reject) => {
    child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal }));
  });
  const kill = signal => { if (child.pid) { try { process.kill(-child.pid, signal); } catch {} } };
  const entry = { completion, kill }; active.add(entry);
  let output = '', stderr = '', bad = false;
  child.stdout.on('data', chunk => { output += chunk; if (output.length > 2_000_000) { bad = true; kill('SIGTERM'); } });
  child.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(-2048); });
  child.stdin.on('error', error => { if (error.code !== 'EPIPE') { bad = true; kill('SIGTERM'); } });
  const deadline = setTimeout(() => { bad = true; kill('SIGTERM'); }, 125_000);
  const force = setTimeout(() => kill('SIGKILL'), 130_000);
  child.stdin.end(encoded);
  return (async () => {
    try {
      const result = await completion;
      if (bad || result.signal) throw new Error('Native fixture resource bound');
      let parsed;
      try { parsed = JSON.parse(output); } catch { throw new Error('Native fixture malformed response: ' + stderr); }
      if (!parsed || typeof parsed.ok !== 'boolean' || ((result.code === 0) !== parsed.ok)) throw new Error('Native fixture exit/verdict mismatch');
      return parsed;
    } finally { clearTimeout(deadline); clearTimeout(force); active.delete(entry); }
  })();
}

export async function stopNativeProcesses(active) {
  const children = [...active]; children.forEach(child => child.kill('SIGTERM'));
  let force, bound;
  try {
    force = setTimeout(() => children.forEach(child => child.kill('SIGKILL')), 3000);
    await Promise.race([Promise.allSettled(children.map(child => child.completion)),
      new Promise((_, reject) => { bound = setTimeout(() => reject(new Error('Native fixture cleanup deadline')), 10_000); })]);
  } finally { clearTimeout(force); clearTimeout(bound); }
}
