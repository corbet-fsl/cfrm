// One bounded worker. Only public proofs enter stdin. Configuration is operator-owned.
import { open } from 'node:fs/promises';
import { resolve, isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createAccountVerifier } from './runtime.mjs';

async function boundedFile(path, maximum) {
  const file = await open(path, 'r');
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size > maximum) throw new Error('Artifact file bound');
    const data = new Uint8Array(stat.size + 1);
    let offset = 0;
    while (offset < data.length) {
      const { bytesRead } = await file.read(data, offset, data.length - offset, null);
      if (!bytesRead) break; offset += bytesRead;
    }
    if (offset !== stat.size) throw new Error('Artifact changed while reading');
    return data.slice(0, offset);
  } finally { await file.close(); }
}

export async function nodeArtifactOptions(configPath) {
  if (!isAbsolute(configPath)) throw new Error('Absolute trusted configuration path required');
  const config = JSON.parse(new TextDecoder().decode(await boundedFile(configPath, 65536)));
  if (!config || Object.keys(config).some(k => !['directory','manifestSha256','limits'].includes(k))
      || typeof config.directory !== 'string' || !isAbsolute(config.directory)) throw new Error('Trusted artifact configuration');
  const directory = config.directory;
  return { manifestBytes: await boundedFile(resolve(directory, 'manifest.json'), 1024 * 1024),
    manifestSha256: config.manifestSha256, limits: config.limits,
    readArtifact(name, maximum) {
      if (!['circuit.json','vk.bin','setup/g1.dat','setup/g2.dat'].includes(name)) throw new Error('Artifact name');
      return boundedFile(resolve(directory, name), maximum);
    } };
}

export async function verifyFromStdin(configPath, input = process.stdin, output = process.stdout) {
  const chunks = []; let size = 0, verifier;
  for await (const chunk of input) {
    size += chunk.length; if (size > 3 * 1024 * 1024) throw new Error('Proof request bound'); chunks.push(chunk);
  }
  const record = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  try {
    verifier = await createAccountVerifier(await nodeArtifactOptions(configPath));
    const result = await verifier.verify(record);
    output.write(JSON.stringify(result) + '\n');
  } finally { await verifier?.destroy(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  // Backend diagnostics must never corrupt the bounded verdict channel.
  console.log = () => {};
  try {
    if (process.argv.length !== 3) throw new Error('Configuration argument required');
    await verifyFromStdin(process.argv[2]);
  } catch { process.exitCode = 1; }
}
