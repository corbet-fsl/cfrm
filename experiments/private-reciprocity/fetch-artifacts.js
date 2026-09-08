import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
const manifest = JSON.parse(await readFile(new URL('./artifacts.json', import.meta.url), 'utf8'));
await mkdir(new URL('./.artifacts/', import.meta.url), { recursive: true });
for (const [kind, artifact] of Object.entries(manifest.files)) {
  const response = await fetch(artifact.url);
  if (!response.ok || !response.body) throw new Error('Artifact download rejected');
  const chunks = [];
  let length = 0;
  for await (const chunk of response.body) {
    length += chunk.length;
    if (length > artifact.bytes) throw new Error('Artifact exceeds pinned size');
    chunks.push(chunk);
  }
  const bytes = Buffer.concat(chunks);
  if (length !== artifact.bytes || createHash('sha256').update(bytes).digest('hex') !== artifact.sha256) {
    throw new Error('Artifact differs from pinned digest');
  }
  await writeFile(new URL(`./.artifacts/semaphore.${kind}`, import.meta.url), bytes);
  console.log(JSON.stringify({ kind, bytes: length, sha256: artifact.sha256 }));
}
