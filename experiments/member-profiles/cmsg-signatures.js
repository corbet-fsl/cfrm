// Real cross-runtime signing test. Requires the separately built public Rust
// example; never imports a private key or asks cmsg to sign arbitrary bytes.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { once } from 'node:events';
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';

if (!process.env.CMSG_PROFILE_SIGNER) throw new Error('Explicit CMSG_PROFILE_SIGNER executable required');
const child = spawn(process.env.CMSG_PROFILE_SIGNER, [], { stdio: ['pipe', 'pipe', 'pipe'] });
const completion = once(child, 'close');
const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
let errorOutput = '';
child.stderr.on('data', bytes => { errorOutput += bytes.toString(); });
const timer = setTimeout(() => child.kill(), 30000); timer.unref();
const hash = bytes => createHash('sha256').update(bytes).digest('base64url');
const id = () => randomBytes(32).toString('base64url');
const encoded = value => Buffer.from(JSON.stringify(value));
try {
  const first = await lines.next();
  assert.equal(first.done, false, errorOutput);
  const { chatPublicKey } = JSON.parse(first.value);
  const issuer = generateKeyPairSync('ed25519');
  const issuerPublic = Buffer.from(issuer.publicKey.export({ format: 'jwk' }).x, 'base64url');
  const communityId = 'community.example';
  const policyDigest = id();
  const now = 1800000000;
  const grant = { version: 1, issuerKeyId: hash(issuerPublic), communityId, memberId: id(),
    chatPublicKey, policyDigest, issuedAt: now, expiresAt: now + 120 };
  grant.signature = sign(null, encoded(['cvld.admission.v1', grant.issuerKeyId, grant.communityId,
    grant.memberId, grant.chatPublicKey, grant.policyDigest, grant.issuedAt, grant.expiresAt]), issuer.privateKey).toString('base64url');
  const challenge = { version: 1, communityId, ownerMemberId: grant.memberId, ownerChatPublicKey: chatPublicKey,
    onionHost: 'pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion', onionPort: 443,
    sessionId: id(), readerNonce: id(), ownerNonce: id(), policyDigest, issuedAt: now, expiresAt: now + 30 };
  const profileDigest = hash(Buffer.from('Synthetic public posture'));
  child.stdin.end(JSON.stringify({ grant, trust: { community_id: communityId,
    policy_digest: policyDigest, issuer_public_key: Array.from(issuerPublic) }, challenge, profileDigest, now }) + '\n');
  const second = await lines.next();
  assert.equal(second.done, false, errorOutput);
  const signatures = JSON.parse(second.value);
  const publicKey = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: chatPublicKey }, format: 'jwk' });
  const challengeBytes = encoded(['cfrm.profile.v1', 'challenge', communityId, grant.memberId, chatPublicKey,
    challenge.onionHost, challenge.onionPort, challenge.sessionId, challenge.readerNonce,
    challenge.ownerNonce, policyDigest, challenge.issuedAt, challenge.expiresAt]);
  const responseBytes = encoded(['cfrm.profile.v1', 'response', hash(challengeBytes), profileDigest]);
  assert.equal(verify(null, challengeBytes, publicKey, Buffer.from(signatures.challengeSignature, 'base64url')), true);
  assert.equal(verify(null, responseBytes, publicKey, Buffer.from(signatures.responseSignature, 'base64url')), true);
  const [code] = await completion;
  assert.equal(code, 0, errorOutput);
  console.log('Real cmsg owner challenge and response signatures match the profile byte contract');
} finally { clearTimeout(timer); child.kill(); }
