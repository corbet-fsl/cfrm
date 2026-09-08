// Unpublished test harness. Node spans holder/operator roles; it is not a relay.
// The two native chat keys never have a Node signing-key substitute.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { Group } from '@semaphore-protocol/group';
import { generateProof, verifyProof } from '@semaphore-protocol/proof';
import { getCurveFromName } from 'ffjavascript';
import { deriveSemaphoreIdentity, openEnrollmentLedger, createEnrollmentService,
  enrollmentBytes, enrollmentMessage } from '../private-reciprocity/enrollment.js';
import { createCheckpointPublisher, registeredAcknowledgementContext } from '../private-reciprocity/checkpoints.js';
import { proveRegisteredAcknowledgement } from '../private-reciprocity/acknowledgement.js';
import { openDirectionalLedger } from './receipts.js';
import { createReleaseReceiptService } from './attestations.js';
import { NOW, COMMUNITY, POLICY, b64, hash, raw, json, suite, proofMessage,
  senderBytes, receiveBytes, admissionBytes, verifyAdmission } from './fixtures.js';
import { releaseDomain, commonContext, commitBytes, redemptionBytes } from './attestation-fixtures.js';

const actors = ['sender', 'recipient'];
const MAX_LINE = 32768;
const RPC_TIMEOUT = 30000;
const artifacts = { wasm: new URL('../private-reciprocity/.artifacts/semaphore.wasm', import.meta.url).pathname,
  zkey: new URL('../private-reciprocity/.artifacts/semaphore.zkey', import.meta.url).pathname };
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const binary = (value, size) => typeof value === 'string' &&
  Buffer.from(value, 'base64url').length === size && b64(Buffer.from(value, 'base64url')) === value;
export const same = (a, b) => isDeepStrictEqual(a, b);
const publicKey = value => createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: value }, format: 'jwk' });

export class NativeRejection extends Error {
  constructor(op, code) {
    const safeCode = ['not-implemented', 'release-rejected'].includes(code) ? code : 'rejected';
    super(`Native ${op} rejected: ${safeCode}`);
    this.code = safeCode;
  }
}

export class NativeBridge {
  constructor() {
    const executable = process.env.CMSG_RELEASE_HARNESS;
    if (!executable || !isAbsolute(executable)) throw new Error('An explicit absolute native harness path is required');
    this.sequence = 0;
    this.pending = undefined;
    this.buffer = Buffer.alloc(0);
    this.failure = undefined;
    this.closed = false;
    this.child = spawn(executable, [], { shell: false, stdio: ['pipe', 'pipe', 'pipe'], env: { RUST_BACKTRACE: '0' } });
    this.exited = new Promise(resolve => {
      this.child.once('close', (code, signal) => resolve({ code, signal }));
    });
    this.child.on('error', () => this.fail('Native harness could not start'));
    this.child.stdin.on('error', () => this.fail('Native harness input failed'));
    this.child.stdout.on('data', chunk => this.read(chunk));
    // Discard raw diagnostics rather than forwarding potentially private payloads.
    let diagnostics = 0;
    this.child.stderr.on('data', chunk => {
      diagnostics += chunk.length;
      if (diagnostics > MAX_LINE) this.fail('Native harness diagnostic limit exceeded');
    });
    this.child.once('close', () => {
      this.closed = true;
      if (this.pending) this.fail('Native harness closed before its response');
    });
  }
  fail(message) {
    this.failure ??= new Error(message);
    const pending = this.pending;
    this.pending = undefined;
    if (pending) { clearTimeout(pending.timer); pending.reject(this.failure); }
    if (!this.closed) this.child.kill('SIGTERM');
  }
  read(chunk) {
    if (this.failure) return;
    if (!this.pending || this.buffer.length + chunk.length > MAX_LINE) {
      this.fail('Native harness output violates the response bound'); return;
    }
    this.buffer = Buffer.concat([this.buffer, chunk]);
    const newline = this.buffer.indexOf(10);
    if (newline < 0) return;
    if (newline !== this.buffer.length - 1) { this.fail('Native harness emitted unsolicited output'); return; }
    let response;
    try { response = JSON.parse(this.buffer.subarray(0, newline).toString('utf8')); }
    catch { this.fail('Native harness emitted an invalid response'); return; }
    this.buffer = Buffer.alloc(0);
    const pending = this.pending;
    const keys = response?.ok === true ? ['id', 'ok', 'result'] : ['id', 'ok', 'error'];
    if (!exact(response, keys) || response.id !== pending.id ||
      (response.ok !== true && response.ok !== false) || (response.ok === false && typeof response.error !== 'string')) {
      this.fail('Native harness response does not match its request'); return;
    }
    this.pending = undefined;
    clearTimeout(pending.timer);
    if (response.ok) pending.resolve(response.result);
    else pending.reject(new NativeRejection(pending.op, response.error));
  }
  call(op, args) {
    if (this.failure || this.closed || this.closing) return Promise.reject(this.failure ?? new Error('Native harness is closed'));
    if (this.pending) return Promise.reject(new Error('Native harness requires sequential requests'));
    const id = ++this.sequence;
    const line = Buffer.from(JSON.stringify({ id, op, args }) + '\n');
    if (line.length > MAX_LINE) return Promise.reject(new Error('Native request exceeds its fixed limit'));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.fail('Native harness response timed out'), RPC_TIMEOUT);
      this.pending = { id, op, resolve, reject, timer };
      this.child.stdin.write(line);
    });
  }
  close() {
    // Share the same terminal result with concurrent/repeated cleanup callers.
    return this.closing ??= this.shutdown();
  }
  async shutdown() {
    if (this.pending) this.fail('Native harness closed with an unfinished request');
    this.child.stdin.end();
    let timer;
    const graceful = await Promise.race([this.exited.then(() => true),
      new Promise(resolve => { timer = setTimeout(() => resolve(false), 1000); })]);
    clearTimeout(timer);
    if (!graceful) {
      this.failure ??= new Error('Native harness exceeded its shutdown deadline');
      this.child.kill('SIGKILL');
    }
    // Wait for actual child/stdio closure before disposing its owned files.
    // A final successful RPC cannot override a later exit or protocol failure.
    const terminal = await this.exited;
    if (terminal.code !== 0 || terminal.signal !== null) {
      this.failure ??= new Error('Native harness terminated unsuccessfully');
    }
    if (this.failure) throw this.failure;
  }
}

let commonPromise;
let curve;
export async function terminateCompositionCrypto() { if (curve) await curve.terminate(); }
async function common() {
  return commonPromise ??= (async () => {
    curve = await getCurveFromName('bn128');
    const keyPair = () => generateKeyPairSync('ed25519');
    const receipt = await suite.generateKey({ publicExponent: Uint8Array.of(1, 0, 1), modulusLength: 3072 });
    return { issuer: keyPair(), publisher: keyPair(), senderOperator: keyPair(), recipientOperator: keyPair(), receipt,
      receiptPublic: await crypto.subtle.exportKey('jwk', receipt.publicKey) };
  })();
}

export async function compositionFixture(t) {
  const shared = await common();
  const directory = mkdtempSync(join(tmpdir(), 'cfrm-native-composition-'));
  const disposables = [];
  let bridge;
  t.after(async () => {
    try { if (bridge) await bridge.close(); }
    finally {
      for (const disposable of disposables.reverse()) disposable.close();
      rmSync(directory, { recursive: true, force: true });
    }
  });
  bridge = new NativeBridge();
  const clock = () => NOW;
  const walletIdentity = () => {
    const material = randomBytes(32);
    try { return deriveSemaphoreIdentity(material, COMMUNITY); }
    finally { material.fill(0); }
  };
  const members = Array.from({ length: 17 }, (_, index) => {
    const identity = walletIdentity();
    const memberId = hash(randomBytes(32));
    if (index < 2) return { identity, memberId, actor: actors[index] };
    const chat = generateKeyPairSync('ed25519');
    return { identity, memberId, chatPublicKey: b64(raw(chat.publicKey)), fillerPrivateKey: chat.privateKey };
  });
  const initialized = await bridge.call('init', {
    now: NOW, communityId: COMMUNITY, policyDigest: POLICY, issuerPublicKey: b64(raw(shared.issuer.publicKey)),
    senderCommitPublicKey: b64(raw(shared.senderOperator.publicKey)),
    recipientRedemptionPublicKey: b64(raw(shared.recipientOperator.publicKey)),
    expectedWalletCommitments: Object.fromEntries(actors.map((actor, index) =>
      [actor, members[index].identity.commitment.toString()])),
  });
  assert.ok(exact(initialized, actors), 'Native init result has the expected actors');
  for (const [index, actor] of actors.entries()) {
    assert.ok(exact(initialized[actor], ['chatPublicKey']) && binary(initialized[actor].chatPublicKey, 32),
      'Native actor returned one canonical public chat key');
    members[index].chatPublicKey = initialized[actor].chatPublicKey;
  }
  assert.ok(members[0].chatPublicKey !== members[1].chatPublicKey, 'The two native keys are distinct');
  const grantFor = member => {
    const grant = { version: 1, issuerKeyId: hash(raw(shared.issuer.publicKey)), communityId: COMMUNITY,
      memberId: member.memberId, chatPublicKey: member.chatPublicKey, policyDigest: POLICY,
      issuedAt: NOW, expiresAt: NOW + 600 };
    return { ...grant, signature: b64(sign(null, admissionBytes(grant), shared.issuer.privateKey)) };
  };
  for (const member of members) member.grant = grantFor(member);
  const bound = await bridge.call('bindAdmissions', Object.fromEntries(actors.map((actor, index) =>
    [actor, members[index].grant])));
  assert.ok(exact(bound, actors), 'Native admission result has the expected actors');
  for (const [index, actor] of actors.entries()) {
    assert.ok(exact(bound[actor], ['memberId', 'chatPublicKey']) &&
      bound[actor].memberId === members[index].memberId && bound[actor].chatPublicKey === members[index].chatPublicKey,
    'Native admission retains the exact certified identity and key');
  }

  const admissionTrust = { trustedPublicKey: raw(shared.issuer.publicKey), communityId: COMMUNITY, policyDigest: POLICY };
  const enrollmentLedger = openEnrollmentLedger(join(directory, 'enrollment.sqlite'));
  disposables.push(enrollmentLedger);
  const enrollment = createEnrollmentService({ ...admissionTrust, verifyAdmission, ledger: enrollmentLedger,
    clock, challengeSeconds: 30 });
  disposables.push(enrollment);
  for (const member of members) {
    const envelope = await enrollment.begin(member.grant, member.identity.commitment.toString());
    const signature = member.identity.signMessage(enrollmentMessage(envelope.challenge));
    let chatSignature;
    if (member.actor) {
      const response = await bridge.call('signEnrollment', { actor: member.actor, challenge: envelope.challenge });
      assert.ok(exact(response, ['signature']) && binary(response.signature, 64), 'Native enrollment signature is canonical');
      chatSignature = response.signature;
    } else {
      chatSignature = b64(sign(null, enrollmentBytes(envelope.challenge), member.fillerPrivateKey));
    }
    assert.equal(await enrollment.enroll({ grant: member.grant, ...envelope,
      publicKey: member.identity.publicKey.map(String),
      semaphoreSignature: { R8: signature.R8.map(String), S: String(signature.S) }, chatSignature }), true,
    'Actual admission, native/filler chat signature and Semaphore possession enroll successfully');
  }
  const publisher = createCheckpointPublisher({ ledger: enrollmentLedger, communityId: COMMUNITY, policyDigest: POLICY,
    signingKey: shared.publisher.privateKey, clock, epochSeconds: 60, minAnonymity: 16, depth: 7, maxRetainedLinks: 32 });
  disposables.push(publisher);
  const checkpointTrust = { trustedPublicKey: raw(shared.publisher.publicKey), communityId: COMMUNITY, policyDigest: POLICY, clock };
  const checkpoint = publisher.publish();
  const senderBinding = publisher.binding(members[0].memberId);
  const acknowledgement = registeredAcknowledgementContext(checkpoint, senderBinding, checkpointTrust);
  assert.equal(checkpoint.commitments.length, 17, 'All 17 admitted identities are in the checkpoint');
  assert.equal(acknowledgement.anonymitySetSize, 16, 'Exactly 16 qualified alternatives remain');
  assert.ok(senderBinding.commitment === members[0].identity.commitment.toString(), 'The sender binding is its retained wallet commitment');
  assert.ok(publisher.binding(members[1].memberId).commitment === members[1].identity.commitment.toString(),
    'The recipient binding is its retained wallet commitment');
  // This prerequisite proof verifies the real native-key enrollment/checkpoint
  // before the intended stub boundary. It is never submitted for a counter debit.
  // This maintained helper also verifies the pinned artifact hashes and sizes.
  const qualification = await proveRegisteredAcknowledgement(members[1].identity, checkpoint,
    senderBinding, checkpointTrust, artifacts);
  assert.equal(await verifyProof(qualification), true, 'Actual sender-excluded qualification proof verifies');
  t.diagnostic('Composition prerequisites: 2 native keys, 17 real enrollments, 16 alternatives, actual proof verified');

  const cohort = { public: { version: 2, purpose: 'release-acknowledged-receive', communityId: COMMUNITY,
    policyDigest: POLICY, cohortId: 'native-composition-1', notBefore: NOW, issueUntil: NOW + 120,
    redeemUntil: NOW + 300, publicKey: shared.receiptPublic }, privateKey: shared.receipt.privateKey };
  const attestationKeys = {
    senderCommit: { publicKey: raw(shared.senderOperator.publicKey), privateKey: shared.senderOperator.privateKey },
    recipientRedemption: { publicKey: raw(shared.recipientOperator.publicKey), privateKey: shared.recipientOperator.privateKey },
  };
  const open = () => {
    const ledger = openDirectionalLedger(join(directory, 'directional.sqlite'));
    disposables.push(ledger);
    const service = createReleaseReceiptService({ ledger, cohort, attestationKeys, checkpointTrust,
      admissionTrust, verifyAdmission, clock, maxAuthorizedSend: 16, maxAcknowledgedReceive: 64,
      maxPending: 2, maxRequestBytes: 32768, authorizationSeconds: 30 });
    return { ledger, service, count: index => ledger.counters(COMMUNITY, cohort.public.cohortId, members[index].memberId) };
  };
  const f = { bridge, members, cohort, context: commonContext(cohort.public), open, checkpoint, senderBinding };
  f.prepare = async () => {
    // The deliberate native RED boundary is here, after all real prerequisites.
    const prepared = await bridge.call('prepareRelease', { context: f.context, preflightExpiresAt: NOW + 120 });
    assert.ok(exact(prepared, ['preflight', 'recipientHasWelcome', 'ciphertextRejectedBeforeWelcome']),
      'Native preflight result contains only the reviewed private metadata and coarse outcomes');
    assert.ok(prepared.recipientHasWelcome === false, 'Recipient still lacks the withheld Welcome');
    assert.ok(prepared.ciphertextRejectedBeforeWelcome === true, 'Ciphertext alone cannot admit the recipient');
    const p = prepared.preflight;
    assert.ok(exact(p, ['version', 'context', 'sender', 'recipient', 'releaseNonce', 'issuedAt', 'expiresAt', 'signature']) &&
      p.version === 1 && same(p.context, f.context) && binary(p.releaseNonce, 32) && binary(p.signature, 64),
    'Native preflight is a canonical authenticated private statement');
    for (const [index, actor] of actors.entries()) {
      assert.ok(exact(p[actor], ['memberId', 'chatPublicKey']) && p[actor].memberId === members[index].memberId &&
        p[actor].chatPublicKey === members[index].chatPublicKey, 'Preflight keeps the same certified peers');
    }
    return p;
  };
  f.action = async preflight => {
    // Holder-side secret serial/unblinding state; never part of operator input.
    const prepared = suite.prepare(Uint8Array.from(Buffer.concat([
      Buffer.from(releaseDomain(cohort.public), 'base64url'), Buffer.from(members[1].memberId, 'base64url'),
      randomBytes(32), Buffer.from(preflight.releaseNonce, 'base64url'),
    ])));
    const { blindedMsg, inv } = await suite.blind(shared.receipt.publicKey, prepared);
    const blinded = b64(blindedMsg);
    const signed = await bridge.call('authorizeSend', { blinded, expiresAt: NOW + 30 });
    assert.ok(exact(signed, ['authorization']), 'Native sender returns only its authorization');
    const authorization = signed.authorization;
    assert.ok(authorization.senderId === members[0].memberId && authorization.requestHash === hash(blindedMsg) &&
      authorization.nonce !== preflight.releaseNonce && verify(null, senderBytes(authorization),
        publicKey(members[0].chatPublicKey), Buffer.from(authorization.signature, 'base64url')),
    'The actual certified sender signed its own blinded request with an independent nonce');
    const group = new Group(checkpoint.commitments.filter(value => value !== senderBinding.commitment).map(BigInt));
    const semaphoreProof = await generateProof(members[1].identity, group, proofMessage(checkpoint, authorization),
      acknowledgement.scope, acknowledgement.depth, artifacts);
    const request = { senderAuthorization: authorization, senderAdmission: members[0].grant, checkpoint,
      senderBinding, blindedReceiptRequest: { blinded }, semaphoreProof };
    const visible = JSON.stringify(request);
    assert.ok(!visible.includes(preflight.releaseNonce) &&
      !visible.includes(hash(Buffer.from(preflight.releaseNonce, 'base64url'))) && !visible.includes(members[1].memberId) &&
      !visible.includes(members[1].chatPublicKey) && !visible.includes(preflight.signature),
    'The sender service envelope contains no explicit recipient or private-preflight join');
    return { request, finish: async output => ({ message: b64(prepared), signature: b64(await suite.finalize(
      shared.receipt.publicKey, prepared, Uint8Array.from(Buffer.from(output.blindSignature, 'base64url')), inv)) }) };
  };
  f.redemption = async receipt => {
    const signed = await bridge.call('authorizeReceive', { receipt, expiresAt: NOW + 30 });
    assert.ok(exact(signed, ['authorization']), 'Native recipient returns only its authorization');
    const authorization = signed.authorization;
    assert.ok(authorization.memberId === members[1].memberId && authorization.receiptHash === hash(json([receipt.message, receipt.signature])) &&
      verify(null, receiveBytes(authorization), publicKey(members[1].chatPublicKey), Buffer.from(authorization.signature, 'base64url')),
    'The actual certified recipient signed its own exact receipt');
    return { receipt, admission: members[1].grant, authorization };
  };
  f.checkStatements = (output, received, action, preflight) => {
    assert.ok(exact(output, ['blindSignature', 'senderCommit']) && exact(received, ['recipientRedemption']),
      'The ledger results have the exact release shapes');
    const s = output.senderCommit;
    const r = received.recipientRedemption;
    assert.ok(same(s.context, f.context) && same(r.context, f.context) &&
      s.sender.memberId === members[0].memberId && s.sender.chatPublicKey === members[0].chatPublicKey &&
      r.recipient.memberId === members[1].memberId && r.recipient.chatPublicKey === members[1].chatPublicKey &&
      s.authorizationNonce === action.request.senderAuthorization.nonce &&
      s.blindedRequestHash === action.request.senderAuthorization.requestHash && r.releaseNonce === preflight.releaseNonce,
    'Actual counter statements preserve the native peers and separate pending bindings');
    assert.equal(verify(null, commitBytes(s), shared.senderOperator.publicKey, Buffer.from(s.signature, 'base64url')), true);
    assert.equal(verify(null, redemptionBytes(r), shared.recipientOperator.publicKey, Buffer.from(r.signature, 'base64url')), true);
    const senderSide = JSON.stringify([action.request, output]);
    assert.ok(!senderSide.includes(preflight.releaseNonce) &&
      !senderSide.includes(hash(Buffer.from(preflight.releaseNonce, 'base64url'))),
    'Neither raw nor SHA-256 private release nonce appears in the complete sender-side service values');
  };
  // Explicit negative witnesses only: these are never accepted as evidence of
  // a counter commit. Successful release always uses untouched ledger outputs.
  f.signNegativeSender = statement => ({ ...statement,
    signature: b64(sign(null, commitBytes(statement), shared.senderOperator.privateKey)) });
  f.signNegativeRecipient = statement => ({ ...statement,
    signature: b64(sign(null, redemptionBytes(statement), shared.recipientOperator.privateKey)) });
  return f;
}
