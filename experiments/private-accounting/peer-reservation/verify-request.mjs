// Trusted cmsg fixture process adapter. All file paths and the Rust executable
// come from process configuration, never the presenting browser's JSON.
import { readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { Barretenberg, BackendType } from '@aztec/bb.js';
import { sha, hex, unhex } from '../common.mjs';
import { accountHashes, checkpointFromVerified, statePolicyDigest, ACCOUNT_MODE } from '../account-state/hashes.mjs';
import { fieldBytes } from '../hashes.mjs';
import { PEER_MODE, EXPECTED_KEYS, exact, bytes32, equalBytes, safeInteger } from './witness.mjs';
import { createPeerVerifier } from './verify.mjs';
import { nativeProcess } from './native-process.mjs';

console.log = (...args) => process.stderr.write(args.map(String).join(' ') + '\n');
let api;
try {
  if (process.argv.length !== 5 || !process.env.ACCOUNTING_LEDGER_FIXTURE) throw new Error('Trusted peer verifier paths and Rust fixture required');
  const [manifestPath, enrollmentPath, configPath] = process.argv.slice(2).map(value => resolve(value));
  const directory = dirname(manifestPath);
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  if (manifest.accountingMode !== ACCOUNT_MODE || manifest.peerReservation?.mode !== PEER_MODE) throw new Error('Peer verifier mode mismatch');
  const native = JSON.parse(await readFile(enrollmentPath, 'utf8'));
  const config = JSON.parse(await readFile(configPath, 'utf8'));
  const chunks = []; let length = 0;
  for await (const chunk of process.stdin) {
    length += chunk.length; if (length > 2_000_000) throw new Error('Peer verifier request bound'); chunks.push(chunk);
  }
  const request = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (!exact(request, ['presentation','expectedContext','requireCurrentOwn']) || typeof request.requireCurrentOwn !== 'boolean') throw new Error('Peer verifier request fields');
  const circuitBytes = new Uint8Array(await readFile(resolve(directory, 'peer-reservation/circuit.json')));
  const verificationKey = new Uint8Array(await readFile(resolve(directory, 'peer-reservation/vk.bin')));
  const peerProofScope = { circuitDigest: Array.from(unhex(manifest.peerReservation.circuitSha256)),
    verifyingKeyDigest: Array.from(unhex(manifest.peerReservation.vkSha256)) };
  const accountProofScope = { circuitDigest: Array.from(unhex(manifest.circuitSha256)), verifyingKeyDigest: Array.from(unhex(manifest.vkSha256)) };
  if (!equalBytes(config.proofScope.circuitDigest, accountProofScope.circuitDigest)
      || !equalBytes(config.proofScope.verifyingKeyDigest, accountProofScope.verifyingKeyDigest)
      || !equalBytes(await statePolicyDigest(unhex(native.community), config.policy.account), await statePolicyDigest(unhex(native.community), manifest.accountPolicy))) throw new Error('Trusted peer/ledger scope mismatch');
  api = await Barretenberg.new({ backend: BackendType.Wasm, threads: 1, skipSrsInit: true,
    memory: { initial: 2048, maximum: 32768 } });
  const community = unhex(native.community), checkpoint = await checkpointFromVerified(community, native.entries, accountHashes(api));
  const setup = {};
  for (const item of manifest.setup) {
    if (!['g1.dat','g2.dat'].includes(item.name)) throw new Error('Peer setup artifact');
    const data = new Uint8Array(await readFile(resolve(directory, 'setup', item.name)));
    if (data.length !== item.bytes || hex(await sha(data)) !== item.sha256) throw new Error('Peer setup pin mismatch');
    setup[item.name] = data;
  }
  await api.srsInitSrs({ pointsBuf: setup['g1.dat'], numPoints: manifest.numPoints, g2Point: setup['g2.dat'] });
  const fixtureArgs = [configPath, resolve(dirname(configPath), 'accounts.sqlite'), resolve('account-state/verify-request.mjs'),
    manifestPath, enrollmentPath, ACCOUNT_MODE];
  const verifier = await createPeerVerifier({ api, circuitBytes, verificationKey, peerProofScope, accountProofScope,
    verifyAccountAcceptance: async acceptance => {
      const result = await nativeProcess(process.env.ACCOUNTING_LEDGER_FIXTURE, fixtureArgs, { action: 'verifyAcceptance', acceptance });
      return result.ok && result.value?.verified === true;
    } });
  // Native cmsg supplies its own expected pair, role, immutable lease, actual
  // history, initial device and challenge. Only state/version may be taken from
  // the certificate, whose signature and scope are checked independently.
  const e = request.expectedContext;
  if (!exact(e, ['now','devicePublicKey','expected']) || !exact(e.expected, EXPECTED_KEYS.filter(key => !['stateVersion','stateCommitment','statePolicyDigest','ownerAuthority'].includes(key)))) throw new Error('Native expected peer context fields');
  const expected = structuredClone(e.expected), acceptance = request.presentation.accountAcceptance;
  const owner = bytes32(expected.owner), device = bytes32(e.devicePublicKey);
  const enrolledIndex = native.entries.findIndex(entry => equalBytes(Buffer.from(entry.memberId, 'base64url'), owner)
    && equalBytes(Buffer.from(entry.originalDelegation.authorization.devicePublicKey, 'base64url'), device));
  if (!equalBytes(bytes32(expected.community), community) || expected.phase !== 2 || enrolledIndex < 0) throw new Error('Native peer owner/device/community/phase');
  Object.assign(expected, { stateVersion: acceptance.statement.nextVersion, stateCommitment: acceptance.statement.nextState,
    ownerAuthority: Array.from(fieldBytes(checkpoint.entries[enrolledIndex].leaf)),
    statePolicyDigest: Array.from(await statePolicyDigest(community, config.policy.account)) });
  // Trusted release metadata, not a new circuit input. The delegation's expiry
  // is independently bounded by its original admission/root-device authority.
  // The accepted request's validUntil only bounded its commit; it does not
  // expire the accepted Active state at every account rate-window boundary.
  const limits = [safeInteger(config.policy.account.policyValidUntil),
    safeInteger(expected.expiresAt),
    safeInteger(native.entries[enrolledIndex].expiresAt)];
  const validUntil = limits.reduce((minimum, value) => value < minimum ? value : minimum);
  if (safeInteger(e.now) >= validUntil) throw new Error('Peer release authority has expired');
  const result = await verifier.verify(request.presentation, { now: e.now, expected,
    accountPolicy: config.policy.account, enrollmentRoot: Array.from(fieldBytes(checkpoint.root)) });
  if (request.requireCurrentOwn) {
    // Set only by native cmsg's own-current path, never a presentation field.
    // This is a read-only snapshot, not a lock extending through payload release.
    const current = await nativeProcess(process.env.ACCOUNTING_LEDGER_FIXTURE, fixtureArgs, {
      action: 'verifyCurrentOwnState', owner: expected.owner,
      stateVersion: expected.stateVersion, stateCommitment: expected.stateCommitment });
    if (!current.ok || current.value?.verified !== true) throw new Error('Own accepted account state has been superseded');
  }
  process.stdout.write(JSON.stringify({ ...result, validUntil: Number(validUntil) }) + '\n');
} catch (error) {
  process.stderr.write(String(error?.message ?? error) + '\n'); process.exitCode = 1;
} finally { await api?.destroy(); }
