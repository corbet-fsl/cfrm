// Dedicated loopback-test bridge; no deployment endpoint. It holds only public
// account requests and independently native-verified enrollment objects.
import { mkdir, readFile, writeFile, rename } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { createAccountVerifier } from '../account-state/verify.mjs';
import { ACCOUNT_MODE, policyDigest, statePolicyDigest } from '../account-state/hashes.mjs';
import { nativeProcess, stopNativeProcesses } from './native-process.mjs';

const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const eq = isDeepStrictEqual;
const decode = hex => {
  if (typeof hex !== 'string' || !/^(?:[0-9a-f]{2})+$/.test(hex) || hex.length > 2_000_000) throw new Error('Public byte encoding');
  return Buffer.from(hex, 'hex');
};

export async function createLedgerBridge({ directory, manifestPath, binary }) {
  if (!binary) throw new Error('Real ACCOUNTING_LEDGER_FIXTURE required');
  await mkdir(directory, { recursive: true });
  const paths = { manifest: resolve(manifestPath), enrollment: resolve(directory, 'enrollment.json'),
    ledger: resolve(directory, 'config.json'), database: resolve(directory, 'accounts.sqlite'),
    verifier: resolve('account-state/verify-request.mjs'), peerVerifier: resolve('peer-reservation/verify-request.mjs') };
  const manifest = JSON.parse(await readFile(paths.manifest, 'utf8'));
  if (manifest.accountingMode !== ACCOUNT_MODE || manifest.peerReservation?.mode !== 'peer-reservation-v3') throw new Error('Bridge artifact mode');
  const scope = { circuitDigest: Array.from(decode(manifest.circuitSha256)), verifyingKeyDigest: Array.from(decode(manifest.vkSha256)) };
  const args = [paths.ledger, paths.database, paths.verifier, paths.manifest, paths.enrollment, ACCOUNT_MODE];
  const active = new Set(), originals = new Map(), accepted = new Map();
  const evidence = { applies: 0, acceptanceChecks: 0, nativeCalls: 0, witnessReceived: false, latest: [], currentStateChecks: [],
    currentStateLimitation: 'trusted own-account read-only snapshot; no lock across delivery or counterpart freshness claim' };
  let initialized = false, busy = false, trusted, config, retained;
  const saveJSON = async (path, value) => { await writeFile(path + '.next', JSON.stringify(value)); await rename(path + '.next', path); };
  async function invoke(input) { evidence.nativeCalls++; return nativeProcess(binary, args, input, active); }
  return {
    paths, evidence,
    async enroll(value) {
      if (initialized || value.synthetic !== true || !eq(value.acceptedTimes, [100,300,600])) throw new Error('Bridge native enrollment/config');
      retained = value;
      value.acceptedPolicies = [structuredClone(manifest.accountPolicy)];
      trusted = { community: value.community, entries: value.entries, acceptedTimes: value.acceptedTimes, acceptedPolicies: value.acceptedPolicies };
      // This function is called only with the native fixture response retained
      // by the server. No browser request can provide authoritative entries.
      const verifier = await createAccountVerifier(paths.manifest, trusted);
      let root;
      try { root = Array.from(Buffer.from(verifier.checkpoint.root.toString(16).padStart(64, '0'), 'hex')); }
      finally { await verifier.destroy(); }
      const trust = value.trust;
      config = { communityId: trust.community_id, admissionPolicyDigest: trust.policy_digest,
        issuerPublicKey: trust.issuer_public_key, policy: { account: manifest.accountPolicy,
          maxAuthorizationSeconds: 100, maxProofBytes: 1_000_000, checkpointPeriodSeconds: 1000 },
        proofScope: scope, checkpoints: [{ slot: 0, root }] };
      for (const entry of value.entries) originals.set(entry.memberId, structuredClone(entry.originalDelegation));
      await saveJSON(paths.enrollment, trusted);
      await saveJSON(paths.ledger, config);
      initialized = true;
    },
    async call(input) {
      if (!initialized || busy) throw new Error('Ledger bridge not ready or busy');
      busy = true;
      try {
        if (exact(input, ['action']) && input.action === 'tuneWaitingPeriod') {
          // A single host-authorized synthetic step, not a deployment endpoint.
          // The browser supplies neither policy values nor operator authority.
          if (evidence.tuning || evidence.applies < 7 || config.policy.account.abandonAfter !== 500) throw new Error('Unscheduled fixture policy tuning');
          const reply = await invoke({ action: 'tuneWaitingPeriod', expectedRevision: 0, seconds: 900, now: 100 });
          if (!reply.ok) return reply;
          const { policy, tuning } = reply.value, community = decode(trusted.community);
          if (!eq(policy, { ...manifest.accountPolicy, abandonAfter: 900 }) || tuning.revision !== 1 || tuning.seconds !== 900
              || !eq(Array.from(await statePolicyDigest(community, policy)), tuning.statePolicyDigest)
              || !eq(Array.from(await policyDigest(community, policy)), tuning.policyDigest)) throw new Error('Actual tuned policy differs from trusted step');
          config.policy.account = policy; trusted.acceptedPolicies.push(structuredClone(policy));
          retained.waitingPeriodTuning = { beforeProofIndex: evidence.applies, tuning, policy };
          evidence.tuning = structuredClone(retained.waitingPeriodTuning);
          await saveJSON(paths.enrollment, trusted); await saveJSON(paths.ledger, config);
          return reply;
        }
        if (exact(input, ['action','acceptance']) && input.action === 'verifyAcceptance') {
          if (++evidence.acceptanceChecks > 160) throw new Error('Acceptance verification call bound');
          return await invoke(input);
        }
        if (!exact(input, ['action','record']) || input.action !== 'apply'
            || !exact(input.record, ['statement','proof','requestAuthorization'])) throw new Error('Public account bridge field set');
        if (++evidence.applies > 24) throw new Error('Chronological account call bound');
        const r = input.record, auth = r.requestAuthorization;
        if (!Array.isArray(r.statement.owner) || r.statement.owner.length !== 32) throw new Error('Public owner');
        const owner = Buffer.from(r.statement.owner).toString('base64url'), original = originals.get(owner);
        if (!original || !eq(auth.circuitDigest, scope.circuitDigest) || !eq(auth.verifyingKeyDigest, scope.verifyingKeyDigest)) throw new Error('Unrecognized owner or verifier scope');
        const request = { statement: r.statement, requestId: auth.requestId, proofScope: scope,
          chatPublicKey: auth.chatPublicKey, issuedAt: auth.issuedAt, expiresAt: auth.expiresAt,
          proof: Array.from(decode(r.proof)), signature: auth.signature };
        if (![100,300,600].includes(r.statement.now)) throw new Error('Unpinned fixture proof time');
        const reply = await invoke({ action: 'apply', grant: original.admission, authorization: original.authorization,
          request, now: r.statement.now });
        if (reply.ok) {
          if (!eq(reply.value.statement, r.statement) || !eq(reply.value.requestId, auth.requestId)) throw new Error('Rust acceptance differs from submitted request');
          const checked = await invoke({ action: 'verifyAcceptance', acceptance: reply.value });
          if (!checked.ok || checked.value?.verified !== true) throw new Error('Rust acceptance signature verification failed');
          const currentInput = { action: 'verifyCurrentOwnState', owner: reply.value.statement.owner,
            stateVersion: reply.value.statement.nextVersion, stateCommitment: reply.value.statement.nextState };
          const current = await invoke(currentInput);
          if (!current.ok || current.value?.verified !== true) throw new Error('Actual committed own state query failed');
          evidence.currentStateChecks.push('current accepted own state ' + evidence.applies);
          const previous = accepted.get(owner);
          if (previous) {
            const stale = await invoke({ ...currentInput, stateVersion: previous.statement.nextVersion, stateCommitment: previous.statement.nextState });
            if (stale.ok) throw new Error('Superseded own state remained current');
            evidence.currentStateChecks.push('prior accepted own state rejected ' + evidence.applies);
          } else if (accepted.size === 0) {
            const altered = [...currentInput.stateCommitment]; altered[31] ^= 1;
            for (const [name, change] of [['absent owner', { owner: Array(32).fill(0) }],
              ['altered version', { stateVersion: currentInput.stateVersion + 1 }], ['altered commitment', { stateCommitment: altered }]]) {
              if ((await invoke({ ...currentInput, ...change })).ok) throw new Error('Invalid own-state query accepted: ' + name);
              evidence.currentStateChecks.push('own-state query rejects ' + name);
            }
          }
          accepted.set(owner, reply.value);
          evidence.latest = [...accepted.values()].map(a => ({ owner: a.statement.owner, version: a.statement.nextVersion,
            commitment: a.statement.nextState, acceptanceDigest: createHash('sha256').update(JSON.stringify(a)).digest('hex') }));
        }
        return reply;
      } finally { busy = false; }
    },
    close: () => stopNativeProcesses(active),
  };
}
