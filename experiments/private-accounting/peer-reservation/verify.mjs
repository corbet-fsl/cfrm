// Portable browser/Node proof verifier. The host supplies a REAL pinned-operator
// Rust acceptance verifier; no default or successful stand-in is provided here.
import { UltraHonkVerifierBackend } from '@aztec/bb.js';
import { OPTIONS, sha } from '../common.mjs';
import { fieldValue } from '../hashes.mjs';
import { policyDigest, statePolicyDigest, POLICY_KEYS } from '../account-state/hashes.mjs';
import { publicInputValues as accountPublicInputs, validityHorizon } from '../account-state/witness.mjs';
import { EXPECTED_KEYS, bytes32, safeInteger, exact, equalBytes, publicInputValues } from './witness.mjs';

const scopeKeys = ['circuitDigest','verifyingKeyDigest'];
const acceptanceKeys = ['statement','requestId','requestDigest','proofScope','acceptedAt','signature'];
const accountKeys = ['protocolVersion','community','owner','policyDigest','enrollmentRoot','now','validUntil','genesis',
  'previousVersion','nextVersion','previousState','nextState','settlementMarker','policy'];
const policyKeys = POLICY_KEYS;
function checkScope(value) {
  if (!exact(value, scopeKeys)) throw new Error('Proof scope field set');
  scopeKeys.forEach(key => bytes32(value[key])); return value;
}
function sameScope(actual, expected) {
  checkScope(actual); checkScope(expected);
  if (!scopeKeys.every(key => equalBytes(actual[key], expected[key]))) throw new Error('Wrong pinned proof scope');
}
export async function validateAcceptedContext(record, trusted, verifyAccountAcceptance) {
  if (record.version !== 3 || !exact(record, ['version','statement','proofScope','proof','accountAcceptance'])) throw new Error('Peer presentation envelope');
  const s = record.statement, a = record.accountAcceptance, e = trusted.expected;
  publicInputValues(s);
  if (!exact(e, EXPECTED_KEYS)) throw new Error('Independently expected peer context required');
  publicInputValues({ ...e, presentationBinding: s.presentationBinding });
  for (const key of EXPECTED_KEYS) {
    if (Array.isArray(e[key]) ? !equalBytes(s[key], e[key]) : s[key] !== e[key]) throw new Error('Peer context mismatch: ' + key);
  }
  sameScope(record.proofScope, trusted.peerProofScope);
  if (!exact(a, acceptanceKeys) || !exact(a.statement, accountKeys) || !exact(a.statement.policy, policyKeys)) throw new Error('Acceptance field set');
  accountPublicInputs(a.statement);
  sameScope(a.proofScope, trusted.accountProofScope);
  const now = safeInteger(trusted.now), acceptedAt = safeInteger(a.acceptedAt);
  bytes32(a.requestId); bytes32(a.requestDigest);
  if (!a.requestId.some(Boolean) || typeof a.signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(a.signature)
      || acceptedAt < BigInt(a.statement.now) || acceptedAt >= BigInt(a.statement.validUntil) || acceptedAt > now) throw new Error('Acceptance identifier/signature/time');
  const accepted = a.statement;
  for (const name of ['enrollmentRoot','previousState','nextState','settlementMarker']) fieldValue(bytes32(accepted[name]));
  if (accepted.genesis || accepted.nextVersion !== accepted.previousVersion + 1
      || accepted.nextVersion !== s.stateVersion || !equalBytes(accepted.nextState, s.stateCommitment)
      || !equalBytes(accepted.owner, s.owner) || !equalBytes(accepted.community, s.community)
      || !equalBytes(accepted.enrollmentRoot, Array.from(bytes32(trusted.enrollmentRoot)))) throw new Error('Acceptance does not certify presented state');
  if (!exact(trusted.accountPolicy, policyKeys) || !policyKeys.filter(key => key !== 'abandonAfter').every(key => accepted.policy[key] === trusted.accountPolicy[key])) throw new Error('Unpinned immutable account policy');
  const digest = await statePolicyDigest(bytes32(s.community), trusted.accountPolicy);
  if (!equalBytes(await policyDigest(bytes32(s.community), accepted.policy), accepted.policyDigest)
      || !equalBytes(await statePolicyDigest(bytes32(s.community), accepted.policy), digest)
      || !equalBytes(digest, s.statePolicyDigest) || now < BigInt(trusted.accountPolicy.policyValidFrom)
      || now >= BigInt(trusted.accountPolicy.policyValidUntil)) throw new Error('Wrong or expired common policy');
  if (BigInt(accepted.validUntil) !== validityHorizon(accepted.now, trusted.accountPolicy)
      || now < BigInt(s.openedAt) || now >= BigInt(s.expiresAt)
      || s.expiresAt >= trusted.accountPolicy.policyValidUntil) throw new Error('Expired or mismatched original introduction lease');
  if (typeof verifyAccountAcceptance !== 'function') throw new Error('Real operator acceptance verifier unavailable');
  // This is a host cryptography boundary, not a prover-selected callback. The
  // adapter must call cfrm::accounting::verify_account_acceptance with the pinned operator.
  if (await verifyAccountAcceptance(a) !== true) throw new Error('Invalid operator acceptance');
}

export async function createPeerVerifier({ api, circuitBytes, verificationKey, peerProofScope, accountProofScope, verifyAccountAcceptance }) {
  const peerScope = structuredClone(checkScope(peerProofScope)), accountScope = structuredClone(checkScope(accountProofScope));
  const key = new Uint8Array(verificationKey);
  if (!equalBytes(await sha(circuitBytes), peerScope.circuitDigest) || !equalBytes(await sha(key), peerScope.verifyingKeyDigest)) throw new Error('Peer circuit/VK artifact pin mismatch');
  if (typeof verifyAccountAcceptance !== 'function') throw new Error('Real operator acceptance verifier unavailable');
  const backend = new UltraHonkVerifierBackend(api);
  return {
    async verify(presentation, expectedContext) {
      const record = structuredClone(presentation), trusted = structuredClone(expectedContext);
      Object.assign(trusted, { peerProofScope: peerScope, accountProofScope: accountScope });
      await validateAcceptedContext(record, trusted, verifyAccountAcceptance);
      if (typeof record.proof !== 'string' || record.proof.length > 2_000_000 || !/^(?:[0-9a-f]{2})+$/.test(record.proof)) throw new Error('Peer proof size/encoding');
      const proof = Uint8Array.from(record.proof.match(/../g), value => parseInt(value, 16));
      const publicInputs = publicInputValues(record.statement).map(n => '0x' + n.toString(16).padStart(64, '0'));
      if (!await backend.verifyProof({ proof, publicInputs, verificationKey: key }, OPTIONS)) throw new Error('Invalid peer reservation proof');
      // Successful verification is not durable challenge consumption or cmsg
      // authorization. The caller must persist those gates before releasing data.
      return { verified: true, statement: record.statement };
    },
  };
}
