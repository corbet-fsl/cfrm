// Browser contract over a genuinely accepted live AccountWitness and a real
// host/Rust acceptance verifier. Openings and paths stay inside the page.
import { Noir } from '@noir-lang/noir_js';
import { UltraHonkBackend } from '@aztec/bb.js';
import { OPTIONS, hex } from '../common.mjs';
import { noirInput } from '../account-state/hashes.mjs';
import { PEER_MODE, preparePeerReservation, publicInputValues } from './witness.mjs';
import { createPeerVerifier, validateAcceptedContext } from './verify.mjs';

export async function runPeerReservationContract({ api, circuitBytes, verificationKey, peerProofScope, accountProofScope,
  state, event, accountAcceptance, context, verifyAccountAcceptance, assert, stage = () => {} }) {
  const began = performance.now(), checks = [];
  const check = (condition, label) => { assert(condition, label); checks.push(label); };
  const candidate = await preparePeerReservation({ api, state, event,
    historyDigest: Uint8Array.from(context.expected.historyDigest), challenge: Uint8Array.from(context.expected.challenge) });
  const record = { version: 3, statement: candidate.statement, proofScope: peerProofScope, proof: '00', accountAcceptance };
  const trusted = { ...context, peerProofScope, accountProofScope };
  await validateAcceptedContext(record, trusted, verifyAccountAcceptance);
  check(true, 'real operator acceptance matches the retained live reservation and expected cmsg context');
  const circuit = JSON.parse(new TextDecoder().decode(circuitBytes));
  const noir = new Noir(circuit);
  stage('peer-reservation-witness');
  const start = performance.now(), execution = await noir.execute(noirInput(candidate.input));
  const witnessMs = performance.now() - start;
  const rejectsWitness = async (label, mutate) => {
    const changed = structuredClone(candidate.input); mutate(changed);
    let failed = false; try { await noir.execute(noirInput(changed)); } catch { failed = true; }
    check(failed, label);
  };
  await rejectsWitness('peer proof rejects a different registered owner secret', input => { input.owner_secret[0] ^= 1; });
  for (const [name, label] of [['owner','owner'], ['peer','peer'], ['nonce','introduction nonce'], ['group','MLS group'],
    ['contact_policy_digest','contact policy'], ['history_digest','history context'], ['state_policy_digest','immutable account policy'],
    ['challenge','peer challenge'], ['owner_authority','original accounting device authority']]) {
    await rejectsWitness('peer proof rejects changed ' + label + ' with the original opening/binding', input => { input[name][0] ^= 1; });
  }
  await rejectsWitness('peer proof rejects the opposite role', input => { input.role ^= 1; });
  await rejectsWitness('peer proof rejects settled phase', input => { input.phase = 3; });
  await rejectsWitness('peer proof rejects canceled phase', input => { input.phase = 4; });
  await rejectsWitness('peer proof rejects expired phase', input => { input.phase = 5; });
  await rejectsWitness('peer proof rejects a changed shared opened-at', input => { input.opened_at += 1n; });
  await rejectsWitness('peer proof rejects a changed original expiry', input => { input.expires_at += 1n; });
  await rejectsWitness('peer proof rejects an altered accepted version', input => { input.state_version += 1n; });
  await rejectsWitness('peer proof rejects a changed Merkle sibling', input => { input.selected.path[0] += 1n; });
  await rejectsWitness('peer proof rejects changed authenticated leaf pointers', input => { input.selected.leaf[2] += 1n; });
  await rejectsWitness('peer proof rejects a different slot amount', input => { input.amount += 1n; });
  await rejectsWitness('peer proof rejects a modified unrelated map root', input => {
    if (input.role === 0) input.opening.incoming_root += 1n; else input.opening.outgoing_root += 1n;
  });
  await rejectsWitness('peer proof rejects the sentinel as a live slot', input => { input.selected.index = 0n; });

  stage('peer-reservation-proof');
  const backend = new UltraHonkBackend(circuit.bytecode, api), proofAt = performance.now();
  const proof = await backend.generateProof(execution.witness, OPTIONS);
  const provingMs = performance.now() - proofAt;
  const expectedInputs = publicInputValues(candidate.statement);
  check(proof.publicInputs.length === expectedInputs.length
    && proof.publicInputs.every((value, index) => BigInt(value) === expectedInputs[index]), 'peer circuit public input encoding matches the host');
  record.proof = hex(proof.proof);
  const verifier = await createPeerVerifier({ api, circuitBytes, verificationKey, peerProofScope, accountProofScope, verifyAccountAcceptance });
  const verifyAt = performance.now();
  await verifier.verify(record, context);
  const verificationMs = performance.now() - verifyAt;
  check(true, 'actual accepted live reservation proof verifies with independently pinned scope');
  const rejectsHost = async (label, mutate, expected = context) => {
    const changed = structuredClone(record); mutate(changed);
    let failed = false; try { await verifier.verify(changed, expected); } catch { failed = true; }
    check(failed, label);
  };
  for (const name of ['challenge','historyDigest','owner','peer','nonce','group','contactPolicyDigest','ownerAuthority','statePolicyDigest']) {
    await rejectsHost('host rejects substituted ' + name, changed => { changed.statement[name][0] ^= 1; });
  }
  await rejectsHost('host rejects a changed signed acceptance', changed => { changed.accountAcceptance.requestDigest[0] ^= 1; });
  await rejectsHost('host rejects a different account-state verifier pin', changed => { changed.accountAcceptance.proofScope.verifyingKeyDigest[0] ^= 1; });
  await rejectsHost('host rejects a different peer verifier pin', changed => { changed.proofScope.verifyingKeyDigest[0] ^= 1; });
  const expired = structuredClone(context); expired.now = context.accountPolicy.policyValidUntil;
  await rejectsHost('host rejects expired current policy', () => {}, expired);
  const expiredLease = structuredClone(context); expiredLease.now = context.expected.expiresAt;
  await rejectsHost('host rejects an expired common introduction lease', () => {}, expiredLease);
  const fresh = structuredClone(context); fresh.expected.challenge[0] ^= 1;
  await rejectsHost('old valid proof cannot satisfy a new verifier challenge', () => {}, fresh);
  await rejectsHost('host rejects corrupted proof bytes', changed => {
    changed.proof = (changed.proof.startsWith('00') ? '01' : '00') + changed.proof.slice(2);
  });
  await verifier.verify(record, context);
  check(true, 'valid peer proof still verifies after all negative cases');
  // This return is exclusively peer-channel/test evidence. It contains neither
  // balances nor private openings, but reveals this pair and must not be logged
  // or submitted with either member's named account request.
  return { mode: PEER_MODE, checks, presentation: record, proofBytes: proof.proof.length,
    witnessMs, provingMs, verificationMs, elapsedMs: performance.now() - began,
    challengeConsumed: false, protectedReleaseAuthorized: false };
}
