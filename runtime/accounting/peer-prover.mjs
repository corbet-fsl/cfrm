// Shared production proving step for the existing peer-reservation-v3 circuit.
// The returned presentation belongs only on the authenticated peer channel.
import { OPTIONS, hex } from './encoding.mjs';
import { noirInput } from './hashes.mjs';
import { publicInputValues } from './peer-witness.mjs';
import { validateAcceptedContext } from './peer-verifier.mjs';

export async function provePeerCandidate({ noir, backend, verifier, candidate, accountAcceptance,
  context, peerProofScope, accountProofScope, verifyAccountAcceptance, maxProofBytes }) {
  if (!Number.isSafeInteger(maxProofBytes) || maxProofBytes <= 0 || maxProofBytes > 1024 * 1024) throw new Error('Peer proof limit');
  const snapshot = structuredClone(candidate), trusted = structuredClone(context);
  const record = { version: 3, statement: snapshot.statement, proofScope: structuredClone(peerProofScope),
    proof: '', accountAcceptance: structuredClone(accountAcceptance) };
  Object.assign(trusted, { peerProofScope: structuredClone(peerProofScope), accountProofScope: structuredClone(accountProofScope) });
  await validateAcceptedContext(record, trusted, verifyAccountAcceptance);
  const execution = await noir.execute(noirInput(snapshot.input));
  const proof = await backend.generateProof(execution.witness, OPTIONS);
  const expected = publicInputValues(record.statement);
  if (proof.proof.length > maxProofBytes || proof.publicInputs.length !== expected.length
      || !proof.publicInputs.every((value, index) => BigInt(value) === expected[index])) {
    throw new Error('Peer prover public input/size mismatch');
  }
  record.proof = hex(proof.proof);
  await verifier.verify(record, trusted);
  return record;
}
