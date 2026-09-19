import { decode, digest, exact, json, reject, utf8 } from './crypto.js';

function issuerCopy(issuer) {
  exact(issuer, ['schemaId', 'credentialDefinitionId']);
  if (typeof issuer.schemaId !== 'string' || !issuer.schemaId ||
      typeof issuer.credentialDefinitionId !== 'string' || !issuer.credentialDefinitionId) reject();
  return issuer;
}
async function decimalDigest(bytes) {
  return BigInt(`0x${Array.from(decode(await digest(bytes), 32), value => value.toString(16).padStart(2, '0')).join('')}`).toString(10);
}
async function encoded(raw) {
  if (/^-?[0-9]+$/.test(raw)) {
    const value = BigInt(raw);
    if (value >= -2147483648n && value <= 2147483647n) return value.toString(10);
  }
  return decimalDigest(utf8.encode(raw));
}
/** Same cvld AnonCreds request shape as the owner-direct experiment. The
 * application supplies its actual wallet/proof verifier; no synthetic proof
 * or public admission certificate substitutes for private holder possession. */
export async function profileEligibilityRequest(issuer, challengeBytes, challenge) {
  issuerCopy(issuer);
  const restrictions = [{ cred_def_id: issuer.credentialDefinitionId }];
  return { name: 'cfrm-profile-key', version: '1', nonce: await decimalDigest(challengeBytes),
    requested_attributes: Object.fromEntries(['community_id', 'policy'].map(name => [name, { name, restrictions }])),
    requested_predicates: {
      eligible: { name: 'eligible', p_type: '>=', p_value: 1, restrictions },
      valid_until: { name: 'valid_until', p_type: '>=', p_value: challenge.expiresAt, restrictions },
    } };
}
/** Reject unsolicited identifying disclosures before invoking a wallet/verifier. */
export async function validateEligibilityPresentation(proof, issuer, challenge, maxProofBytes) {
  issuerCopy(issuer);
  if (!proof || typeof proof !== 'object' || json(proof).length > maxProofBytes) reject();
  exact(proof, ['proof', 'requested_proof', 'identifiers']);
  const requested = proof.requested_proof;
  exact(requested, ['revealed_attrs', 'self_attested_attrs', 'unrevealed_attrs', 'predicates']);
  exact(requested.revealed_attrs, ['community_id', 'policy']);
  exact(requested.self_attested_attrs, []); exact(requested.unrevealed_attrs, []);
  exact(requested.predicates, ['eligible', 'valid_until']);
  for (const [name, raw] of [['community_id', challenge.communityId], ['policy', challenge.policyDigest]]) {
    const value = requested.revealed_attrs[name];
    exact(value, ['sub_proof_index', 'raw', 'encoded']);
    if (value.sub_proof_index !== 0 || value.raw !== raw || value.encoded !== await encoded(raw)) reject();
  }
  for (const value of Object.values(requested.predicates)) {
    exact(value, ['sub_proof_index']); if (value.sub_proof_index !== 0) reject();
  }
  if (!Array.isArray(proof.identifiers) || proof.identifiers.length !== 1) reject();
  const identifier = proof.identifiers[0];
  exact(identifier, ['schema_id', 'cred_def_id', 'rev_reg_id', 'timestamp']);
  if (identifier.schema_id !== issuer.schemaId || identifier.cred_def_id !== issuer.credentialDefinitionId ||
      identifier.rev_reg_id !== null || identifier.timestamp !== null) reject();
}
