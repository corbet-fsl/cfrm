// Private witness adapter: reuse the actual account-state helper and map paths.
// Nothing returned as `input` may enter a named request or an evidence log.
import { fieldBytes, fieldValue, limbs32 } from '../hashes.mjs';
import { SAFE } from '../account-state/hashes.mjs';

export const PEER_MODE = 'peer-reservation-v3';
export const PEER_DOMAIN = 0x6366726d2e706565722d7265736572766174696f6e2e7633n;
export const PUBLIC_INPUT_COUNT = 389;
export const STATEMENT_KEYS = ['community','owner','peer','role','nonce','group','contactPolicyDigest',
  'historyDigest','phase','openedAt','expiresAt','ownerAuthority','statePolicyDigest','stateVersion','stateCommitment','challenge','presentationBinding'];
export const EXPECTED_KEYS = STATEMENT_KEYS.filter(name => name !== 'presentationBinding');
export const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
export function bytes32(value) {
  if (!Array.isArray(value) || value.length !== 32 || value.some(v => !Number.isInteger(v) || v < 0 || v > 255)) throw new Error('Noncanonical bytes32');
  return Uint8Array.from(value);
}
export function safeInteger(value) {
  if (!Number.isSafeInteger(value) || value < 0 || BigInt(value) > SAFE) throw new Error('Unsafe peer statement integer');
  return BigInt(value);
}
export const equalBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

export function publicInputValues(statement) {
  if (!exact(statement, STATEMENT_KEYS)) throw new Error('Peer statement field set');
  const s = statement;
  if (![0, 1].includes(s.role) || ![1, 2].includes(s.phase) || safeInteger(s.stateVersion) === 0n || safeInteger(s.openedAt) === 0n) throw new Error('Peer role/phase/version/opened-at');
  if (safeInteger(s.expiresAt) <= safeInteger(s.openedAt)) throw new Error('Peer original lease expiry');
  const bytes = name => Array.from(bytes32(s[name]), BigInt);
  for (const name of ['ownerAuthority','stateCommitment','presentationBinding']) fieldValue(bytes32(s[name]));
  if (!s.challenge.some(Boolean) || !s.nonce.some(Boolean) || !s.stateCommitment.some(Boolean)
      || equalBytes(s.owner, s.peer)) throw new Error('Peer challenge/nonce/state/identity');
  const values = [...bytes('community'), ...bytes('owner'), ...bytes('peer'), BigInt(s.role),
    ...bytes('nonce'), ...bytes('group'), ...bytes('contactPolicyDigest'), ...bytes('historyDigest'), BigInt(s.phase),
    safeInteger(s.openedAt), safeInteger(s.expiresAt), ...bytes('ownerAuthority'), ...bytes('statePolicyDigest'), safeInteger(s.stateVersion), ...bytes('stateCommitment'), ...bytes('challenge'), ...bytes('presentationBinding')];
  if (values.length !== PUBLIC_INPUT_COUNT) throw new Error('Peer public input count');
  return values;
}

export async function presentationBinding(api, ownerSecret, stateCommitment, payload, challenge, historyDigest) {
  return fieldValue((await api.poseidon2Hash({ inputs: [PEER_DOMAIN, 1n, ...limbs32(ownerSecret),
    fieldValue(stateCommitment), payload, ...limbs32(challenge), ...limbs32(historyDigest)].map(fieldBytes) })).hash);
}

export async function preparePeerReservation({ api, state, event, historyDigest, challenge }) {
  // `state` must be the retained opening for a real accepted AccountWitness,
  // not merely a locally computed candidate. The verifier checks its certificate.
  const slot = state.slots.get(event.toString());
  if (!slot || ![1, 2].includes(slot.phase)) throw new Error('No live reservation');
  if (!(historyDigest instanceof Uint8Array) || !(challenge instanceof Uint8Array)) throw new Error('Peer context bytes');
  const selectedMap = slot.role === 0 ? state.outgoing : state.incoming;
  const found = selectedMap.find(event); if (!found) throw new Error('Missing selected reservation leaf');
  const selected = selectedMap.witness(found[0]);
  const payload = await state.hashes.obligation(event, slot, slot.phase);
  if (selected.leaf[1] !== payload) throw new Error('Private slot differs from authenticated map');
  const commitment = fieldBytes(state.commitment);
  const binding = await presentationBinding(api, state.ownerSecret, commitment, payload, challenge, historyDigest);
  const statement = { community: Array.from(state.community), owner: Array.from(state.owner.member), peer: Array.from(slot.peer),
    role: slot.role, nonce: Array.from(slot.nonce), group: Array.from(slot.group), contactPolicyDigest: Array.from(slot.contactPolicy),
    historyDigest: Array.from(historyDigest), phase: slot.phase, openedAt: Number(slot.admittedAt), expiresAt: Number(slot.expiresAt),
    ownerAuthority: Array.from(fieldBytes(slot.ownerAuthority)), statePolicyDigest: Array.from(state.statePolicyHash),
    stateVersion: Number(state.version), stateCommitment: Array.from(commitment), challenge: Array.from(challenge),
    presentationBinding: Array.from(fieldBytes(binding)) };
  publicInputValues(statement);
  const o = state.opening;
  return { statement, input: { community: state.community, owner: state.owner.member, peer: slot.peer, role: slot.role,
    nonce: slot.nonce, group: slot.group, contact_policy_digest: slot.contactPolicy, history_digest: historyDigest,
    phase: slot.phase, opened_at: slot.admittedAt, expires_at: slot.expiresAt, state_policy_digest: state.statePolicyHash, state_version: state.version, state_commitment: commitment,
    challenge, presentation_binding: fieldBytes(binding), owner_secret: state.ownerSecret,
    opening: { available: o.available, reserved: o.reserved, outgoing_root: o.outgoingRoot, outgoing_count: o.outgoingCount,
      incoming_root: o.incomingRoot, incoming_count: o.incomingCount, pair_root: o.pairRoot, pair_count: o.pairCount,
      frontier: o.frontier, created_at: o.createdAt, admission_epoch: o.admissionEpoch, admissions: o.admissions, blind: o.blind },
    selected: { leaf: selected.leaf, index: selected.index, path: selected.path },
    amount: slot.amount, peer_authority: slot.peerAuthority, owner_authority: fieldBytes(slot.ownerAuthority) } };
}
