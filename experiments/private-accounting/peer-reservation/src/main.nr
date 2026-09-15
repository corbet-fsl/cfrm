// Peer-only membership presentation. The host separately verifies the genuine
// operator acceptance, common account circuit/VK, current policy and cmsg state.
// It is not a named operator account transition and must never be sent as one.
use p2hash::poseidon2::Poseidon2;

global ACCOUNT_DOMAIN: Field = 0x6366726d2e6163636f756e742d73746174652e7632;
global LEGACY_DOMAIN: Field = 0x6366726d2e6163636f756e74696e672e706f736569646f6e322e7631;
global PEER_DOMAIN: Field = 0x6366726d2e706565722d7265736572766174696f6e2e7633;
global SAFE: u64 = 9007199254740991;
global LIMIT: u64 = 4294967296;

struct Opening {
    available: u32, reserved: u128,
    outgoing_root: Field, outgoing_count: u64,
    incoming_root: Field, incoming_count: u64,
    pair_root: Field, pair_count: u64,
    frontier: u64, created_at: u64, admission_epoch: u64, admissions: u32, blind: [u8; 32],
}

struct Membership { leaf: [Field; 4], index: u32, path: [Field; 32] }

fn limbs(bytes: [u8; 32]) -> [Field; 2] {
    let mut high: u128 = 0; let mut low: u128 = 0;
    for i in 0..16 {
        high = high * 256 + bytes[i] as u128;
        low = low * 256 + bytes[16+i] as u128;
    }
    [high as Field, low as Field]
}
fn field(bytes: [u8; 32]) -> Field { Field::from_be_bytes_checked(bytes) }
fn hash<let N: u32>(values: [Field; N]) -> Field { Poseidon2::hash(values, N) }

fn secret_hash(community: [u8; 32], secret: [u8; 32]) -> Field {
    let c = limbs(community); let s = limbs(secret);
    hash([LEGACY_DOMAIN, 2, c[0], c[1], s[0], s[1]])
}
fn event_key(community: [u8; 32], owner: [u8; 32], secret: [u8; 32], peer: [u8; 32], nonce: [u8; 32]) -> Field {
    let c = limbs(community); let o = limbs(owner); let s = limbs(secret);
    let p = limbs(peer); let n = limbs(nonce);
    hash([LEGACY_DOMAIN, 5, c[0], c[1], s[0], s[1], o[0], o[1], p[0], p[1], n[0], n[1]])
}
fn state_hash(community: [u8; 32], owner: [u8; 32], policy: [u8; 32],
    secret: Field, version: u64, state: Opening) -> Field {
    let c = limbs(community); let o = limbs(owner); let p = limbs(policy); let b = limbs(state.blind);
    hash([ACCOUNT_DOMAIN, 3, c[0], c[1], o[0], o[1], p[0], p[1], secret, version as Field,
        state.available as Field, state.reserved as Field,
        state.outgoing_root, state.outgoing_count as Field,
        state.incoming_root, state.incoming_count as Field,
        state.pair_root, state.pair_count as Field, state.frontier as Field,
        state.created_at as Field, state.admission_epoch as Field, state.admissions as Field, b[0], b[1]])
}
fn slot_hash(event: Field, role: u8, peer: [u8; 32], nonce: [u8; 32], group: [u8; 32],
    contact_policy: [u8; 32], amount: u32, phase: u8, admitted_at: u64, expires_at: u64, peer_authority: Field, owner_authority: Field) -> Field {
    let p = limbs(peer); let n = limbs(nonce); let g = limbs(group); let c = limbs(contact_policy);
    hash([ACCOUNT_DOMAIN, 4, event, role as Field, p[0], p[1], n[0], n[1], g[0], g[1],
        c[0], c[1], amount as Field, phase as Field, admitted_at as Field, expires_at as Field, peer_authority, owner_authority])
}
fn membership(root: Field, count: u64, event: Field, payload: Field, witness: Membership) {
    assert((count > 1) & (count <= LIMIT));
    assert((witness.index > 0) & ((witness.index as u64) < count));
    assert(witness.leaf[0] == event);
    assert(witness.leaf[1] == payload);
    // Pointer correctness/order follows from the accepted account's reachable
    // root invariant. Membership authenticates the unchanged complete leaf.
    let mut current = hash([ACCOUNT_DOMAIN, 12, witness.leaf[0], witness.leaf[1], witness.leaf[2], witness.leaf[3]]);
    for level in 0..32 {
        let left = ((witness.index >> (level as u32)) & 1) == 0;
        current = hash([ACCOUNT_DOMAIN, 13,
            if left { current } else { witness.path[level] },
            if left { witness.path[level] } else { current }]);
    }
    assert(current == root);
}

fn main(
    community: pub [u8; 32], owner: pub [u8; 32], peer: pub [u8; 32], role: pub u8,
    nonce: pub [u8; 32], group: pub [u8; 32], contact_policy_digest: pub [u8; 32],
    history_digest: pub [u8; 32], phase: pub u8, opened_at: pub u64, expires_at: pub u64, owner_authority: pub [u8; 32], state_policy_digest: pub [u8; 32],
    state_version: pub u64, state_commitment: pub [u8; 32], challenge: pub [u8; 32],
    presentation_binding: pub [u8; 32],
    owner_secret: [u8; 32], opening: Opening, selected: Membership,
    amount: u32, peer_authority: Field,
) {
    assert(owner != peer);
    assert(role <= 1);
    assert((phase == 1) | (phase == 2)); // Settled is never release evidence.
    assert((state_version > 0) & (state_version <= SAFE));
    assert(challenge != [0; 32]);
    assert(nonce != [0; 32]);
    assert((amount > 0) & (opened_at > 0) & (opened_at <= SAFE));
    assert((expires_at > opened_at) & (expires_at <= SAFE));
    assert(opening.frontier <= SAFE);
    assert((opening.created_at > 0) & (opening.created_at <= opening.frontier));
    assert(opening.admission_epoch <= SAFE);
    assert((opening.outgoing_count > 0) & (opening.outgoing_count <= LIMIT));
    assert((opening.incoming_count > 0) & (opening.incoming_count <= LIMIT));
    assert((opening.pair_count > 0) & (opening.pair_count <= LIMIT));
    let state = field(state_commitment);
    assert(state != 0);
    assert(state == state_hash(community, owner, state_policy_digest,
        secret_hash(community, owner_secret), state_version, opening));
    let event = event_key(community, owner, owner_secret, peer, nonce);
    assert(event != 0);
    let payload = slot_hash(event, role, peer, nonce, group, contact_policy_digest,
        amount, phase, opened_at, expires_at, peer_authority, field(owner_authority));
    membership(if role == 0 { opening.outgoing_root } else { opening.incoming_root },
        if role == 0 { opening.outgoing_count } else { opening.incoming_count }, event, payload, selected);
    // History is authenticated presentation context, not a field in the old
    // reservation. The host must obtain its expected value from actual cmsg.
    let s = limbs(owner_secret); let c = limbs(challenge); let h = limbs(history_digest);
    assert(field(presentation_binding) == hash([PEER_DOMAIN, 1, s[0], s[1], state, payload, c[0], c[1], h[0], h[1]]));
}
