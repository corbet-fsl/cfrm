// EXPERIMENT ONLY: one reserved obligation -> one authenticated close/answer.
// No genesis, refill, arbitrary pending map, policy selection or production admission.
use sha2lib::digest;
use p2hash::poseidon2::Poseidon2;

// ASCII cfrm.accounting.poseidon2.v1, below the BN254 scalar modulus.
global DOMAIN: Field = 0x6366726d2e6163636f756e74696e672e706f736569646f6e322e7631;

fn limbs32(bytes: [u8; 32]) -> [Field; 2] {
    let mut high: u128 = 0;
    let mut low: u128 = 0;
    for i in 0..16 {
        high = high * 256 + bytes[i] as u128;
        low = low * 256 + bytes[16+i] as u128;
    }
    [high as Field, low as Field]
}

fn canonical(bytes: [u8; 32]) -> Field {
    Field::from_be_bytes_checked(bytes)
}

fn fixed_hash<let N: u32>(fields: [Field; N]) -> [u8; 32] {
    // The upstream fixed-length sponge receives its compile-time arity only.
    Poseidon2::hash(fields, N).to_be_bytes()
}

fn leaf(community: [u8; 32], member: [u8; 32], key: [u8; 64], secret_hash: [u8; 32], start: u64, end: u64) -> [u8; 32] {
    let c = limbs32(community); let m = limbs32(member);
    let mut x = [0; 32]; let mut y = [0; 32];
    for i in 0..32 { x[i] = key[i]; y[i] = key[32+i]; }
    let a = limbs32(x); let b = limbs32(y);
    fixed_hash([DOMAIN, 1, c[0], c[1], m[0], m[1], a[0], a[1], b[0], b[1],
        canonical(secret_hash), start as Field, end as Field])
}

fn node(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    fixed_hash([DOMAIN, 6, canonical(a), canonical(b)])
}

fn membership(value: [u8; 32], path: [[u8; 32]; 2], index: u8, root: [u8; 32]) {
    assert(index < 4);
    let mut current = value;
    for level in 0..2 {
        let is_left = ((index >> (level as u8)) & 1) == 0;
        let left = if is_left { current } else { path[level] };
        let right = if is_left { path[level] } else { current };
        current = node(left, right);
    }
    assert(current == root);
}

fn secret_commitment(community: [u8; 32], secret: [u8; 32]) -> [u8; 32] {
    let c = limbs32(community); let s = limbs32(secret);
    fixed_hash([DOMAIN, 2, c[0], c[1], s[0], s[1]])
}

fn state(community: [u8; 32], owner: [u8; 32], secret_hash: [u8; 32], balance: u32,
    role: u8, peer: [u8; 32], nonce: [u8; 32], group: [u8; 32], reserved: u32, blind: [u8; 32]) -> [u8; 32] {
    let c = limbs32(community); let o = limbs32(owner); let p = limbs32(peer);
    let n = limbs32(nonce); let g = limbs32(group); let b = limbs32(blind);
    fixed_hash([DOMAIN, 3, c[0], c[1], o[0], o[1], canonical(secret_hash),
        balance as Field, role as Field, p[0], p[1], n[0], n[1], g[0], g[1],
        reserved as Field, b[0], b[1]])
}

fn event_marker(community: [u8; 32], secret: [u8; 32], owner: [u8; 32], peer: [u8; 32], nonce: [u8; 32]) -> [u8; 32] {
    let c = limbs32(community); let s = limbs32(secret); let o = limbs32(owner);
    let p = limbs32(peer); let n = limbs32(nonce);
    fixed_hash([DOMAIN, 5, c[0], c[1], s[0], s[1], o[0], o[1], p[0], p[1], n[0], n[1]])
}

fn receipt(community: [u8; 32], responder: [u8; 32], peer: [u8; 32], nonce: [u8; 32],
    group: [u8; 32], kind: u8, issued: u64) -> [u8; 32] {
    let mut bytes = [0; 170]; bytes[0] = 4;
    for i in 0..32 {
        bytes[1+i] = community[i]; bytes[33+i] = responder[i]; bytes[65+i] = peer[i];
        bytes[97+i] = nonce[i]; bytes[129+i] = group[i];
    }
    bytes[161] = kind;
    let t: [u8; 8] = (issued as Field).to_be_bytes();
    for i in 0..8 { bytes[162+i] = t[i]; }
    digest(bytes)
}

fn main(
    community: pub [u8; 32], enrollment_root: pub [u8; 32], owner: pub [u8; 32],
    old_state: pub [u8; 32], new_state: pub [u8; 32], spent_marker: pub [u8; 32], now: pub u64,
    owner_secret: [u8; 32], owner_key: [u8; 64], owner_start: u64, owner_end: u64,
    owner_path: [[u8; 32]; 2], owner_index: u8,
    peer: [u8; 32], peer_key: [u8; 64], peer_secret_hash: [u8; 32], peer_start: u64, peer_end: u64,
    peer_path: [[u8; 32]; 2], peer_index: u8,
    balance: u32, reserved: u32, role: u8, nonce: [u8; 32], group: [u8; 32],
    old_blind: [u8; 32], new_blind: [u8; 32], kind: u8, issued: u64, signature: [u8; 64],
) {
    assert(owner != peer);
    assert(owner_index != peer_index);
    assert((owner_start > 0) & (peer_start > 0));
    assert((owner_start <= issued) & (issued < owner_end));
    assert((peer_start <= issued) & (issued < peer_end));
    assert((issued <= now) & (now < owner_end) & (now < peer_end));
    assert(reserved > 0);
    assert(role < 2);
    assert((kind == 1) | (kind == 2));
    // Recipient may prove its own closure. Its own declaration of an answer
    // cannot stand in for authenticated evidence of a counterpart response.
    if role == 1 { assert(kind == 2); }
    let owner_hash = secret_commitment(community, owner_secret);
    membership(leaf(community, owner, owner_key, owner_hash, owner_start, owner_end), owner_path, owner_index, enrollment_root);
    membership(leaf(community, peer, peer_key, peer_secret_hash, peer_start, peer_end), peer_path, peer_index, enrollment_root);
    assert(state(community, owner, owner_hash, balance, role, peer, nonce, group, reserved, old_blind) == old_state);
    // Bounded integer addition rejects overflow. This is release of already
    // reserved units, not an invented production answer reward formula.
    let next_balance: u32 = balance + reserved;
    assert(state(community, owner, owner_hash, next_balance, 0, [0; 32], [0; 32], [0; 32], 0, new_blind) == new_state);
    let responder = if role == 0 { peer } else { owner };
    let other = if role == 0 { owner } else { peer };
    let signer_key = if role == 0 { peer_key } else { owner_key };
    let mut x = [0; 32]; let mut y = [0; 32];
    for i in 0..32 { x[i] = signer_key[i]; y[i] = signer_key[32+i]; }
    assert(std::ecdsa_secp256r1::verify_signature(x, y, signature, receipt(community, responder, other, nonce, group, kind, issued)));
    // Same owner gets the same event marker across direction/signature renewal.
    // It is secret-keyed and never shared between the two named endpoints.
    assert(event_marker(community, owner_secret, owner, peer, nonce) == spent_marker);
}
