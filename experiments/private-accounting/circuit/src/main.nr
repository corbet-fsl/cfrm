// EXPERIMENT ONLY: one reserved obligation -> one authenticated close/answer.
// No genesis, refill, arbitrary pending map, policy selection or production admission.
use sha2lib::digest;

fn leaf(community: [u8; 32], member: [u8; 32], key: [u8; 64], secret_hash: [u8; 32], start: u64, end: u64) -> [u8; 32] {
    let mut bytes = [0; 177];
    bytes[0] = 1;
    for i in 0..32 { bytes[1+i] = community[i]; bytes[33+i] = member[i]; bytes[129+i] = secret_hash[i]; }
    for i in 0..64 { bytes[65+i] = key[i]; }
    let a: [u8; 8] = (start as Field).to_be_bytes();
    let b: [u8; 8] = (end as Field).to_be_bytes();
    for i in 0..8 { bytes[161+i] = a[i]; bytes[169+i] = b[i]; }
    digest(bytes)
}

fn node(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut bytes = [0; 65]; bytes[0] = 6;
    for i in 0..32 { bytes[1+i] = a[i]; bytes[33+i] = b[i]; }
    digest(bytes)
}

fn membership(value: [u8; 32], path: [[u8; 32]; 2], index: u8, root: [u8; 32]) {
    assert(index < 4);
    let mut current = value;
    for level in 0..2 {
        current = if ((index >> (level as u8)) & 1) == 0 { node(current, path[level]) } else { node(path[level], current) };
    }
    assert(current == root);
}

fn secret_commitment(community: [u8; 32], secret: [u8; 32]) -> [u8; 32] {
    let mut bytes = [0; 65]; bytes[0] = 2;
    for i in 0..32 { bytes[1+i] = community[i]; bytes[33+i] = secret[i]; }
    digest(bytes)
}

fn state(community: [u8; 32], owner: [u8; 32], secret_hash: [u8; 32], balance: u32,
    role: u8, peer: [u8; 32], nonce: [u8; 32], group: [u8; 32], reserved: u32, blind: [u8; 32]) -> [u8; 32] {
    let mut bytes = [0; 234]; bytes[0] = 3;
    for i in 0..32 {
        bytes[1+i] = community[i]; bytes[33+i] = owner[i]; bytes[65+i] = secret_hash[i];
        bytes[102+i] = peer[i]; bytes[134+i] = nonce[i]; bytes[166+i] = group[i]; bytes[202+i] = blind[i];
    }
    let b: [u8; 4] = (balance as Field).to_be_bytes();
    let r: [u8; 4] = (reserved as Field).to_be_bytes();
    for i in 0..4 { bytes[97+i] = b[i]; bytes[198+i] = r[i]; }
    bytes[101] = role;
    digest(bytes)
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
    let mut event = [0; 161]; event[0] = 5;
    for i in 0..32 {
        event[1+i] = community[i]; event[33+i] = owner_secret[i]; event[65+i] = owner[i];
        event[97+i] = peer[i]; event[129+i] = nonce[i];
    }
    assert(digest(event) == spent_marker);
}
