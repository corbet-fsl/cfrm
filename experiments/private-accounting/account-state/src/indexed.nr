// Indexed Merkle construction: full ordered keys, append-only positions.
// https://docs.aztec.network/developers/docs/foundational-topics/advanced/storage/indexed_merkle_tree
// Depth is implementation capacity; it does not select a contact allowance.
use p2hash::poseidon2::Poseidon2;

// ASCII cfrm.account-state.v2, independent of enrollment/secret/marker domains.
global DOMAIN: Field = 0x6366726d2e6163636f756e742d73746174652e7632;
global LIMIT: u64 = 4294967296;

pub fn hash<let N: u32>(values: [Field; N]) -> Field {
    Poseidon2::hash(values, N)
}

pub fn node(left: Field, right: Field) -> Field {
    hash([DOMAIN, 13, left, right])
}

// Leaf = [full key, payload commitment, next index, full next key].
pub fn leaf(value: [Field; 4]) -> Field {
    hash([DOMAIN, 12, value[0], value[1], value[2], value[3]])
}

fn halves(value: Field) -> [u128; 2] {
    let bytes: [u8; 32] = value.to_be_bytes();
    let mut high: u128 = 0; let mut low: u128 = 0;
    for i in 0..16 {
        high = high * 256 + bytes[i] as u128;
        low = low * 256 + bytes[16+i] as u128;
    }
    [high, low]
}

pub fn less(left: Field, right: Field) -> bool {
    // Compare canonical representatives, never a truncated field subtraction.
    let a = halves(left); let b = halves(right);
    (a[0] < b[0]) | ((a[0] == b[0]) & (a[1] < b[1]))
}

pub fn root(value: Field, path: [Field; 32], index: u32) -> Field {
    let mut current = value;
    for level in 0..32 {
        let left = ((index >> (level as u32)) & 1) == 0;
        current = node(if left { current } else { path[level] },
            if left { path[level] } else { current });
    }
    current
}

pub fn initial_root() -> Field {
    let mut sentinel = leaf([0; 4]);
    let mut empty: Field = 0;
    for _ in 0..32 {
        sentinel = node(sentinel, empty);
        empty = node(empty, empty);
    }
    sentinel
}

fn valid_leaf(value: [Field; 4], index: u32, count: u64) {
    assert((count >= 1) & (count <= LIMIT));
    assert((index as u64) < count);
    assert((value[0] == 0) == (index == 0));
    if index == 0 { assert(value[1] == 0); }
    let next = value[2] as u32;
    assert(value[2] == next as Field);
    assert((next as u64) < count);
    assert((next == 0) == (value[3] == 0));
    if next != 0 {
        assert(next != index);
        assert(less(value[0], value[3]));
    }
}

pub fn absent(current_root: Field, count: u64, key: Field,
    low: [Field; 4], index: u32, path: [Field; 32]) {
    assert(key != 0);
    valid_leaf(low, index, count);
    assert(root(leaf(low), path, index) == current_root);
    assert(less(low[0], key));
    assert((low[3] == 0) | less(key, low[3]));
}

pub fn insert(current_root: Field, count: u64, key: Field, payload: Field,
    low: [Field; 4], low_index: u32, low_path: [Field; 32],
    append_path: [Field; 32]) -> Field {
    assert(count < LIMIT);
    absent(current_root, count, key, low, low_index, low_path);
    let append = count as u32;
    assert(low_index != append);
    let linked_low = [low[0], low[1], append as Field, key];
    let intermediate = root(leaf(linked_low), low_path, low_index);
    // The appended position must be empty in the UPDATED predecessor root.
    // Checking its path against the original root would drop the link update.
    assert(root(0, append_path, append) == intermediate);
    let added = [key, payload, low[2], low[3]];
    root(leaf(added), append_path, append)
}

pub fn update(current_root: Field, count: u64, key: Field,
    old_payload: Field, new_payload: Field, value: [Field; 4],
    index: u32, path: [Field; 32]) -> Field {
    assert(key != 0);
    valid_leaf(value, index, count);
    assert((value[0] == key) & (value[1] == old_payload));
    assert(root(leaf(value), path, index) == current_root);
    // Full key and both pointers survive every payload/phase update.
    root(leaf([value[0], new_payload, value[2], value[3]]), path, index)
}

pub fn present(current_root: Field, count: u64, key: Field, payload: Field,
    value: [Field; 4], index: u32, path: [Field; 32]) {
    valid_leaf(value, index, count);
    assert((key != 0) & (value[0] == key) & (value[1] == payload));
    assert(root(leaf(value), path, index) == current_root);
}
