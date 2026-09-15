// Versioned private lifecycle. No Answer reward, private protected-release
// integration, v1 migration or production enablement is implied.
mod indexed;
use sha2lib::digest;
use p2hash::poseidon2::Poseidon2;

global DOMAIN: Field = 0x6366726d2e6163636f756e742d73746174652e7632;
// Preserve the measured P2 secret and owner/event marker namespaces.
global LEGACY_DOMAIN: Field = 0x6366726d2e6163636f756e74696e672e706f736569646f6e322e7631;
global SAFE: u64 = 9007199254740991;

struct Enrollment {
    key: [u8; 64], secret_hash: [u8; 32], start: u64, end: u64,
    delegation_digest: [u8; 32], path: [Field; 32], index: u32,
}

struct Opening {
    available: u32, reserved: u128,
    outgoing_root: Field, outgoing_count: u64,
    incoming_root: Field, incoming_count: u64,
    pair_root: Field, pair_count: u64,
    frontier: u64, created_at: u64, admission_epoch: u64, admissions: u32, blind: [u8; 32],
}

struct Obligation {
    role: u8, peer: [u8; 32], nonce: [u8; 32], group: [u8; 32],
    contact_policy: [u8; 32], amount: u32, phase: u8,
    admitted_at: u64, expires_at: u64, peer_authority: Field, owner_authority: Field,
}

struct MapWitness {
    leaf: [Field; 4], index: u32, path: [Field; 32], append_path: [Field; 32],
}

struct Resolution {
    kind: u8, issued_at: u64, history_digest: [u8; 32],
    ed25519_receipt_digest: [u8; 32], signature: [u8; 64],
}

struct Acknowledgment { issued_at: u64, signature: [u8; 64] }

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

fn marker(community: [u8; 32], owner: [u8; 32], secret: [u8; 32], peer: [u8; 32], nonce: [u8; 32]) -> Field {
    let c = limbs(community); let o = limbs(owner); let s = limbs(secret);
    let p = limbs(peer); let n = limbs(nonce);
    hash([LEGACY_DOMAIN, 5, c[0], c[1], s[0], s[1], o[0], o[1], p[0], p[1], n[0], n[1]])
}

fn pair_key(community: [u8; 32], owner: [u8; 32], secret: [u8; 32], peer: [u8; 32]) -> Field {
    let c = limbs(community); let o = limbs(owner); let s = limbs(secret); let p = limbs(peer);
    hash([DOMAIN, 5, c[0], c[1], s[0], s[1], o[0], o[1], p[0], p[1]])
}

fn enrollment_leaf(community: [u8; 32], member: [u8; 32], enrolled: Enrollment) -> Field {
    let c = limbs(community); let m = limbs(member); let d = limbs(enrolled.delegation_digest);
    let mut x = [0; 32]; let mut y = [0; 32];
    for i in 0..32 { x[i] = enrolled.key[i]; y[i] = enrolled.key[32+i]; }
    let a = limbs(x); let b = limbs(y);
    hash([DOMAIN, 1, c[0], c[1], m[0], m[1], a[0], a[1], b[0], b[1],
        field(enrolled.secret_hash), enrolled.start as Field, enrolled.end as Field, d[0], d[1]])
}

fn verify_enrollment(community: [u8; 32], member: [u8; 32], enrolled: Enrollment,
    checkpoint: Field, now: u64, valid_until: u64) {
    assert((enrolled.start > 0) & (enrolled.start <= now) & (now < enrolled.end));
    assert(enrolled.end >= valid_until);
    assert(enrolled.end <= SAFE);
    assert(enrolled.delegation_digest != [0; 32]);
    let mut current = enrollment_leaf(community, member, enrolled);
    for level in 0..32 {
        let left = ((enrolled.index >> (level as u32)) & 1) == 0;
        current = hash([LEGACY_DOMAIN, 6,
            if left { current } else { enrolled.path[level] },
            if left { enrolled.path[level] } else { current }]);
    }
    assert(current == checkpoint);
}

fn verify_peer_authority(community: [u8; 32], slot: Obligation, peer: Enrollment,
    checkpoint: Field, now: u64, valid_until: u64) {
    // Original peer authority was checked at reservation. Expiry does not
    // invalidate a receipt/ack signed within that historical validity period.
    // A different/renewed delegation needs current independent enrollment.
    if enrollment_leaf(community, slot.peer, peer) != slot.peer_authority {
        verify_enrollment(community, slot.peer, peer, checkpoint, now, valid_until);
    }
}

fn policy_bytes(community: [u8; 32], initial_credit: u32, maximum_available: u32,
    outgoing_reservation: u32, incoming_reservation: u32, revision: u64,
    valid_from: u64, valid_until: u64, newcomer_period: u64, rate_window: u64,
    newcomer_admissions: u32, maximum_admissions: u32, refill_period: u64,
    refill_units: u32, abandon_after: u64) -> [u8; 140] {
    // Existing fields, then the seven v2 parameters in their fixed wire order.
    let prefix: [u8; 23] = [99,102,114,109,46,97,99,99,111,117,110,116,45,112,111,108,105,99,121,46,118,50,0];
    let mut bytes = [0; 140];
    for i in 0..23 { bytes[i] = prefix[i]; }
    for i in 0..32 { bytes[23+i] = community[i]; }
    let amounts = [initial_credit, maximum_available, outgoing_reservation, incoming_reservation];
    for i in 0..4 {
        let encoded: [u8; 4] = (amounts[i] as Field).to_be_bytes();
        for j in 0..4 { bytes[55+i*4+j] = encoded[j]; }
    }
    let times = [revision, valid_from, valid_until, newcomer_period, rate_window];
    for i in 0..5 {
        let encoded: [u8; 8] = (times[i] as Field).to_be_bytes();
        for j in 0..8 { bytes[71+i*8+j] = encoded[j]; }
    }
    let caps = [newcomer_admissions, maximum_admissions];
    for i in 0..2 {
        let encoded: [u8; 4] = (caps[i] as Field).to_be_bytes();
        for j in 0..4 { bytes[111+i*4+j] = encoded[j]; }
    }
    let refill: [u8; 8] = (refill_period as Field).to_be_bytes();
    let units: [u8; 4] = (refill_units as Field).to_be_bytes();
    let abandon: [u8; 8] = (abandon_after as Field).to_be_bytes();
    for i in 0..8 { bytes[119+i] = refill[i]; bytes[131+i] = abandon[i]; }
    for i in 0..4 { bytes[127+i] = units[i]; }
    bytes[139] = 32;
    bytes
}

fn state_policy_hash(bytes: [u8; 140]) -> [u8; 32] {
    let prefix: [u8; 29] = [99,102,114,109,46,97,99,99,111,117,110,116,45,115,116,97,116,101,45,112,111,108,105,99,121,46,118,49,0];
    let mut stable = [0; 138];
    for i in 0..29 { stable[i] = prefix[i]; }
    for i in 0..32 { stable[29+i] = bytes[23+i]; }
    for i in 0..76 { stable[61+i] = bytes[55+i]; }
    stable[137] = 32;
    digest(stable)
}

fn state_hash(community: [u8; 32], owner: [u8; 32], policy: [u8; 32],
    secret: Field, version: u64, state: Opening) -> Field {
    let c = limbs(community); let o = limbs(owner); let p = limbs(policy); let b = limbs(state.blind);
    hash([DOMAIN, 3, c[0], c[1], o[0], o[1], p[0], p[1], secret, version as Field,
        state.available as Field, state.reserved as Field,
        state.outgoing_root, state.outgoing_count as Field,
        state.incoming_root, state.incoming_count as Field,
        state.pair_root, state.pair_count as Field, state.frontier as Field,
        state.created_at as Field, state.admission_epoch as Field, state.admissions as Field, b[0], b[1]])
}

fn obligation_hash(event: Field, slot: Obligation, phase: u8) -> Field {
    let p = limbs(slot.peer); let n = limbs(slot.nonce); let g = limbs(slot.group);
    let c = limbs(slot.contact_policy);
    hash([DOMAIN, 4, event, slot.role as Field, p[0], p[1], n[0], n[1], g[0], g[1],
        c[0], c[1], slot.amount as Field, phase as Field, slot.admitted_at as Field, slot.expires_at as Field, slot.peer_authority, slot.owner_authority])
}

fn receipt_bytes(community: [u8; 32], responder: [u8; 32], other: [u8; 32],
    slot: Obligation, delegation: [u8; 32], receipt: Resolution) -> [u8; 357] {
    let prefix: [u8; 27] = [99,109,115,103,46,97,99,99,111,117,110,116,105,110,103,45,114,101,99,101,105,112,116,46,118,49,0];
    let mut bytes = [0; 357];
    for i in 0..27 { bytes[i] = prefix[i]; }
    // The original initiator is the receipt's peer. Only the original recipient
    // can sign these decisions; sender self-cancellation is not a resolution.
    let fields = [community, responder, other, other, slot.nonce, slot.group,
        delegation, slot.contact_policy, receipt.history_digest, receipt.ed25519_receipt_digest];
    for i in 0..10 { for j in 0..32 { bytes[27+i*32+j] = fields[i][j]; } }
    bytes[347] = receipt.kind;
    bytes[348] = 1; // Authenticated original-recipient role, never sender.
    let time: [u8; 8] = (receipt.issued_at as Field).to_be_bytes();
    for i in 0..8 { bytes[349+i] = time[i]; }
    bytes
}

fn low_s(signature: [u8; 64]) {
    let mut high: u128 = 0; let mut low: u128 = 0;
    for i in 0..16 {
        high = high * 256 + signature[32+i] as u128;
        low = low * 256 + signature[48+i] as u128;
    }
    let half_high: u128 = 0x7fffffff800000007fffffffffffffff;
    let half_low: u128 = 0xde737d56d38bcf4279dce5617e3192a8;
    assert((high < half_high) | ((high == half_high) & (low <= half_low)));
}

fn verify_acknowledgment(community: [u8; 32], owner: [u8; 32], slot: Obligation,
    recipient: Enrollment, sender: Enrollment, receipt: Resolution,
    acknowledgment: Acknowledgment, now: u64) {
    assert(receipt.kind == 1);
    assert((acknowledgment.issued_at >= receipt.issued_at) & (acknowledgment.issued_at <= now));
    assert((sender.start <= acknowledgment.issued_at) & (acknowledgment.issued_at < sender.end));
    let receipt_prefix: [u8; 34] = [99,109,115,103,46,97,99,99,111,117,110,116,105,110,103,45,114,101,99,101,105,112,116,45,100,105,103,101,115,116,46,118,49,0];
    let answer = receipt_bytes(community, owner, slot.peer, slot, recipient.delegation_digest, receipt);
    let mut answer_bytes = [0; 455];
    for i in 0..34 { answer_bytes[i] = receipt_prefix[i]; }
    for i in 0..357 { answer_bytes[34+i] = answer[i]; }
    for i in 0..64 { answer_bytes[391+i] = receipt.signature[i]; }
    let answer_digest = digest(answer_bytes);
    let ack_prefix: [u8; 23] = [99,109,115,103,46,97,99,99,111,117,110,116,105,110,103,45,97,99,107,46,118,49,0];
    let mut bytes = [0; 255];
    for i in 0..23 { bytes[i] = ack_prefix[i]; }
    let fields = [community, slot.peer, owner, slot.nonce, slot.group, answer_digest, sender.delegation_digest];
    for i in 0..7 { for j in 0..32 { bytes[23+i*32+j] = fields[i][j]; } }
    let time: [u8; 8] = (acknowledgment.issued_at as Field).to_be_bytes();
    for i in 0..8 { bytes[247+i] = time[i]; }
    let mut x = [0; 32]; let mut y = [0; 32];
    for i in 0..32 { x[i] = sender.key[i]; y[i] = sender.key[32+i]; }
    low_s(acknowledgment.signature);
    assert(std::ecdsa_secp256r1::verify_signature(x, y, acknowledgment.signature, digest(bytes)));
}

fn verify_resolution(community: [u8; 32], owner: [u8; 32], slot: Obligation,
    signer: Enrollment, receipt: Resolution, now: u64) {
    assert((receipt.kind == 1) | (receipt.kind == 2));
    assert((receipt.issued_at >= slot.admitted_at) & (receipt.issued_at <= now));
    assert((signer.start <= receipt.issued_at) & (receipt.issued_at < signer.end));
    let responder = if slot.role == 0 { slot.peer } else { owner };
    let other = if slot.role == 0 { owner } else { slot.peer };
    let mut x = [0; 32]; let mut y = [0; 32];
    for i in 0..32 { x[i] = signer.key[i]; y[i] = signer.key[32+i]; }
    low_s(receipt.signature);
    assert(std::ecdsa_secp256r1::verify_signature(x, y, receipt.signature,
        digest(receipt_bytes(community, responder, other, slot, signer.delegation_digest, receipt))));
}

fn main(
    community: pub [u8; 32], owner: pub [u8; 32], policy_digest: pub [u8; 32],
    enrollment_root: pub [u8; 32], now: pub u64, valid_until: pub u64, genesis: pub bool,
    previous_version: pub u64, next_version: pub u64,
    previous_state: pub [u8; 32], next_state: pub [u8; 32], settlement_marker: pub [u8; 32],
    initial_credit: pub u32, maximum_available: pub u32,
    outgoing_reservation: pub u32, incoming_reservation: pub u32,
    policy_revision: pub u64, policy_valid_from: pub u64, policy_valid_until: pub u64,
    newcomer_period: pub u64, rate_window: pub u64, newcomer_admissions: pub u32,
    maximum_admissions: pub u32, refill_period: pub u64, refill_units: pub u32, abandon_after: pub u64,
    owner_secret: [u8; 32], owner_enrollment: Enrollment, peer_enrollment: Enrollment,
    receipt_owner_enrollment: Enrollment,
    old: Opening, new_blind: [u8; 32], action: u8, slot: Obligation,
    own_map: MapWitness, opposite_map: MapWitness, pair_map: MapWitness,
    pair_exists: bool, resolution: Resolution, acknowledgment: Acknowledgment,
) {
    assert((now > 0) & (now <= SAFE));
    assert((previous_version <= SAFE) & (next_version <= SAFE));
    assert((policy_revision > 0) & (policy_revision <= SAFE));
    assert((policy_valid_from > 0) & (policy_valid_from <= now));
    assert((now < policy_valid_until) & (policy_valid_until <= SAFE));
    assert((maximum_available > 0) & (initial_credit <= maximum_available));
    assert((outgoing_reservation > 0) & (outgoing_reservation <= initial_credit));
    assert((incoming_reservation > 0) & (incoming_reservation <= initial_credit));
    assert((newcomer_period > 0) & (newcomer_period <= SAFE));
    assert((rate_window > 0) & (rate_window <= SAFE));
    assert((refill_period > 0) & (refill_period <= SAFE));
    assert((abandon_after > 0) & (abandon_after <= SAFE));
    assert(abandon_after >= rate_window);
    assert((newcomer_admissions > 0) & (newcomer_admissions <= maximum_admissions));
    assert((refill_units > 0) & (refill_units <= initial_credit));
    let window_end = (now / rate_window + 1) * rate_window;
    assert(valid_until == if window_end < policy_valid_until { window_end } else { policy_valid_until });
    let policy = policy_bytes(community, initial_credit, maximum_available,
        outgoing_reservation, incoming_reservation, policy_revision,
        policy_valid_from, policy_valid_until, newcomer_period, rate_window,
        newcomer_admissions, maximum_admissions, refill_period, refill_units, abandon_after);
    assert(digest(policy) == policy_digest);
    let state_policy = state_policy_hash(policy);
    assert((owner_secret != [0; 32]) & (new_blind != [0; 32]));
    let registered_secret = secret_hash(community, owner_secret);
    assert(registered_secret == field(owner_enrollment.secret_hash));
    verify_enrollment(community, owner, owner_enrollment, field(enrollment_root), now, valid_until);
    assert(field(next_state) != 0);
    if genesis {
        assert((previous_version == 0) & (next_version == 0));
        assert((previous_state == [0; 32]) & (settlement_marker == [0; 32]));
        let empty = indexed::initial_root();
        let initial = Opening { available: initial_credit, reserved: 0,
            outgoing_root: empty, outgoing_count: 1, incoming_root: empty, incoming_count: 1,
            pair_root: empty, pair_count: 1, frontier: valid_until, created_at: valid_until,
            admission_epoch: now / rate_window, admissions: 0, blind: new_blind };
        assert(state_hash(community, owner, state_policy, registered_secret, 0, initial) == field(next_state));
    } else {
        assert(next_version == previous_version + 1);
        assert(new_blind != old.blind);
        assert(state_hash(community, owner, state_policy, registered_secret, previous_version, old) == field(previous_state));
        assert((old.created_at > 0) & (old.created_at <= old.frontier) & (old.frontier <= valid_until));
        let mature = if now >= old.created_at { now - old.created_at >= newcomer_period } else { false };
        let capacity = if mature { maximum_available } else { initial_credit };
        let admission_limit = if mature { maximum_admissions } else { newcomer_admissions };
        let epoch = now / rate_window;
        assert((old.admission_epoch <= epoch) & (old.admissions <= maximum_admissions));
        assert(old.available as u128 + old.reserved <= capacity as u128);
        assert((old.outgoing_count >= 1) & (old.outgoing_count <= 4294967296));
        assert((old.incoming_count >= 1) & (old.incoming_count <= 4294967296));
        assert((old.pair_count >= 1) & (old.pair_count <= 4294967296));
        assert((action >= 1) & (action <= 6)); // reserve, activate, settle, cancel, expire, refill
        let amount = if slot.role == 0 { outgoing_reservation } else { incoming_reservation };
        if action != 6 {
            assert((slot.role < 2) & (slot.peer != owner));
            assert((slot.nonce != [0; 32]) & (slot.group != [0; 32]) & (slot.contact_policy != [0; 32]));
            assert((slot.admitted_at > 0) & (slot.admitted_at <= now));
            assert((slot.expires_at > slot.admitted_at) & (slot.expires_at < policy_valid_until));
            assert(slot.amount == amount);
        }
        let event = marker(community, owner, owner_secret, slot.peer, slot.nonce);
        let pair = pair_key(community, owner, owner_secret, slot.peer);
        if action != 6 { assert((event != 0) & (pair != 0)); }
        let own_root = if slot.role == 0 { old.outgoing_root } else { old.incoming_root };
        let own_count = if slot.role == 0 { old.outgoing_count } else { old.incoming_count };
        let other_root = if slot.role == 0 { old.incoming_root } else { old.outgoing_root };
        let other_count = if slot.role == 0 { old.incoming_count } else { old.outgoing_count };
        let mut changed_root = own_root;
        let mut changed_count = own_count;
        let mut pair_root = old.pair_root;
        let mut pair_count = old.pair_count;
        let mut available = old.available;
        let mut reserved = old.reserved;
        let mut frontier = old.frontier;
        let mut admission_epoch = old.admission_epoch;
        let mut admissions = old.admissions;
        let mut issued: u32 = 0;
        if action == 1 {
            // Both owners commit the original initiator's common opened-at.
            assert((slot.phase == 1) & (now < slot.expires_at));
            assert(valid_until <= slot.expires_at);
            if slot.role == 0 {
                assert(slot.admitted_at == now);
                assert(slot.expires_at == now + abandon_after);
            }
            // Incoming adopts the exact sender lease verified by the native
            // peer gate. Its proof alone does not establish cross-owner consent.
            let count = if old.admission_epoch == epoch { old.admissions as u64 + 1 } else { 1 };
            assert(count <= admission_limit as u64);
            admission_epoch = epoch; admissions = count as u32;
            verify_enrollment(community, slot.peer, peer_enrollment, field(enrollment_root), now, valid_until);
            assert(slot.peer_authority == enrollment_leaf(community, slot.peer, peer_enrollment));
            assert(slot.owner_authority == enrollment_leaf(community, owner, owner_enrollment));
            // Same event cannot be inserted under another role or a new path.
            indexed::absent(other_root, other_count, event,
                opposite_map.leaf, opposite_map.index, opposite_map.path);
            changed_root = indexed::insert(own_root, own_count, event, obligation_hash(event, slot, 1),
                own_map.leaf, own_map.index, own_map.path, own_map.append_path);
            changed_count = own_count + 1;
            if pair_exists {
                indexed::present(pair_root, pair_count, pair, 1,
                    pair_map.leaf, pair_map.index, pair_map.path);
            } else {
                pair_root = indexed::insert(pair_root, pair_count, pair, 1,
                    pair_map.leaf, pair_map.index, pair_map.path, pair_map.append_path);
                pair_count = pair_count + 1;
            }
            available = old.available - amount;
            reserved = old.reserved + amount as u128;
            assert(settlement_marker == [0; 32]);
        } else if action == 6 {
            assert(now >= old.frontier);
            assert(now - old.frontier >= refill_period);
            let headroom = capacity as u128 - (old.available as u128 + old.reserved);
            issued = if headroom < refill_units as u128 { headroom as u32 } else { refill_units };
            available = old.available + issued;
            // No backdated proof chain may collect multiple grants inside one
            // accepted window. Even a zero grant consumes the common horizon.
            frontier = valid_until;
            assert(settlement_marker == [0; 32]);
        } else {
            let next_phase = if action == 2 { 2 } else if action == 4 { 4 } else if action == 5 { 5 } else { 3 };
            assert(slot.phase == if (action == 2) | (action == 4) { 1 } else { 2 });
            changed_root = indexed::update(own_root, own_count, event,
                obligation_hash(event, slot, slot.phase), obligation_hash(event, slot, next_phase),
                own_map.leaf, own_map.index, own_map.path);
            if action == 2 {
                assert(now < slot.expires_at);
                assert(valid_until <= slot.expires_at);
                assert(settlement_marker == [0; 32]);
            } else if action == 4 {
                // Before protected release only; the admission counter and
                // permanent event tombstone prevent refund/reset churn.
                available = old.available + amount;
                reserved = old.reserved - amount as u128;
                assert(event == field(settlement_marker));
            } else if action == 5 {
                assert((slot.role == 0) & (now >= slot.expires_at));
                // The fixed wait refunds the bond regardless of whether a
                // Close receipt was delivered. Admission throughput stays spent.
                available = old.available + amount;
                reserved = old.reserved - amount as u128;
                assert(event == field(settlement_marker));
            } else {
                if resolution.kind == 1 {
                    assert(now < slot.expires_at);
                    assert(valid_until <= slot.expires_at);
                }
                if slot.role == 0 {
                    // Recipient Close does not change the outgoing refund date.
                    // Only a confirmed Answer may settle this role early.
                    assert(resolution.kind == 1);
                    verify_peer_authority(community, slot, peer_enrollment, field(enrollment_root), now, valid_until);
                }
                // Incoming owner closure has no current-eligibility dependency
                // on the silent counterpart. Historical authority is in slot.
                if slot.role == 1 {
                    let authority = enrollment_leaf(community, owner, receipt_owner_enrollment);
                    assert((authority == slot.owner_authority) | (authority == enrollment_leaf(community, owner, owner_enrollment)));
                }
                let signer = if slot.role == 0 { peer_enrollment } else { receipt_owner_enrollment };
                verify_resolution(community, owner, slot, signer, resolution, now);
                if (slot.role == 1) & (resolution.kind == 1) {
                    verify_peer_authority(community, slot, peer_enrollment, field(enrollment_root), now, valid_until);
                    verify_acknowledgment(community, owner, slot, receipt_owner_enrollment,
                        peer_enrollment, resolution, acknowledgment, now);
                }
                // Incoming Close and confirmed Answer restore the exact bond.
                // There is no additional reward or sender-selected burn.
                available = old.available + amount;
                reserved = old.reserved - amount as u128;
                assert(event == field(settlement_marker));
            }
        }
        assert(available as u128 + reserved <= capacity as u128);
        assert(available as u128 + reserved == old.available as u128 + old.reserved + issued as u128);
        let successor = Opening { available, reserved,
            outgoing_root: if slot.role == 0 { changed_root } else { old.outgoing_root },
            outgoing_count: if slot.role == 0 { changed_count } else { old.outgoing_count },
            incoming_root: if slot.role == 1 { changed_root } else { old.incoming_root },
            incoming_count: if slot.role == 1 { changed_count } else { old.incoming_count },
            pair_root, pair_count, frontier, created_at: old.created_at,
            admission_epoch, admissions, blind: new_blind };
        assert(state_hash(community, owner, state_policy, registered_secret, next_version, successor) == field(next_state));
    }
}
