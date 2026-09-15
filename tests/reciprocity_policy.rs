//! Executable economic model, not a proof verifier or a production ledger.
//!
//! Device-to-root bindings and received receipt/ACK evidence are assumed to have
//! been authenticated elsewhere. These tests exercise policy/state transitions;
//! they do not establish cryptographic acceptance, delivery, or atomic exchange
//! between two accounts. The real policy validation/time helpers are exercised.
//! Event tombstones are modeled; pair/block history across fresh nonces is not.
//! cmsg's real contact gate separately enforces that encounter-authorization rule.
//! Waiting-period changes here model trusted configuration, not durable policy CAS.

use cfrm::accounting::AccountPolicy;
use std::collections::BTreeMap;

fn policy() -> AccountPolicy {
    AccountPolicy {
        initial_credit: 3,
        maximum_available: 6,
        outgoing_reservation: 1,
        incoming_reservation: 2,
        policy_revision: 1,
        policy_valid_from: 1,
        policy_valid_until: 10_000_000,
        newcomer_period: 100,
        rate_window: 10,
        newcomer_admissions: 3,
        maximum_admissions: 6,
        refill_period: 5,
        refill_units: 1,
        abandon_after: 20,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Outgoing,
    Incoming,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Prepared,
    Active,
    Canceled,
    Answered,
    Closed,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Evidence {
    None,
    RecipientReceipt,
    SenderAcknowledgment,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Slot {
    role: Role,
    phase: Phase,
    opened_at: u64,
    expires_at: u64,
    turn_epoch: u64,
    amount: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Account {
    created_at: u64,
    frontier: u64,
    epoch: u64,
    admissions: u32,
    available: u32,
    locked: u128,
    refilled: u128,
    version: u64,
    clock: u64,
    // Event IDs abstract an already-bound (community, owner, peer, nonce).
    // Both directions use the same namespace; terminal entries are retained.
    slots: BTreeMap<u16, Slot>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Model {
    policy: AccountPolicy,
    accounts: BTreeMap<u8, Account>,
    devices: BTreeMap<u8, u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reject {
    Policy,
    Clock,
    Root,
    Device,
    Conflict,
    Rate,
    Capacity,
    Replay,
    Phase,
    Expired,
    Evidence,
    RefillWait,
}

#[derive(Clone, Copy, Debug)]
enum Action {
    Reserve(u16, Role, u64),
    Activate(u16),
    CancelPrepared(u16),
    Answer(u16, Evidence),
    Close(u16),
    Expire(u16),
    Refill,
    QueueAnswer(u16),
    Recover,
    Disconnect,
}

impl Model {
    fn new(policy: AccountPolicy) -> Self {
        policy.validate().unwrap();
        Self {
            policy,
            accounts: BTreeMap::new(),
            devices: BTreeMap::new(),
        }
    }

    fn create(&mut self, root: u8, device: u8, now: u64) -> Result<(), Reject> {
        self.create_at(root, device, now, now)
    }

    fn create_at(
        &mut self,
        root: u8,
        device: u8,
        proved_at: u64,
        committed_at: u64,
    ) -> Result<(), Reject> {
        if self.accounts.contains_key(&root) {
            return Err(Reject::Root);
        }
        if self.devices.contains_key(&device) {
            return Err(Reject::Device);
        }
        if committed_at < proved_at {
            return Err(Reject::Clock);
        }
        let anchor = self
            .policy
            .proof_valid_until(proved_at)
            .map_err(|_| Reject::Policy)?;
        if committed_at >= anchor {
            return Err(Reject::Expired);
        }
        self.policy
            .capacity_at(anchor, proved_at)
            .map_err(|_| Reject::Policy)?;
        self.accounts.insert(
            root,
            Account {
                created_at: anchor,
                frontier: anchor,
                epoch: proved_at / self.policy.rate_window,
                admissions: 0,
                available: self.policy.initial_credit,
                locked: 0,
                refilled: 0,
                version: 0,
                clock: committed_at,
                slots: BTreeMap::new(),
            },
        );
        self.devices.insert(device, root);
        Ok(())
    }

    fn attach_device(&mut self, root: u8, device: u8) {
        assert!(self.accounts.contains_key(&root));
        assert!(!self.devices.contains_key(&device));
        self.devices.insert(device, root);
    }

    fn update_waiting_period(&mut self, seconds: u64) -> Result<(), Reject> {
        let mut policy = self.policy.clone();
        policy.abandon_after = seconds;
        policy.validate().map_err(|_| Reject::Policy)?;
        self.policy = policy;
        Ok(())
    }

    fn run(&mut self, device: u8, action: Action, now: u64) -> Result<(), Reject> {
        let root = *self.devices.get(&device).ok_or(Reject::Device)?;
        let version = self.accounts[&root].version;
        self.commit(device, version, action, now, now)
    }

    fn commit(
        &mut self,
        device: u8,
        version: u64,
        action: Action,
        proved_at: u64,
        committed_at: u64,
    ) -> Result<(), Reject> {
        let root = *self.devices.get(&device).ok_or(Reject::Device)?;
        let original = &self.accounts[&root];
        if original.version != version {
            return Err(Reject::Conflict);
        }
        if committed_at < original.clock || committed_at < proved_at {
            return Err(Reject::Clock);
        }
        // Control/recovery never needs spendable units or an admission turn.
        if matches!(action, Action::Recover | Action::Disconnect) {
            return Ok(());
        }
        let until = self
            .policy
            .proof_valid_until(proved_at)
            .map_err(|_| Reject::Policy)?;
        if committed_at >= until {
            return Err(Reject::Expired);
        }
        let capacity = self
            .policy
            .capacity_at(original.created_at, proved_at)
            .map_err(|_| Reject::Policy)?;
        let mut account = original.clone();
        match action {
            Action::Reserve(id, role, opened_at) => {
                let expires_at = opened_at
                    .checked_add(self.policy.abandon_after)
                    .filter(|end| *end <= 9_007_199_254_740_991)
                    .ok_or(Reject::Policy)?;
                if expires_at >= self.policy.policy_valid_until {
                    return Err(Reject::Expired);
                }
                Self::live_horizon(opened_at, expires_at, proved_at, until)?;
                if account.slots.contains_key(&id) {
                    return Err(Reject::Replay);
                }
                let epoch = proved_at / self.policy.rate_window;
                if epoch < account.epoch {
                    return Err(Reject::Clock);
                }
                if epoch != account.epoch {
                    account.epoch = epoch;
                    account.admissions = 0;
                }
                let limit = self
                    .policy
                    .admission_limit_at(account.created_at, proved_at)
                    .map_err(|_| Reject::Policy)?;
                if account.admissions >= limit {
                    return Err(Reject::Rate);
                }
                let amount = match role {
                    Role::Outgoing => self.policy.outgoing_reservation,
                    Role::Incoming => self.policy.incoming_reservation,
                };
                if account.available < amount {
                    return Err(Reject::Capacity);
                }
                account.available -= amount;
                account.locked += u128::from(amount);
                account.admissions += 1;
                account.slots.insert(
                    id,
                    Slot {
                        role,
                        phase: Phase::Prepared,
                        opened_at,
                        expires_at,
                        turn_epoch: epoch,
                        amount,
                    },
                );
            }
            Action::Refill => {
                if proved_at < account.frontier
                    || proved_at - account.frontier < self.policy.refill_period
                {
                    return Err(Reject::RefillWait);
                }
                let headroom =
                    u128::from(capacity) - u128::from(account.available) - account.locked;
                let grant = u128::from(self.policy.refill_units).min(headroom) as u32;
                account.available += grant;
                account.refilled += u128::from(grant);
                // Upper-bound actual acceptance time; backdated proofs cannot
                // compress several grants into one still-valid common window.
                account.frontier = until; // Includes clipped zero grants.
            }
            Action::Activate(id)
            | Action::CancelPrepared(id)
            | Action::Answer(id, _)
            | Action::Close(id)
            | Action::Expire(id)
            | Action::QueueAnswer(id) => {
                let slot = account.slots.get(&id).ok_or(Reject::Phase)?.clone();
                let (phase, refund) = match action {
                    Action::Activate(_) => {
                        if slot.phase != Phase::Prepared {
                            return Err(Reject::Phase);
                        }
                        Self::live_horizon(slot.opened_at, slot.expires_at, proved_at, until)?;
                        (Phase::Active, false)
                    }
                    Action::CancelPrepared(_) => {
                        if slot.phase != Phase::Prepared {
                            return Err(Reject::Phase);
                        }
                        // Safe only because peer release requires accepted Active evidence.
                        (Phase::Canceled, true)
                    }
                    Action::Answer(_, evidence) => {
                        if slot.phase != Phase::Active {
                            return Err(Reject::Phase);
                        }
                        Self::live_horizon(slot.opened_at, slot.expires_at, proved_at, until)?;
                        let expected = match slot.role {
                            Role::Outgoing => Evidence::RecipientReceipt,
                            Role::Incoming => Evidence::SenderAcknowledgment,
                        };
                        if evidence != expected {
                            return Err(Reject::Evidence);
                        }
                        (Phase::Answered, true)
                    }
                    Action::Close(_) => {
                        if slot.phase != Phase::Active || slot.role != Role::Incoming {
                            return Err(Reject::Phase);
                        }
                        // Disclosing or suppressing Close never changes the
                        // sender's original wait or its eventual refund.
                        (Phase::Closed, true)
                    }
                    Action::Expire(_) => {
                        if slot.phase != Phase::Active || slot.role != Role::Outgoing {
                            return Err(Reject::Phase);
                        }
                        if proved_at < slot.expires_at {
                            return Err(Reject::Expired);
                        }
                        (Phase::Expired, true)
                    }
                    Action::QueueAnswer(_) => {
                        if slot.phase != Phase::Active || slot.role != Role::Incoming {
                            return Err(Reject::Phase);
                        }
                        return Ok(()); // A local draft conveys no economic evidence.
                    }
                    _ => unreachable!(),
                };
                account.slots.get_mut(&id).unwrap().phase = phase;
                if refund {
                    account.locked -= u128::from(slot.amount);
                    account.available += slot.amount;
                }
            }
            Action::Recover | Action::Disconnect => unreachable!(),
        }
        account.version += 1;
        account.clock = committed_at;
        self.accounts.insert(root, account);
        Ok(())
    }

    fn live_horizon(opened_at: u64, expires_at: u64, now: u64, until: u64) -> Result<(), Reject> {
        if opened_at == 0 || opened_at > now || now >= expires_at || until > expires_at {
            return Err(Reject::Expired);
        }
        Ok(())
    }

    fn invariants(&self, now: u64) {
        for account in self.accounts.values() {
            let capacity = self.policy.capacity_at(account.created_at, now).unwrap();
            assert!(u128::from(account.available) + account.locked <= u128::from(capacity));
            assert_eq!(
                u128::from(account.available) + account.locked,
                u128::from(self.policy.initial_credit) + account.refilled
            );
            assert_eq!(
                account.locked,
                account
                    .slots
                    .values()
                    .filter(|slot| matches!(slot.phase, Phase::Prepared | Phase::Active))
                    .map(|slot| u128::from(slot.amount))
                    .sum::<u128>()
            );
            assert!(account
                .slots
                .values()
                .all(|slot| slot.opened_at < slot.expires_at
                    && slot.expires_at < self.policy.policy_valid_until));
            assert_eq!(
                account.admissions as usize,
                account
                    .slots
                    .values()
                    .filter(|slot| slot.turn_epoch == account.epoch)
                    .count()
            );
            assert!(
                account.admissions
                    <= self
                        .policy
                        .admission_limit_at(account.created_at, now)
                        .unwrap()
            );
            assert!(account.epoch <= now / self.policy.rate_window);
            assert!(account.created_at <= account.frontier);
            assert!(account.frontier <= self.policy.proof_valid_until(now).unwrap());
        }
    }
}

fn single(policy: AccountPolicy) -> Model {
    let mut model = Model::new(policy);
    model.create(7, 70, 100).unwrap();
    model
}

fn active(model: &mut Model, device: u8, id: u16, role: Role, now: u64) {
    model
        .run(device, Action::Reserve(id, role, now), now)
        .unwrap();
    model.run(device, Action::Activate(id), now).unwrap();
}

#[test]
fn actual_policy_rejects_unusable_newcomer_and_refill_parameters() {
    let good = policy();
    good.validate().unwrap();
    let invalid = [
        AccountPolicy {
            initial_credit: 0,
            ..good.clone()
        },
        AccountPolicy {
            initial_credit: 1,
            ..good.clone()
        },
        AccountPolicy {
            newcomer_period: 0,
            ..good.clone()
        },
        AccountPolicy {
            rate_window: 0,
            ..good.clone()
        },
        AccountPolicy {
            newcomer_admissions: 0,
            ..good.clone()
        },
        AccountPolicy {
            maximum_admissions: 2,
            ..good.clone()
        },
        AccountPolicy {
            refill_period: 0,
            ..good.clone()
        },
        AccountPolicy {
            refill_units: 0,
            ..good.clone()
        },
        AccountPolicy {
            refill_units: 4,
            ..good.clone()
        },
        AccountPolicy {
            abandon_after: 0,
            ..good.clone()
        },
        AccountPolicy {
            abandon_after: 9,
            ..good.clone()
        },
    ];
    for value in invalid {
        assert!(value.validate().is_err(), "{value:?}");
    }
    assert_eq!(good.capacity_at(110, 100).unwrap(), 3);
    assert_eq!(good.admission_limit_at(110, 109).unwrap(), 3);
    assert!(good.capacity_at(111, 100).is_err());
    assert!(good.admission_limit_at(111, 100).is_err());
    assert_eq!(good.proof_valid_until(109).unwrap(), 110);
    let clipped = AccountPolicy {
        policy_valid_until: 115,
        ..good
    };
    assert_eq!(clipped.proof_valid_until(110).unwrap(), 115);
}

#[test]
fn both_directions_share_capacity_and_full_incoming_cannot_refill_around_it() {
    let mut model = single(policy());
    active(&mut model, 70, 1, Role::Outgoing, 100);
    active(&mut model, 70, 2, Role::Incoming, 100);
    assert_eq!(
        (model.accounts[&7].available, model.accounts[&7].locked),
        (0, 3)
    );
    assert_eq!(
        model.run(70, Action::Reserve(3, Role::Outgoing, 100), 100),
        Err(Reject::Capacity)
    );
    model.run(70, Action::Refill, 115).unwrap();
    assert_eq!(model.accounts[&7].available, 0);
    model.invariants(115);

    let p = AccountPolicy {
        incoming_reservation: 1,
        maximum_available: 3,
        ..policy()
    };
    let mut inbox = single(p);
    for id in 1..=3 {
        active(&mut inbox, 70, id, Role::Incoming, 100);
    }
    let before = inbox.clone();
    inbox.run(70, Action::Disconnect, 101).unwrap();
    inbox.run(70, Action::Recover, 101).unwrap();
    assert_eq!(inbox, before);
    inbox.run(70, Action::Refill, 1000).unwrap();
    assert_eq!(inbox.accounts[&7].locked, 3);
    assert_eq!(inbox.accounts[&7].available, 0);
    assert_eq!(inbox.run(70, Action::Expire(1), 1000), Err(Reject::Phase));
    assert_eq!(
        inbox.run(70, Action::Reserve(4, Role::Outgoing, 1000), 1000),
        Err(Reject::Capacity)
    );
    inbox.run(70, Action::Close(1), 1000).unwrap();
    assert_eq!(inbox.accounts[&7].available, 1);
    inbox.invariants(1000);
}

#[test]
fn prepared_cancel_returns_units_but_preserves_turns_and_cross_role_tombstones() {
    let mut model = single(policy());
    for id in 1..=3 {
        model
            .run(70, Action::Reserve(id, Role::Outgoing, 100), 100)
            .unwrap();
        model.run(70, Action::CancelPrepared(id), 100).unwrap();
    }
    assert_eq!(model.accounts[&7].available, 3);
    assert_eq!(model.accounts[&7].admissions, 3);
    assert_eq!(
        model.run(70, Action::Reserve(4, Role::Incoming, 100), 100),
        Err(Reject::Rate)
    );
    assert_eq!(
        model.run(70, Action::Reserve(1, Role::Incoming, 110), 110),
        Err(Reject::Replay)
    );
    assert_eq!(model.run(70, Action::Activate(1), 110), Err(Reject::Phase));
    model.invariants(110);
}

#[test]
fn fixed_epoch_boundary_allows_exactly_two_limits_not_an_unbounded_reset() {
    let mut model = single(policy());
    for (now, first) in [(109, 1), (110, 4)] {
        for id in first..first + 3 {
            model
                .run(70, Action::Reserve(id, Role::Outgoing, now), now)
                .unwrap();
            model.run(70, Action::CancelPrepared(id), now).unwrap();
        }
    }
    assert_eq!(model.accounts[&7].slots.len(), 6);
    assert_eq!(
        model.run(70, Action::Reserve(7, Role::Outgoing, 110), 110),
        Err(Reject::Rate)
    );
    assert_eq!(
        model.run(70, Action::Reserve(7, Role::Outgoing, 109), 109),
        Err(Reject::Clock)
    );
    model.invariants(110);
}

#[test]
fn expiry_refunds_and_months_offline_yields_only_one_refill_grant() {
    let mut model = single(policy());
    for id in 1..=3 {
        active(&mut model, 70, id, Role::Outgoing, 100);
    }
    for id in 1..=3 {
        model.run(70, Action::Expire(id), 120).unwrap();
    }
    assert_eq!(
        (model.accounts[&7].available, model.accounts[&7].locked),
        (3, 0)
    );
    let later = 100 + 30 * 24 * 60 * 60;
    model.run(70, Action::Refill, later).unwrap();
    assert_eq!(model.accounts[&7].available, 4);
    assert_eq!(
        model.run(70, Action::Refill, later + 4),
        Err(Reject::RefillWait)
    );
    assert_eq!(
        model.run(70, Action::Refill, later + 14),
        Err(Reject::RefillWait)
    );
    model.run(70, Action::Refill, later + 15).unwrap();
    assert_eq!(model.accounts[&7].available, 5);
    model.invariants(later + 15);

    let mut newcomer = single(policy());
    assert_eq!(newcomer.policy.capacity_at(110, 209).unwrap(), 3);
    assert_eq!(newcomer.policy.capacity_at(110, 210).unwrap(), 6);
    assert_eq!(newcomer.policy.admission_limit_at(110, 209).unwrap(), 3);
    assert_eq!(newcomer.policy.admission_limit_at(110, 210).unwrap(), 6);
    assert_eq!(newcomer.accounts[&7].available, 3);
    newcomer.run(70, Action::Refill, 210).unwrap();
    assert_eq!(newcomer.accounts[&7].available, 4);
    newcomer.invariants(210);
}

#[test]
fn delayed_genesis_cannot_start_age_or_cooldown_before_actual_registration() {
    let p = AccountPolicy {
        newcomer_period: 2,
        refill_period: 2,
        ..policy()
    };
    let mut model = Model::new(p);
    model.create_at(7, 70, 100, 109).unwrap();
    let account = &model.accounts[&7];
    assert_eq!((account.created_at, account.frontier), (110, 110));
    assert_eq!(
        model.policy.capacity_at(account.created_at, 109).unwrap(),
        3
    );
    assert_eq!(
        model
            .policy
            .admission_limit_at(account.created_at, 109)
            .unwrap(),
        3
    );
    assert_eq!(
        model.policy.capacity_at(account.created_at, 111).unwrap(),
        3
    );
    assert_eq!(
        model.policy.capacity_at(account.created_at, 112).unwrap(),
        6
    );
    assert_eq!(model.run(70, Action::Refill, 109), Err(Reject::RefillWait));
    // Future conservative anchors must not freeze ordinary newcomer activity.
    active(&mut model, 70, 1, Role::Outgoing, 109);
    model.invariants(109);
    assert_eq!(model.run(70, Action::Refill, 111), Err(Reject::RefillWait));
    let mut expired = Model::new(policy());
    assert_eq!(expired.create_at(7, 70, 100, 110), Err(Reject::Expired));
    assert!(expired.accounts.is_empty());
}

#[test]
fn backdated_refill_proofs_cannot_catch_up_inside_one_acceptance_window() {
    let mut model = single(AccountPolicy {
        newcomer_period: 90,
        refill_period: 2,
        ..policy()
    });
    for id in 1..=3 {
        active(&mut model, 70, id, Role::Outgoing, 100);
    }
    for id in 1..=3 {
        model.run(70, Action::Expire(id), 120).unwrap();
    }
    let version = model.accounts[&7].version;
    model.commit(70, version, Action::Refill, 203, 209).unwrap();
    assert_eq!(
        (model.accounts[&7].available, model.accounts[&7].frontier),
        (4, 210)
    );
    // Each signed time is in the still-valid 200..210 window. Storing the
    // first proof's 203 as frontier would permit extra grants at 205/207/209.
    for proved_at in [205, 207, 209] {
        let before = model.clone();
        let version = model.accounts[&7].version;
        assert_eq!(
            model.commit(70, version, Action::Refill, proved_at, 209),
            Err(Reject::RefillWait)
        );
        assert_eq!(model, before);
    }
    assert_eq!(model.run(70, Action::Refill, 211), Err(Reject::RefillWait));
    model.run(70, Action::Refill, 212).unwrap();
    assert_eq!(model.accounts[&7].available, 5);
    assert_eq!(model.accounts[&7].frontier, 220);
    model.invariants(212);
}

#[test]
fn zero_grant_consumes_horizon_but_does_not_block_other_transitions() {
    let mut model = single(policy());
    model.run(70, Action::Refill, 115).unwrap();
    assert_eq!(model.accounts[&7].refilled, 0);
    assert_eq!(model.accounts[&7].frontier, 120);
    model
        .run(70, Action::Reserve(1, Role::Outgoing, 115), 115)
        .unwrap();
    model.run(70, Action::CancelPrepared(1), 115).unwrap();
    assert_eq!(model.run(70, Action::Refill, 119), Err(Reject::RefillWait));
    assert_eq!(model.run(70, Action::Refill, 124), Err(Reject::RefillWait));
    model.run(70, Action::Refill, 125).unwrap();
    assert_eq!(model.accounts[&7].frontier, 130);
    assert_eq!(model.accounts[&7].refilled, 0);
    model.invariants(125);
}

#[test]
fn answer_requires_directional_received_evidence_and_close_escapes_withheld_ack() {
    let mut model = single(policy());
    model.create(8, 80, 100).unwrap();
    active(&mut model, 70, 1, Role::Outgoing, 100);
    active(&mut model, 80, 1, Role::Incoming, 100);
    let recipient_before = model.accounts[&8].clone();
    model.run(80, Action::QueueAnswer(1), 105).unwrap();
    assert_eq!(model.accounts[&8], recipient_before);
    assert_eq!(
        model.run(80, Action::Answer(1, Evidence::None), 105),
        Err(Reject::Evidence)
    );
    assert_eq!(
        model.run(80, Action::Answer(1, Evidence::RecipientReceipt), 105),
        Err(Reject::Evidence)
    );
    model
        .run(70, Action::Answer(1, Evidence::RecipientReceipt), 105)
        .unwrap();
    // Sender has its refund while its ACK remains unavailable to the recipient.
    assert_eq!(model.accounts[&8].locked, 2);
    model.run(80, Action::Close(1), 106).unwrap();
    assert_eq!(model.accounts[&8].available, 3);
    assert_eq!(model.run(70, Action::Close(1), 106), Err(Reject::Phase));
    assert_eq!(
        model.run(80, Action::Answer(1, Evidence::SenderAcknowledgment), 106),
        Err(Reject::Phase)
    );
    model.invariants(106);

    assert_eq!(model.run(70, Action::Expire(1), 120), Err(Reject::Phase));
}

#[test]
fn outgoing_wait_is_fixed_across_disconnect_and_expiry_refunds_exactly_once() {
    let mut model = single(policy());
    active(&mut model, 70, 1, Role::Outgoing, 100);
    model.attach_device(7, 71);
    let reserved = model.clone();
    for now in [100, 105, 119] {
        model.run(71, Action::Disconnect, now).unwrap();
        model.run(71, Action::Recover, now).unwrap();
        assert_eq!(model.run(71, Action::Expire(1), now), Err(Reject::Expired));
        assert_eq!(
            model.run(71, Action::CancelPrepared(1), now),
            Err(Reject::Phase)
        );
        assert_eq!(model, reserved);
    }
    let version = model.accounts[&7].version;
    // The prover cannot claim the deadline has passed before the host clock.
    assert_eq!(
        model.commit(71, version, Action::Expire(1), 120, 119),
        Err(Reject::Clock)
    );
    assert_eq!(model, reserved);
    model.run(71, Action::Expire(1), 120).unwrap();
    assert_eq!(
        (model.accounts[&7].available, model.accounts[&7].locked),
        (3, 0)
    );
    assert_eq!(model.accounts[&7].slots[&1].opened_at, 100);
    assert_eq!(model.accounts[&7].slots[&1].expires_at, 120);
    assert_eq!(model.accounts[&7].slots[&1].phase, Phase::Expired);
    assert_eq!(model.accounts[&7].admissions, 1);
    let refunded = model.clone();
    assert_eq!(
        model.commit(70, version, Action::Expire(1), 120, 120),
        Err(Reject::Conflict)
    );
    assert_eq!(model.run(70, Action::Expire(1), 120), Err(Reject::Phase));
    assert_eq!(model.run(70, Action::Expire(1), 1000), Err(Reject::Phase));
    assert_eq!(
        model.run(70, Action::Answer(1, Evidence::RecipientReceipt), 120),
        Err(Reject::Phase)
    );
    assert_eq!(
        model.run(70, Action::Reserve(1, Role::Incoming, 120), 120),
        Err(Reject::Replay)
    );
    assert_eq!(model, refunded);
    model.invariants(120);
}

#[test]
fn disclosed_and_suppressed_close_give_identical_sender_wait_and_refund() {
    let mut disclosed = single(policy());
    disclosed.create(8, 80, 100).unwrap();
    active(&mut disclosed, 70, 1, Role::Outgoing, 100);
    active(&mut disclosed, 80, 1, Role::Incoming, 100);
    let mut suppressed = disclosed.clone();
    for model in [&mut disclosed, &mut suppressed] {
        model.run(80, Action::Close(1), 105).unwrap();
        assert_eq!(
            (model.accounts[&8].available, model.accounts[&8].locked),
            (3, 0)
        );
    }
    // Only one sender sees the Close. Neither can use it as accounting settlement.
    assert_eq!(disclosed.run(70, Action::Close(1), 105), Err(Reject::Phase));
    assert_eq!(disclosed.accounts[&7], suppressed.accounts[&7]);
    for now in [105, 119] {
        for model in [&mut disclosed, &mut suppressed] {
            assert_eq!(model.run(70, Action::Expire(1), now), Err(Reject::Expired));
            assert_eq!(
                model.run(70, Action::Reserve(1, Role::Outgoing, now), now),
                Err(Reject::Replay)
            );
            assert_eq!(
                (model.accounts[&7].available, model.accounts[&7].locked),
                (2, 1)
            );
        }
        assert_eq!(disclosed.accounts[&7], suppressed.accounts[&7]);
    }
    for model in [&mut disclosed, &mut suppressed] {
        model.run(70, Action::Expire(1), 120).unwrap();
        assert_eq!(
            (model.accounts[&7].available, model.accounts[&7].locked),
            (3, 0)
        );
        assert_eq!(model.accounts[&7].admissions, 1);
        assert_eq!(model.run(70, Action::Expire(1), 120), Err(Reject::Phase));
        model.invariants(120);
    }
    assert_eq!(disclosed, suppressed);
}

#[test]
fn expiry_refunds_preserve_consumed_turns_and_cannot_reuse_old_events() {
    let mut model = single(policy());
    for id in 1..=3 {
        active(&mut model, 70, id, Role::Outgoing, 100);
    }
    assert_eq!(model.accounts[&7].available, 0);
    for old_id in 1..=3 {
        model.run(70, Action::Expire(old_id), 120).unwrap();
        assert_eq!(
            model.run(70, Action::Reserve(old_id, Role::Incoming, 120), 120),
            Err(Reject::Replay)
        );
        let fresh_id = old_id + 3;
        active(&mut model, 70, fresh_id, Role::Outgoing, 120);
        model
            .run(
                70,
                Action::Answer(fresh_id, Evidence::RecipientReceipt),
                120,
            )
            .unwrap();
        assert_eq!(model.accounts[&7].admissions, u32::from(old_id));
    }
    assert_eq!(model.accounts[&7].available, 3);
    assert_eq!(
        model.run(70, Action::Reserve(7, Role::Outgoing, 120), 120),
        Err(Reject::Rate)
    );
    assert_eq!(
        model.run(70, Action::Reserve(7, Role::Incoming, 120), 120),
        Err(Reject::Rate)
    );
    assert_eq!(model.accounts[&7].slots.len(), 6);
    model.invariants(120);
}

#[test]
fn waiting_period_tuning_changes_only_subsequent_reservation_deadlines() {
    let mut model = single(policy());
    active(&mut model, 70, 1, Role::Outgoing, 100); // Original wait: 20.
    model.update_waiting_period(10).unwrap();
    active(&mut model, 70, 2, Role::Outgoing, 105); // Shorter wait: 10.
    model.update_waiting_period(40).unwrap();
    active(&mut model, 70, 3, Role::Outgoing, 106); // Longer wait: 40.
    let deadlines: Vec<_> = model.accounts[&7]
        .slots
        .values()
        .map(|slot| slot.expires_at)
        .collect();
    assert_eq!(deadlines, vec![120, 115, 146]);
    let before = model.clone();
    assert_eq!(model.update_waiting_period(9), Err(Reject::Policy));
    assert_eq!(model, before);
    assert_eq!(model.run(70, Action::Expire(2), 114), Err(Reject::Expired));
    model.run(70, Action::Expire(2), 115).unwrap();
    assert_eq!(model.run(70, Action::Expire(1), 119), Err(Reject::Expired));
    model.run(70, Action::Expire(1), 120).unwrap();
    // Shortening again cannot pull an already admitted longer wait forward.
    model.update_waiting_period(10).unwrap();
    assert_eq!(model.run(70, Action::Expire(3), 120), Err(Reject::Expired));
    assert_eq!(model.run(70, Action::Expire(3), 145), Err(Reject::Expired));
    model.run(70, Action::Expire(3), 146).unwrap();
    assert_eq!(
        (model.accounts[&7].available, model.accounts[&7].locked),
        (3, 0)
    );
    assert_eq!(model.accounts[&7].admissions, 3);
    assert_eq!(
        model.accounts[&7]
            .slots
            .values()
            .map(|slot| slot.expires_at)
            .collect::<Vec<_>>(),
        deadlines
    );
    model.invariants(146);
}

#[test]
fn tuning_preserves_existing_activation_and_answer_windows() {
    let mut shortened = single(policy());
    shortened
        .run(70, Action::Reserve(1, Role::Outgoing, 100), 100)
        .unwrap();
    shortened.update_waiting_period(10).unwrap();
    shortened.run(70, Action::Activate(1), 119).unwrap();
    shortened
        .run(70, Action::Answer(1, Evidence::RecipientReceipt), 119)
        .unwrap();
    assert_eq!(shortened.accounts[&7].available, 3);

    let mut extended = single(policy());
    active(&mut extended, 70, 1, Role::Outgoing, 100);
    extended.update_waiting_period(40).unwrap();
    let before = extended.clone();
    assert_eq!(
        extended.run(70, Action::Answer(1, Evidence::RecipientReceipt), 120),
        Err(Reject::Expired)
    );
    assert_eq!(extended, before);
    extended.run(70, Action::Expire(1), 120).unwrap();
    extended.invariants(120);

    let mut prepared = single(policy());
    prepared
        .run(70, Action::Reserve(1, Role::Outgoing, 100), 100)
        .unwrap();
    prepared.update_waiting_period(40).unwrap();
    assert_eq!(
        prepared.run(70, Action::Activate(1), 120),
        Err(Reject::Expired)
    );
    prepared.run(70, Action::CancelPrepared(1), 120).unwrap();
    prepared.invariants(120);
}

#[test]
fn reservations_leave_a_refund_interval_before_policy_expiry_or_change_nothing() {
    for policy_end in [119, 120] {
        let mut model = single(AccountPolicy {
            policy_valid_until: policy_end,
            ..policy()
        });
        let before = model.clone();
        assert_eq!(
            model.policy.reservation_deadline(100),
            Err(cfrm::Error::Expired)
        );
        assert_eq!(
            model.run(70, Action::Reserve(1, Role::Outgoing, 100), 100),
            Err(Reject::Expired)
        );
        assert_eq!(model, before);
    }

    let mut just_before = single(AccountPolicy {
        policy_valid_until: 121,
        ..policy()
    });
    assert_eq!(just_before.policy.reservation_deadline(100).unwrap(), 120);
    active(&mut just_before, 70, 1, Role::Outgoing, 100);
    assert_eq!(just_before.accounts[&7].slots[&1].expires_at, 120);
    just_before.run(70, Action::Expire(1), 120).unwrap();
    assert_eq!(
        (
            just_before.accounts[&7].available,
            just_before.accounts[&7].locked
        ),
        (3, 0)
    );
    just_before.invariants(120);

    let mut later = single(AccountPolicy {
        policy_valid_until: 141,
        abandon_after: 40,
        ..policy()
    });
    active(&mut later, 70, 1, Role::Outgoing, 100);
    let before = later.clone();
    assert_eq!(
        later.run(70, Action::Reserve(2, Role::Outgoing, 101), 101),
        Err(Reject::Expired)
    );
    assert_eq!(later, before); // No debit, admission turn, new slot or deadline change.
    later.invariants(101);
}

#[test]
fn common_proof_horizon_rejects_late_commits_and_last_partial_lease_window() {
    let mut model = single(policy());
    active(&mut model, 70, 1, Role::Outgoing, 100);
    let before = model.clone();
    let version = model.accounts[&7].version;
    assert_eq!(
        model.commit(
            70,
            version,
            Action::Answer(1, Evidence::RecipientReceipt),
            119,
            120
        ),
        Err(Reject::Expired)
    );
    assert_eq!(model, before);
    model
        .run(70, Action::Answer(1, Evidence::RecipientReceipt), 119)
        .unwrap();

    let mut partial = single(policy());
    active(&mut partial, 70, 1, Role::Outgoing, 105); // Lease ends at 125.
    assert_eq!(
        partial.run(70, Action::Answer(1, Evidence::RecipientReceipt), 120),
        Err(Reject::Expired)
    );
    assert_eq!(
        partial.run(70, Action::Expire(1), 124),
        Err(Reject::Expired)
    );
    partial.run(70, Action::Expire(1), 125).unwrap();
    assert_eq!(
        partial.run(70, Action::Answer(1, Evidence::RecipientReceipt), 125),
        Err(Reject::Phase)
    );
    partial.invariants(125);
    let mut stale_open = single(policy());
    assert_eq!(
        stale_open.run(70, Action::Reserve(1, Role::Incoming, 100), 120),
        Err(Reject::Expired)
    );
    assert_eq!(
        stale_open.run(70, Action::Reserve(1, Role::Incoming, 111), 110),
        Err(Reject::Expired)
    );
    assert_eq!(
        stale_open.run(70, Action::Reserve(1, Role::Incoming, 105), 120),
        Err(Reject::Expired)
    );
    stale_open
        .run(70, Action::Reserve(1, Role::Incoming, 105), 105)
        .unwrap();
    assert_eq!(
        stale_open.run(70, Action::Activate(1), 120),
        Err(Reject::Expired)
    );
    stale_open.run(70, Action::CancelPrepared(1), 125).unwrap();
    stale_open.invariants(125);
}

#[test]
fn new_devices_restore_the_same_root_frontier_and_cannot_create_new_genesis() {
    let mut model = single(policy());
    let stale_version = model.accounts[&7].version;
    model.attach_device(7, 71);
    active(&mut model, 70, 1, Role::Outgoing, 100);
    active(&mut model, 71, 2, Role::Incoming, 100);
    assert_eq!(model.accounts[&7].available, 0);
    let before = model.clone();
    assert_eq!(model.create(7, 72, 200), Err(Reject::Root));
    assert_eq!(
        model.commit(71, stale_version, Action::Refill, 105, 105),
        Err(Reject::Conflict)
    );
    assert_eq!(model, before);
    let restored = model.clone(); // Model of authenticated snapshot restoration.
    assert_eq!(restored.accounts[&7].created_at, 110);
    assert_eq!(restored.accounts[&7].admissions, 2);
    model.run(71, Action::Recover, 105).unwrap();
    model.run(71, Action::Disconnect, 105).unwrap();
    assert_eq!(model, restored);
    model.invariants(105);
}

#[test]
fn colluding_answer_refund_loops_consume_both_roots_epoch_turns() {
    let mut model = single(policy());
    model.create(8, 80, 100).unwrap();
    for id in 1..=3 {
        let (initiator, recipient) = if id % 2 == 0 { (80, 70) } else { (70, 80) };
        active(&mut model, initiator, id, Role::Outgoing, 100);
        active(&mut model, recipient, id, Role::Incoming, 100);
        model
            .run(
                initiator,
                Action::Answer(id, Evidence::RecipientReceipt),
                100,
            )
            .unwrap();
        model
            .run(
                recipient,
                Action::Answer(id, Evidence::SenderAcknowledgment),
                100,
            )
            .unwrap();
    }
    for device in [70, 80] {
        assert_eq!(
            model.run(device, Action::Reserve(4, Role::Outgoing, 100), 100),
            Err(Reject::Rate)
        );
    }
    for account in model.accounts.values() {
        assert_eq!(account.available, 3);
        assert_eq!(account.admissions, 3);
        assert_eq!(account.refilled, 0);
    }
    model.invariants(100);
}

#[test]
fn bounded_adversarial_sequences_conserve_units_and_failed_actions_are_atomic() {
    fn explore(model: Model, depth: u8) {
        let now = 100 + u64::from(4 - depth) * 10;
        let actions = [
            Action::Reserve(1, Role::Outgoing, now),
            Action::Reserve(2, Role::Incoming, now),
            Action::Activate(1),
            Action::CancelPrepared(2),
            Action::Answer(1, Evidence::RecipientReceipt),
            Action::Close(2),
            Action::Expire(1),
            Action::Refill,
        ];
        for action in actions {
            let mut next = model.clone();
            if next.run(70, action, now).is_err() {
                assert_eq!(next, model);
            }
            next.invariants(now);
            if depth > 1 {
                explore(next, depth - 1);
            }
        }
    }
    // 8 + 64 + 512 + 4096 transitions; no unbounded search or external work.
    explore(single(policy()), 4);
}
