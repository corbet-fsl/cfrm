# Operational tunables

Packages expose validated settings with units, bounds and a clear application
boundary. The embedding chooses their values and records a configuration
revision alongside aggregate metrics. Loading new settings must not rewrite
existing promises, reset allowances or discard anti-replay history.

## Waiting period: live tuning

`AccountPolicy.abandon_after` is the waiting period in UTC seconds for a **new
outgoing reservation**. It is deliberately a tunable. No product default has
been chosen. Its valid range is at least `rate_window`, within the exact integer
range `1..=2^53-1`, and short enough to leave a nonempty refund interval before the
immutable policy expiry. The same bound is checked for each new reservation.

The trusted host can change it while the ledger is running:

```rust,ignore
let current = ledger.waiting_period()?;
let updated = ledger.update_waiting_period(
    current.revision,
    proposed_seconds,
    trusted_clock,
)?;
```

`WaitingPeriodTuning` returns `revision`, `seconds`, the full `policy_digest`
and stable `state_policy_digest`. The update validates the value and atomically
commits it with a monotonic revision and clock floor. Concurrent operators must
use the expected revision. A stale ledger handle cannot accept a new account
update; configuration is checked both before and after expensive verification.
`reload_policy()` refreshes another handle; `account_policy()` exposes its
snapshot. Reopening a database loads the persisted waiting period over the
bootstrap value, while all immutable configuration remains pinned.

This API is for an authorized operator, never a member-controlled endpoint.
The package provides neither an admin HTTP service nor an automatic optimizer.

Every slot commits its original `expiresAt`. Outgoing Reserve derives that
deadline from its opening time and the current wait. An incoming reservation
adopts the authenticated outgoing deadline through the cmsg proof gate. Later
tuning changes neither side's deadline, including tuning between their two
reservations. Close and silence both release the sender at that original
deadline; confirmed Answer may release it early. Expiry is a client-proved
transition and does not require the recipient to return.

The full public policy digest binds the current waiting period. The stable
state-policy digest excludes only that field, so existing private openings
remain usable after tuning. It still binds all credit, rate, age, refill,
revision and policy-validity fields. Peer proofs preserve the original
certified policy and deadline while the verifier checks this stable binding.
Exact accepted retries and authenticated recovery survive tuning.

## Configuration inventory

| Setting / API | Application boundary | Tuning signals |
| --- | --- | --- |
| `AccountPolicy.abandon_after` through the live API above | Future outgoing reservations; committed deadlines remain fixed | Client-local reply-delay and pending-age distributions; aggregate proof/commit latency |
| `BoardLimits.max_members`, `max_devices_per_member`, `max_lease_seconds`, `max_replay_entries` | Explicit configuration of a board instance; do not replace a live board by discarding signed rows or replay state | Aggregate board size, presence renewal latency, capacity rejections |
| `AccountLedgerPolicy.max_authorization_seconds`, `max_proof_bytes`, `checkpoint_period_seconds` | Pinned database configuration; no hot-change API | Proof sizes, authorization expiry failures and checkpoint publication latency |
| Remaining `AccountPolicy` credit, rate, age, refill, revision and validity fields | Pinned cryptographic policy; changing them is not a waiting-period reload | Locally measured capacity pressure and coarse population statistics, subject to the privacy constraints below |
| Older `AllocationPolicy` credit, period and request limits | Separate blind-permit ledger configuration, not the private reciprocal account | Aggregate issuance/resource measurements; issuance is not delivered messaging |

Only settings with a stated live or prospective API are operational knobs.
Circuit/VK hashes, signature rules, field encodings, privacy checks and replay
requirements are security invariants. Tuning does not weaken them. Runtime
changes to other economic rules need their own proved state-continuity design;
opening a new database or issuing a second genesis is not a policy update.
The cmsg package has its own [tuning inventory](https://github.com/cmtymeet/cmsg/blob/main/docs/tuning.md).

## Metrics and change discipline

Choose a waiting period using measured user response delays together with
browser proving, ledger acceptance and connection delays. A shorter wait
releases unsuccessful senders sooner and permits more unanswered attempts;
a longer wait reduces that throughput but increases the cost of incompatible
schedules. The shared admission counter remains a separate upper bound. No
single duration can distinguish malice from absence.

The operator cannot directly observe private balances, contact outcomes or
which accounts are waiting on each other. Do not add counterpart IDs, shared
event tags, per-member outcome counters or joined presence histories to make
tuning easier. Proof verification latency, aggregate resource use and coarse
public error counts are available at the host boundary. Reply delay and inbox
pressure belong at endpoints; exporting them needs a separately defined
aggregation, minimum-population and retention policy. Small samples and timing
can reveal relationships even without explicit identifiers.

Record the setting revision, observation interval and aggregate result. Apply
bounded operator-approved changes, compare subsequent cohorts, and allow an
authorized change back using a **new** revision. Never rewind accounting or
move an existing deadline to undo a configuration decision. No production
metrics collector or automatic feedback controller is implied by this library.
