# Durable private account ledger

The experimental [Rust ledger](../src/accounting_ledger.rs) accepts one opaque
state per permanent member and atomically records each verified successor.
It stores no peer, conversation tuple, private receipt, balance or map opening.
The updating owner, update timing, state versions and owner-specific markers
remain visible. This does not hide timing correlations or operator equivocation.

## Trust and scope

The host configures a complete `AccountProofVerifier`, common independently
verified enrollment checkpoints, an eligibility authority, an operator signing
key, trusted time and durable SQLite storage. There is no successful default
verifier. A verifier that merely checks a signature or returns success defeats
the accounting relation; the storage API cannot turn it into a proof verifier.

Policy values are mandatory. The v2 [reciprocity policy](reciprocity-policy.md)
covers genesis, both reservation roles, activation, Answer/Close settlement,
Prepared cancellation, outgoing expiry and bounded refill. It combines shared
capacity with a permanent-root admission counter and newcomer probation.
Extra Answer rewards and numerical disapproval are outside this policy.
Separate peer presentations and cmsg's protected release gate compose with this
ledger through a trusted verifier. `AllocationLedger::resolve_private` remains
closed; the older blind-permit allocation ledger is a separate mechanism.

One common checkpoint root can be admitted per configured time slot. Publishing
a root is a trusted local operation and requires independently verifying its
root/device/accounting delegations. Member-supplied roots are not authoritative.
The immutable database configuration is pinned on first open. Its trusted
[tuning API](tuning.md) changes only the prospective waiting period with durable
revision/CAS checks. Full named policy digests change; stable state-policy
bindings and committed slot deadlines do not. Other economic rules and proof
scopes remain pinned; a configuration edit cannot bypass state continuity.

## Updates and recovery

Each request signs a domain-separated transcript binding the owner statement,
proof digest, circuit/VK digests, independent random request ID, authorizing
device and validity interval. Statements use canonical BN254 field encodings
and bounded integers. Unknown serialized fields are rejected. Neither named
endpoint's request contains a shared conversation identifier.

Protocol-v2 statements bind all fourteen policy fields and the common
`validUntil` proof horizon. A new request must commit before that horizon;
its signed expiry cannot exceed it. That commit deadline does not expire an
already accepted Active reservation. Its private lease and the original
reservation-device authority bound protected first-payload release separately.

A short SQLite transaction checks whether the request is already accepted or
eligible for verification. Proof verification runs with all database locks
released. A final immediate transaction rechecks current authorization, time,
current configuration, checkpoint, cached response, lifetime genesis or exact previous state, and
settlement markers before committing the successor and signed acceptance.
Another owner can commit while a slow proof is being checked. WAL with
`synchronous=FULL` protects commits under SQLite's filesystem durability assumptions.

Exact signed retries recover the cached acceptance without another proof or
debit, including after the original request expires when the caller supplies
current root/device authority, including after a waiting-period update. A newly authorized device can request the latest
acceptance or an earlier request's result. The signed status response binds a
fresh challenge and observation time; an old acceptance alone does not prove
that it is current. A status lookup returns no private opening and permits no
second genesis. The client must preserve openings and exact pending requests.

An operator acceptance certifies an accepted opaque state. A peer still needs
the separate proof of a matching active reservation and current cmsg consent
before releasing an introduction. Lost private recovery material, rollback of
all replicas and a malicious operator's inconsistent histories remain limits.

## Executed evidence

Crow9/60 at `96c1884a08e0b7aaba0dea38c238517ae0261f9c` passed 19
storage/authorization tests, including six new live-tuning tests. They exercise
concurrent tuning, rejected stale handles/proofs, tuning during verification,
rollback after partial writes, restart recovery, immutable fields and exact
old-policy retries. The same run passed 19 reciprocity-model tests, including
4,680 bounded transitions, the existing 21 native and 55 historical JavaScript
tests, and the portable Wasm check. Storage tests use the explicit synthetic
proof verifier.

Crow9/61 at the same revision passed real browser account/peer proofs through
the Rust ledger and cmsg gate. Answer/Close passed 22/24 separate Rust ledger
checks across 31/35 child processes, plus 10/12 chronological live applies.
Both scenarios change the waiting period from 500 to 900 synthetic seconds,
recover exact accepted old-policy retries, and reject unused old-policy writes.
Original reservations still expire at 600. See the
[current integration evidence](../experiments/private-accounting/account-state/README.md#revision3-integration-evidence)
for proof counts, artifact hashes and limits.

### Earlier relation

At `524956395852696c1d3f6ac4bd57ef5f8652c261`, Crow run 9/48 passed thirteen
storage/authorization tests, the existing 21 native and 55 historical JavaScript
tests, and the portable Wasm check. The new suite exercises strict signatures,
device continuity, expired exact retry, checkpoint and proof rejection, time
changes during verification, challenge-bound recovery, and rollback after marker
insertion. Two separate child processes race independent requests against the
same database; one successor commits and its exact response survives reopening.
Channel-driven tests hold one verifier while another owner opens the database,
publishes a checkpoint and commits. Competing state updates, shared clock
advancement and expiry are rechecked when the paused verifier finishes.

Those tests deliberately use a synthetic verifier to isolate the storage
contract. They are not cryptographic acceptance evidence. The separate
[account-state integration](../experiments/private-accounting/account-state/README.md)
invokes the real pinned backend through
[account_ledger_fixture](../examples/account_ledger_fixture.rs). Answer passed
with the recorded browser proofs and corrected ledger on Crow 9/49; Close passed
with fresh browser proofs on Crow 9/50. Their source pins, check counts and
substantial browser resource costs are recorded separately.
