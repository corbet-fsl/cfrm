# Live introductions and reciprocal capacity

This policy limits first introductions. Established conversation traffic has no
per-message operator accounting. Members may modify their clients, disconnect,
withhold acknowledgments, coordinate with other members and use several devices.
All devices share one permanent community account and one accepted state chain.

## State machine

Transport availability and account state are separate. Losing a connection
cancels that session's pending application delivery. It neither proves that a
message was never received nor authorizes an account refund.

| Account state | Permitted transition | Capacity effect |
|---|---|---|
| Absent event | Reserve as outgoing or incoming | Move the configured amount from available to reserved; consume one admission turn |
| Prepared | Activate within the agreed live lease | No balance change |
| Prepared | Cancel | Return reserved units; retain event tombstone and consumed turn |
| Active | Confirmed Answer within its proof validity window | Return the owner's reservation, with role-specific signed evidence |
| Active incoming | Explicit recipient Close | Return the recipient's reservation |
| Active outgoing | Recipient Close | Remain reserved until the original deadline; Close is not an outgoing settlement |
| Active outgoing | Original lease expires | Return the reservation exactly once, without requiring the recipient |
| Active incoming | Silence, expiry or disconnect | Remain reserved until Answer or explicit Close |
| Terminal event | Retry or another outcome | Exact accepted requests are idempotent; new settlement or reuse is rejected |

An outgoing Active proof is required before an honest recipient authorizes its
incoming reservation. Both matching Active proofs are required before either
side releases first-contact plaintext. Prepared evidence never authorizes
payload release. Thus cancelling Prepared cannot erase an already authorized
delivery. Local flags such as “never sent” are not cancellation evidence.

Both slots bind the same community, members, introduction nonce, group, contact
policy and opening time. The sender's opening time plus the current `abandonAfter` defines its original
`expiresAt`, committed inside the slot. An incoming reservation copies the
authenticated outgoing deadline. The deadline is immutable after reservation,
even if the operating waiting period changes between those two reservations. Peer-only presentations expose
this context to the counterpart; named operator updates must not contain it.

A pending introduction belongs to the devices that reserved it. Its peer proof
binds the reservation-time device authority; a sibling device cannot substitute
its own welcome or first payload. Other devices may synchronize accepted history
and participate after the conversation is established. Moving an unresolved
introduction to another device requires closure and fresh admission. Concurrent
instances of one device must use a durable storage version check; copying or
rolling back all trusted device storage is outside that guarantee.

## A predictable waiting period

The sender's recovery must not require meeting the recipient online again.
Close and silence have identical sender-side refund timing. Otherwise a modified
sender could hide a Close receipt and claim a cheaper timeout. Recipient Close
immediately clears the incoming obligation and preserves its signed contact
restriction; the sender's account slot can stay Active while cmsg marks that
contact closed. Only confirmed Answer releases outgoing capacity early.

A refund never authorizes another attempt against an unresolved introduction
or an existing block. New nonces, replacement groups and sibling devices do not
clear that history. Established conversation traffic remains outside this rule.

The waiting period is an explicit operational tunable, not a fixed product
constant. The [tuning contract](tuning.md) documents its validated live update,
metrics and effect on future reservations. New reservations require a deadline
strictly before policy expiry, leaving a usable interval for their refund proof.
The recipient may still need to Close locally after the sender disappears;
receiving without resolving messages continues to occupy the shared budget.

## One budget and one rate counter

Let `A` be available units, `R` all reserved units across both directions, and
`C` the account's current capacity. Every reachable state satisfies:

```
0 <= A; 0 <= R; A + R <= C
```

New accounts start with `initialCredit` available units and that same total
capacity. After `newcomerPeriod` from their permanent genesis time, capacity
becomes `maximumAvailable`. The permanent genesis age anchor is the end of the
genesis proof's validity window, so backdating that proof cannot shorten the
newcomer period. That field bounds available **plus reserved** units
in protocol v2. Graduation raises the ceiling and does not issue units. Device
enrollment, renewal, profile edits and reconnects cannot restart account age.

Every reservation consumes one turn from the root account's fixed time window,
regardless of direction. The limit is `newcomerAdmissions` or
`maximumAdmissions`. Answer, Close and cancellation never return that turn.
This is a rate counter, not a separate spendable or transferable budget. A fixed
window permits a boundary burst across two adjacent windows; it is not a claim
of a rolling-window limit. Unauthenticated handshake traffic additionally needs
transport resource limits.

After at least `refillPeriod` beyond the previous refill's proof horizon, a
refill issues:

```
grant = min(refillUnits, C - A - R)
```

The refill frontier advances to `validUntil`, even for a zero grant; genesis
initializes it to that same horizon. This prevents multiple backdated proofs
from collecting missed grants during a single current window.
Only one grant is available after an absence; missed periods do not accumulate.
Full unresolved capacity leaves no refill headroom. Close and recovery do not
need new admission turns. All amounts and durations are mandatory configuration;
synthetic fixture values are not product defaults.

## Time and atomicity

Each proof has a public `validUntil` at the end of the common rate window,
clipped to policy expiry. All members proving in that window use the same
horizon, avoiding a per-contact public expiry tag. The signed request cannot
outlive it. The ledger rechecks expiry after proof verification and atomically
accepts one successor with its exact response and event marker.
Current accounting enrollment must remain valid through that horizon. Historical
receipt authority is checked at its signature time against the exact authority
committed in the reservation; it cannot replace current owner authorization.

Reservation, activation and Answer require the entire proof validity window to
fit inside the private lease. Configuration rejects `abandonAfter < rateWindow`.
A final partial window may nevertheless be unusable;
clients must leave enough time for proving and acceptance. Outgoing expiry
returns its reservation at or after the original deadline,
without a peer receipt. Expiry requires the client to prove the transition,
possibly on its next login; the operator cannot edit a hidden balance directly.
Unclaimed late Answer evidence cannot claim a second refund after expiry.
An already accepted Answer cannot be reversed or settled again by a later Close.

Atomic owner updates do not establish simultaneous settlement of both accounts
or simultaneous network delivery. A peer can withhold the last acknowledgment.
Incoming Answer requires the sender's authenticated acknowledgment; locally
signing or queuing an Answer earns no refund. The recipient can explicitly Close
to clear the obligation. This is a defined escape from withholding, not proof of
perfect fair exchange. Protocols that guarantee stronger recovery commonly add
a trusted recovery party ([Asokan et al., 1997](https://research.ibm.com/publications/optimistic-protocols-for-fair-exchange)).

A fresh peer challenge proves possession of an accepted Active opening, not
that the accepted state has never been superseded. The honest endpoint therefore
also enforces its own current obligation, exact encounter context, expiry and
durable first-payload/closure history. An old certificate cannot authorize a new
encounter. The own-state query is a snapshot; it is not a cross-account lock held
through network delivery.

## Incentive bounds and limits

The capacity invariant follows by induction over accepted transitions: Reserve
moves units from `A` to `R`; a refund reverses that transfer; only bounded refill
adds units. Increasing the capacity ceiling adds no units. Available plus
reserved units equals initial credit plus accepted refill grants. The ledger's single-successor check
prevents two devices from spending the same predecessor.

For a root with window limit `K`, at most `K` new reservations can be accepted
in that window, including canceled attempts and both directions. Refunds cannot
increase this bound. Across a coalition of `N` admitted roots, the corresponding
bound is at most `N × K`; eligibility therefore remains essential. Unanswered outgoing attempts occupy their configured capacity until their
original deadline. Confirmed Answer can release that capacity early. Repeated
unanswered attempts are bounded by this waiting time and the admission counter. These are resource bounds against
strategic clients, not assumptions about their motives.

- Disconnecting yields no accounting benefit. A successful “send then disappear”
  occupies capacity until Answer or the original deadline and consumes a turn.
- Ignoring admitted messages fills the same budget used to initiate contacts.
  Refill cannot empty the inbox. Explicit Close clears the incoming obligation
  while the sender waits until its original refund deadline.
- Refund loops cannot create units. Colluding members can exchange valid
  receipts, but their admission counts still bound the number of new encounters.
  No bonus is awarded for apparent sincerity, message length or distinct peers.
- A sender must commit its own scarce capacity before an honest recipient
  accepts an obligation. This bounds inbox exhaustion per sender; it does not
  make denial of service impossible for a large coalition.
- Persistent roots prevent a device reset from restoring allowances. Obtaining
  many distinct admitted roots is an eligibility problem; per-account accounting
  cannot solve Sybil attacks by itself.
- Returning refunds and replenishing capacity provide mechanical incentives,
  not a proof that all humans prefer cooperative behavior. An adversary who
  values harming others may willingly pay the bounded cost.

Correctness assumes sound signatures/proofs and a consistent account ledger
with trusted monotonic time. Privacy excludes explicit peer identifiers and
shared event tags from named updates; timing correlation and operator
equivocation require separate defenses. Model tests establish properties of
the stated model; actual circuit, ledger and browser tests establish their own
implementation boundaries.

## Validation

Crow9/60 tested the fixed-wait refund, stored deadlines and live tuning at cfrm
`96c1884a08e0b7aaba0dea38c238517ae0261f9c`. It passed 19 independent Rust
model tests, including 4,680 bounded transitions, 19 storage/authorization tests,
21 existing native tests, 55 historical JavaScript tests and Wasm checking.
Model exploration and storage tests are separate from cryptographic acceptance.

At pinned cmsg `ef1483c0a709e86975c44f6f8c84e833e7aa6ac4`, Crow10/78
passed 163 native tests and Wasm checking; Crow10/79 passed 21 actual Chromium
contract groups with no unexpected tab requests. These include preserved
original deadlines and refusal to reopen an unresolved or closed contact after
capacity release. Tab request interception is not process-wide network capture.

Crow9/61 at the same cfrm revision passed the real account/peer browser proof
integration. Answer/Close passed 231/243 browser checks, 10/12 account proofs
and two peer proofs each: 26 real proofs in total. Independent Node checks were
23/25; real Rust ledger checks were 22/24 across 31/35 child processes, plus
10/12 chronological live applies and 21/25 current-own checks. Both scenarios
change the waiting period from 500 to 900 while retaining original expiry 600.
Close settles the recipient immediately; the sender later proves its single
deadline refund without the recipient. All times are synthetic. Browser and
Node use the same cryptographic backend; this is not implementation diversity.
See the [current integration evidence](../experiments/private-accounting/account-state/README.md#revision3-integration-evidence)
for checked artifact hashes and [proof costs](account-proof-cost.md).

### Earlier relation

The independent Rust model passed 13 tests, including 4,680 bounded transitions,
on Crow9/54. This is bounded exploration plus the invariant argument above,
not exhaustive verification of every implementation state.

Crow9/58 tested cfrm `eddc92835b2e2b08bc431852c8ff3332203198eb` with cmsg
`80bbcf30e777b56a9ce6f8ea4a261f440c349eb0`: Answer/Close passed 224/229
browser checks, 10/12 real account proofs and two real peer proofs each.
Independent Node verification passed 23/25 checks; the real Rust ledger passed
19/21 checks, including competing successors, retry and recovery. The browser
and Node verifier use the same cryptographic backend. Private openings stayed
inside the page. Synthetic policy clocks do not measure live-lease feasibility.

At that cmsg revision, Crow10/76 passed 161 native tests plus Wasm checking;
Crow10/77 passed 21 actual Chromium contract groups including shipped IndexedDB
version checks across concurrent instances. Scripted transport cases and the
earlier private-Tor runtime evidence are labeled separately. See the
[account-state evidence](../experiments/private-accounting/account-state/README.md)
and [proof costs](account-proof-cost.md) for artifacts and remaining limits.
