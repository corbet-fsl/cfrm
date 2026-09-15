# Private reservation protocol

**2026-09-15 — partially implemented experimental protocol; not audited or enabled for production.**

This extends the requirements in [Private reciprocal accounting](private-accounting.md)
and the [account-state foundation](../experiments/private-accounting/account-state/README.md).
The foundation implements proved empty genesis, both reservation maps, activation,
settlement, cancellation, expiry, refill and a [durable Rust ledger](account-ledger.md).
Peer presentations bind accepted reservations to cmsg's protected live-release
gate. Exact tested revisions and remaining validation limits are recorded in the
account-state evidence. The older `resolve_private` entry point remains
`UnsupportedCapability`.

The proposal keeps one named account per permanent community member while hiding
its contacts. Both outgoing and incoming obligations affect that same account.
An Active outgoing obligation stays reserved until confirmed Answer or its
original deadline. At that deadline the sender can prove a single refund
without the recipient returning. The consumed admission turn remains spent.

## Scope and policy boundary

`P` is a complete, common, versioned policy, authenticated independently of a
particular contact. It must select all required amounts, capacity bounds, time
rules and permitted numerical changes before a transition can execute.
Unspecified parameters cause rejection. The [reciprocity policy](reciprocity-policy.md)
defines the v2 lifecycle, capacity/rate bounds, conservative proof windows and
refill formula. Numerical values remain explicit configuration. No extra
Answer/repeated-pair reward or inhibition formula is enabled.

The relation includes genesis, preparation, activation, authorized settlement,
Prepared cancellation, outgoing expiry and refill. The account circuit is
implemented; its complete live release composition is being validated.
Established communication and ordinary device catchup
continue without a conversation-specific operator request.

## One durable owner state

For each `(community, permanent_owner_id)`, the operator retains one lifetime
registration and one current accepted state commitment/version. Device renewal,
eligibility expiry, recovery and deletion must not allow another genesis. The
member root authorizes the accounting authority; the eligibility issuer cannot
replace that authority under an existing member ID.

The hiding state commitment must cover at least:

- Community, owner, policy/version, accounting-secret commitment and any
  authorized key-continuity metadata.
- Available capacity and the frontiers needed to apply `P` exactly once.
- An outgoing obligation map and an incoming obligation map, both charged
  against the same capacity. These are separate authenticated roots inside the
  owner state, not two independent balances or one overwriteable slot.
- Lifetime event/pair history and the authenticated block/consent history needed
  by the accounting policy, including archived unresolved obligations.
- Fresh commitment randomness.

Each private obligation binds its role, permanent peer, original introduction
nonce, authenticated group binding, contact-policy digest and bounds, reserved
amount, phase, historical peer authorization and settlement history. Map keys
and event markers must use reviewed, domain-separated constructions bound to the
registered owner secret. Roles, devices or renewed signatures cannot change the
identity of the original event. Accounting-key rotation must preserve this
continuity rather than create a fresh marker namespace.

Transitions prove the actual previous opening, all changed paths, conservation,
integer bounds and preservation of untouched paths. The account-state foundation
implements those constraints with depth32 indexed maps. Its measured browser
cost is a release constraint; this document selects no product contact limit.

## Operator envelopes

The following field sets define the proposed separation of information. They
describe the information boundary. The implemented named-owner formats have
versioned canonical encodings in [`src/accounting.rs`](../src/accounting.rs).
Peer presentation and protected-release formats remain experimental.

| Envelope | Fields visible to the operator |
| --- | --- |
| `AccountGenesis` | Protocol version, community, owner ID, root-authorized accounting registration, current eligibility input, common policy and circuit/verifying-key digests, common eligibility checkpoint and accepted time interval, independently random request ID, initial state commitment, genesis proof, owner authorization |
| `AccountTransition` | Protocol version, community, owner ID, common policy and circuit/verifying-key digests, common eligibility checkpoint and accepted time interval, independently random request ID, previous version/commitment, proposed next commitment, owner-specific event markers required by the relation, explicitly permitted numerical outputs, transition proof, owner authorization |
| `AccountStatus` | Protocol version, community, owner ID, authenticated request for that owner's current state/version or an exact prior request ID |
| `AccountAcceptance` | Protocol version, community, owner ID, request ID, binding to the exact accepted owner request, previous and resulting versions/commitments, policy/circuit/checkpoint scope, acceptance status, operator signature |

The owner authorization binds the complete request. A retry reuses the exact
request and its persisted successor opening; it does not regenerate a different
proof or request ID after an ambiguous response. The server rejects reuse of a
request ID with different contents and returns the cached acceptance for an
already accepted exact request. A proof that was accepted before credential
expiry remains accepted: a later authenticated status lookup must not turn it
into a new debit or a new genesis.

The operator atomically compares the previous version/commitment, consumes the
required markers, stores the successor and caches its acceptance response.
Competing devices get at most one accepted successor. Root recovery can
authenticate a status lookup, but knowing the latest opaque commitment does not
recover its private opening.

### No public join between the two owners

Neither endpoint's named request may contain the other endpoint's commitment,
acceptance certificate, request ID, proof hash or event marker. The introduction
nonce, group binding, counterpart ID and any common pair hash also stay out of
both operator envelopes. Merely hashing one of these shared values does not
remove the correlation.

Use independent owner request IDs and owner-specific markers. Common policy,
eligibility checkpoints and accepted time intervals must serve a population;
an operator-selected per-contact checkpoint would become a tag. Reservation
roles remain private, including when selecting circuits or proof envelopes.
Different public verifying keys or encodings for sender and recipient would
disclose a role that the witness otherwise hides.

These rules remove explicit pair joins. Named update timing, volume, unusual
amounts, a malicious operator and sparse traffic can still correlate members.
Tor, common configurations and scheduling need separate evaluation; this is
not a claim that named-account traffic becomes unobservable.

## Peer-only reservation evidence

An `AccountAcceptance` authenticates an accepted opaque state. It does not by
itself prove that a particular hidden reservation exists. Introduce a separate
`PeerReservationProof`, exchanged only through authenticated cmsg.

Its statement, visible to the two peers but never submitted with either named
operator update, binds:

- Both permanent member IDs, community and the presenting owner's authority.
- Original introduction nonce, actual authenticated group binding, role,
  contact policy/bounds and the reservation phase.
- The presenting owner's accepted commitment/version and operator acceptance,
  under the pinned operator authority and common policy/checkpoint.
- A fresh challenge from the verifying peer, to bind the presentation to the
  current private exchange.

The proof establishes that the accepted commitment contains exactly that slot
without exposing the balance or unrelated obligations. Its construction,
operator-signature verification and browser cost are additional work, not
properties of the existing settlement proof. The proof and certificate may be
visible to the peer; forwarding them into the other named request is forbidden.

A fresh presentation challenge does not make an old accepted state current.
Safety also requires monotonic slot transitions: an Active reservation cannot
disappear through cancellation, restoration or a different map path. Authorized
resolution and current local cmsg closure/nonce state must prevent old evidence
from authorizing another introduction. Operator equivocation requires an
independently consistent checkpoint/log assumption or additional witnessing.

## Preparation, activation and protected release

1. **Prepare the outgoing slot.** The sender authorizes and durably submits its
   owner transition. Prepared capacity is unavailable for another reservation.
   It privately presents accepted Prepared evidence with the exact contact
   tuple. This evidence cannot authorize protected payload release.
2. **Explicit recipient authorization.** The recipient verifies the sender's
   accepted Active reservation, the offer,
   admission requirements and both owners' block/consent rules. Only an explicit
   recipient-authorized transition creates its incoming Prepared slot. An
   unsolicited preflight, guessed member ID or received proof cannot debit it.
3. **Activate.** The sender activates before requesting the incoming reservation;
   the recipient then activates its own authorized slot. Both privately present
   accepted Active evidence with the same opening time and lease. No cross-account
   operator transaction is claimed.
4. **Release.** Both honest endpoints verify the matching Active evidence for
   both roles and persist the contact gate before releasing the introduction.
   The receiving endpoint also checks its current local slot, selected group,
   nonce, bound, block history and one-introduction limit before plaintext
   exposure. Prepared evidence and an opaque operator certificate alone fail.
5. **Resolve.** The recipient answers through the authenticated response
   protocol or closes the exact introduction. Settlement consumes the matching
   obligation while retaining the event and pair history.

This separates atomic owner updates from the combined release condition.
Neither owner can atomically force the other owner to update its independent
ledger. Shared identifiers in both named requests are not an acceptable shortcut
to cross-account coordination.

## Durable ordering and recovery

Before submitting any owner transition, persist the old/new openings, exact
request, request ID and private peer context together. After acceptance, persist
the returned certificate before exposing its peer proof or protected payload.
The cmsg checkpoint and outgoing frames need a durable outbox transaction.
Storage failure must not publish a half-updated journal or consume a different
contact nonce on retry.

| Interruption | Required recovery behavior |
| --- | --- |
| Operator response lost | Query or retry the exact persisted request. Do not guess failure, generate another debit, or overwrite its successor opening. |
| Competing device wins | Recover the accepted version and opening through authorized device/recovery synchronization, then construct a new transition from that state. Never rebase by dropping obligations. |
| One or both slots remain Prepared | No introduction is released. Cancel only by proving the current slot is still Prepared; retain the event tombstone and consumed admission turn. |
| Sender becomes Active; recipient stays silent or never activates | No payload is released without both Active proofs. At the original deadline, the sender can prove expiry and recover its reservation without a peer receipt; the admission turn stays spent. Reconnect cannot accelerate the deadline. |
| Recipient becomes Active; its acknowledgment is lost | Retry the private evidence exchange for the same event. Do not activate another slot or regenerate the introduction nonce. |
| Recipient closes before seeing an introduction | Persist its exact closure and retain it for private delivery/retry. Once validly bound to the Active obligation, it can support settlement without claiming that an introduction was delivered. Old data remains rejected. |
| Receipt or settlement response is lost | Retry the same private event/owner update. A renewed receipt changes its current signature evidence, not the event marker or credit count. |
| Credentials expire while pending | Preserve historical reservation provenance. Verify authority appropriate to the eventual transition; a silent peer's expired membership must not prevent the recipient's own authorized closure. |
| All private openings/recovery material are lost | Preserve the lifetime account registration and operator state. There is no second genesis or balance reset. Continued usability is not guaranteed. |

Transport cancellation does not grant an early refund. The fixed deadline,
not a claim that the recipient disappeared, authorizes expiry. The client must
prove that transition under valid own authority and policy; operator downtime
can delay acceptance. This provides recovery without meeting the peer again,
not perfect simultaneous fair exchange. Runtime tuning affects future
reservations only; see [operational tunables](tuning.md).

## Settlement authority and remaining implementation work

An early outgoing refund requires an authenticated recipient Answer bound to
the reserved pair, nonce, group and role. At the original deadline, proved
expiry returns the reservation without a peer receipt. Outgoing Close settlement
is rejected, so hiding Close cannot improve the sender's refund timing. A
recipient's own closure immediately resolves only its incoming obligation. A self-declared incoming answer
cannot earn a reward without the additional authenticated acknowledgment event
selected by the response protocol. No reward formula is chosen here.

The account-state experiment verifies cmsg's versioned delegated P-256 receipt
and original-sender acknowledgment. Native cmsg verifies the underlying
Ed25519 contact event before preparing this extension; the circuit does not
independently parse that original event. Historical verification preserves the
original settlement identity and retained authority.

Before enabling this protocol, complete and adversarially test peer proofs,
archived settlement and client recovery, block/consent history and cmsg release
composition. Preserve the existing real-proof ledger race/retry tests. Test
both named envelopes together for shared identifiers, and resolve the full
relation's browser cost. Desktop experiment results do not establish acceptable
latency or memory use on target mobile browsers.
