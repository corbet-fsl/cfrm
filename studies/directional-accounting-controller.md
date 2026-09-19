# Proposed directional accounting controller experiment

**Reviewable next experiment; no controller implementation or participation policy selected.** Preserve the original initial allowance, gradual earned capacity and limits on sustained one-sided participation. Use the [actual directional counters](directional-blind-receipts.md), not the separate endorsement-only fallback. The [existing rules simulator](../docs/rules.md) has stronger contact and delivery observables; its policy cannot simply be copied into this private boundary.

## Observable inputs and candidate rules

`A = authorizedSend` records an account's signed authorization acknowledged by a distinct qualified identity. `B = acknowledgedReceive` records its own authorized blind-receipt redemption. Neither proves delivery, reading or same-pair reciprocity. Declined or unanswered approaches can produce neither counter, while still consuming an introduction allowance reservation.

Configure explicitly: initial allowance `n`, base grant `gBase`, maximum grant `gMax`, carryover cap `C`, maturity increment and cap, rule epoch duration, common receipt grace, imbalance horizon `H`, directional limits, balance bands and absolute per-origin-epoch `A/B` caps. `H=0` means lifetime; positive `H` means the most recent `H` rule epochs. Simulator values `n=3`, `gBase=2`, `gMax=6`, `C=8`, and `H=0` versus `H=2` are comparison inputs, not selected defaults.

Proposed first comparator:

- Give `n` once per stable community member. Reconnection, key rotation and policy changes do not reset it.
- Reserve an introduction unit when the permit issuer commits issuance. Exact retries cost nothing extra. Claimed loss, silence and decline earn no refunds; delivery is unobservable.
- At rollover, expire issued old permits and carry only unissued allocation: `Qnext = min(C, Qcurrent - issued + nextGrant)`. Allocations are immutable once opened.
- Add at most one capped maturity step for a finalized origin epoch with `A>0`, `B>0`, and `max(A,B) <= r * min(A,B)`, for an explicit rational band `r>=1`. A comparison such as `r=2` rejects 99-to-1 activity. Excess counts cannot buy future maturity steps. This measures balanced authorized activity, not paired conversation.
- At allocation time, compute `delta = sum_H(A-B)`. Award the maturity bonus only inside an explicit band `abs(delta) <= bonusBand`: `nextGrant = min(gMax, gBase + eligibleBonus)`. Outside it, retain only the base grant. Already issued capacity is not withdrawn.
- Before a new signed counter operation, require prospective `delta <= outboundLimit` for an `A` increment and `delta >= -inboundLimit` for a `B` increment, plus the applicable absolute origin-epoch cap.

Thus both earning maturity and retaining its grant bonus depend on balance; occasional opposite-direction activity alone is insufficient. Current introduction permits are transferable: per-account issuance `Q` is not a strict outreach bound under one visible identity when permits are pooled. Inactivity earns no maturity, although fixed grants can refill to `C`. Lazy catch-up must not accumulate more than this cap. Base grants do not cure a lifetime hard-imbalance lock: rolling recovery also restores attacker capacity, which the comparison must measure.

## Cohorts, settlement and durable state

Map each shared receipt cohort immutably to one origin rule epoch and policy snapshot. All its receipts retain that origin, including redemption in a later grace interval. Multiple cohorts cannot multiply the epoch's caps or maturity opportunities. Keep grace shorter than an epoch for the first bounded experiment.

Finalize maturity only after every cohort for that origin has reached its common redemption deadline. New allocations may therefore use the last finalized maturity with an explicit lag. Late redemption changes its original bucket, never supplies a new-epoch event, and cannot rewrite an already opened allocation. An origin outside the current rolling window supplies no current balancing credit; its own frozen cap still applies while redemption remains valid.

| Durable state | Purpose |
|---|---|
| Existing scoped identity/enrollment; funded and settled epoch frontiers; bounded maturity | Prevent new-account allowance resets and duplicate settlement. |
| Fixed permit allocations and committed issuance counts | Reserve capacity and calculate bounded carryover. |
| Per-member origin-epoch `A/B` buckets; finalized aggregates where lifetime balance requires them | Enforce directional limits and settle maturity before pruning. |
| Shared cohort/epoch/policy/deadline mapping and monotonic retirement floors | Keep delayed events and restart behavior consistent. |
| Existing phase-local replay records, cached results, receipt markers and lifetime nullifiers | Preserve exactly-once effects and lifetime scope continuity. |

Lifetime nullifiers grow with admitted directed events; bounded carryover and recent buckets do not make all storage constant. Never add epoch, action-role, group or policy suffixes to the existing lifetime scope, or prune it to renew opportunities. No profiles, text, reported behavior or counterpart map is needed.

Counter mutation, replay consumption, cached result and controller cap/bucket update must share one transaction. Repeat time and allowance checks after asynchronous verification under the write lock. Permit reservation and epoch allocation/retirement also need atomic, idempotent integration. Existing private ledger transactions cannot provide this through sequential calls or an after-success callback into another database. Persist settlement before pruning its source counters.

Exact committed retries change no counters or maturity; preserve the service's distinct sender recovery and current receiver-authorization rules. Sender and receiver remain independent transactions: cumulative accepted `B <= A` across the same purpose/cohort system, not equality or a comparison of whichever rows survive pruning. No cross-phase join identifier or pair-based refund is introduced.

## Consent and the first reversed action

Receive limits apply only to the receiver's own authorized redemption, never to unsolicited preflight, copied certificates, visits or local decline. A sender can commit `A` before the receiver reaches its `B` cap; subsequent refusal leaves an unmatched debit without automatic refund. The [first-contact release contract](https://github.com/cmtymeet/cmsg/blob/main/studies/first-contact-release-gate.md) retains this fairness limitation.

The first reversed action still needs actual integration: the former receiver becomes named authorizer, the former sender anonymously acknowledges and redeems its receipt. It consumes no additional introduction permit. Encrypted client contact/direction/pending state must distinguish it from a new approach; ordinary established messages remain free.

An asserted `reply=true` cannot justify an operator cap bypass: current proofs establish neither the earlier pair nor unordered-pair uniqueness. Reserved reply-accounting capacity or accepting that exhausted caps postpone this accounting remains a policy question. Do not claim every first reply can be counted, or freeze ordinary conversation while deciding it.

## Required evidence

Start with meaningful failing contracts around the existing real permit and receipt services:

1. Initial allowance once; concurrent last-unit reservation, exact retries, expiry and bounded carryover across restart.
2. Counter/controller atomicity under pre/post-commit failure, duplicate requests, rollover and concurrent cohorts.
3. Late origin attribution, settlement/pruning order, clock rollback and no retroactive grant changes.
4. Symmetric imbalance limits, 99-to-1 maturity rejection, idle/unilateral behavior and one-step caps.
5. Explicit receive consent; exhausted-cap asymmetry without invented refunds; actual reversed accounting without another permit.
6. Lifetime continuity, accepted receipt pooling, and inspection of actual operator records for accidental pair joins.

Then compare fixed schedules and seeds with 100 participants: cooperative initiators, selective recipients, passive accounts, silence, reconnects, delays and colluding groups pooling receipts and permits. Give the evaluator the hidden contact graph, never the controller. Compare lifetime/rolling balance and explicit band/grant choices using useful contacts, cooperative lockouts, recovery, attacker reach, maturity concentration and retained-state growth. Keep the fast simulation separate from a real 100-member cryptographic benchmark. Existing [pooling bounds and limitations](directional-blind-receipts.md#quantifying-the-accepted-collusion) remain applicable; this experiment measures tradeoffs rather than selecting an optimal policy.
