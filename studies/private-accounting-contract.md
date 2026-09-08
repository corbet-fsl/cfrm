# Private accounting: supported observations and a candidate rule contract

The proven primitives support **per-account permit issuance budgets and distinct anonymous endorsements**. They do **not** establish per-account messages sent, messages received, actual delivery or sincere replies. The simulator's directional `sent − received` rule therefore remains unsupported by the present private protocol. The candidate below is a demonstrator policy for review, not a silent replacement for that requirement.

The follow-up [directional blind-receipt study](directional-blind-receipts.md) investigates the original directional route using mutually authorized anonymous acknowledgements. It preserves the distinction between an honest-client counter protocol, poolable collusion credit and truthful delivery; neither candidate is selected or implemented.

## What can be counted

| Event | What is established | What is not established |
|---|---|---|
| Trusted allocation created | One fixed issuance budget exists for an authenticated stable account and permit epoch | A message was attempted or another person exists |
| Blind signature issued | One budget unit was reserved; retrying the same blinded request returns the same response | The client recovered the token, used it, or delivered content |
| Permit redeemed | One random permit acquired one winning claim; the same claim can retry idempotently | Which allocation/account supplied it, who received it, or whether content was displayed |
| Recipient Inbox commits locally | A compliant client validated the invitation, persisted its claim, spent the permit and persisted joined state before exposing it | Operator-verifiable delivery; a malicious client can lie or bypass its own local workflow |
| Registered acknowledgement accepted | A distinct currently qualified Semaphore identity endorsed the named target once for that lifetime scope | A particular permit was used, a first reply happened, or the interaction was sincere |
| Target authenticates and claims activity | The target voluntarily exercised its own certified account capability in this rule epoch | It privately sent or received any message |

These distinctions follow the [permit ledger](../experiments/anonymous-permits/permits.js), [registered acknowledgements](../experiments/private-reciprocity/acknowledgement.js) and [recipient Inbox](https://github.com/corbet-labs/cmsg/blob/main/src/inbox.rs). The cfrm run at `11acb6a30c23b28abaafe4c10e228efdaed90aae` passed 105 tests, including 16 permit, 10 acknowledgement, 11 enrollment and 13 checkpoint tests. That validates the primitives, not the proposed accounting controller. Existing [simulator rules](../docs/rules.md) intentionally have more information.

Do not count successful redemption responses as distinct spends: the winning claim can receive `accepted:true` repeatedly. Count first ledger insertion. Expired ledger rows are pruned, so a current row count is not automatically a lifetime operational total.

## Candidate: reservation budget with claimed endorsement maturity

1. An authenticated stable account receives `n` units once. Later rule epochs add a bounded grant `g(maturity)`, capped by `gMax`. The current budget never exceeds `cap`.
2. Committing a blind signature consumes one unit immediately. It is called a **reservation**, not a sent-message count. The issuer cannot know whether the client will successfully turn its blinded request into a usable permit. An identical blinded-request retry consumes nothing further. A new request after losing client state is another reservation.
3. Permit validity and grant epochs do not overlap. At rollover, only **unissued** budget carries forward: `nextQuota=min(cap, currentQuota-issued+nextGrant)`. Previously issued permits expire; they are not refunded merely because a client claims they were unused, rejected or lost. Short qualification checkpoints remain a separate interval.
4. A rule epoch can add at most one maturity step, and only when it contains both a newly accepted distinct endorsement and an authenticated activity claim from the target. Multiple endorsements and claims do not add more steps. Excess or unclaimed endorsements do not become banked maturity for later epochs. Maturity affects later grants and is capped.
5. Reserving a permit is not required to claim maturity. Someone who only responds to others can claim an endorsement without buying another first-contact opportunity. Ordinary replies, local blocking and declining remain free and private.

For example, `n=3`, base grant `2`, `cap=8`: reserving two permits leaves one unissued unit, so the next epoch starts with three units. This is true whether the two permits were redeemed or abandoned. Reserving all three and then claiming delivery failed leaves only the next base grant of two. This differs deliberately from the simulator's free failed-delivery behavior.

The authenticated claim stops unsolicited endorsements from automatically maturing an inactive account. It still does not prove a private interaction: a cooperating pair may endorse and claim without exchanging a message. A fixed colluding set of `k` immutable identities can supply each member with at most `k−1` distinct endorsers, which can be spread across epochs. Sincerity remains unproven and bounded collusion remains possible.

## Minimal durable state and integration seam

| State | Purpose |
|---|---|
| Existing community/member identity and immutable Semaphore binding | Stable authentication, qualification and no account reset |
| Current rule epoch and bounded maturity level per account | One initial allocation and idempotent epoch settlement |
| Current-epoch endorsement flag and authenticated-claim flag | At most one justified maturity step; no automatic passive maturity |
| Fixed current allocation quota and issued count | Source of truth for available reservations and unissued carryover; these already exist in the permit ledger |
| Existing lifetime acknowledgement nullifiers and aggregate credits | Distinct endorsement replay prevention; no endorser ID |

No per-account delivered, accepted-inbound, sent, received, reply, contact, block or group counter is justified by the present observations. The operator does not need those records for this candidate.

The proposed cfrm controller needs four authenticated/internal interfaces:

- `reserveIntroduction(accountCapability, epoch, blindedRequest)`: resolve the stable account server-side, select its single deterministic opaque allocation, and call the existing issuer. Clients cannot select new allocation IDs or quotas.
- `recordNewEndorsement(targetMemberId, ruleEpoch)`: trusted internal hook executed only with a newly committed verified nullifier. The proof endpoint knows the target; it must never attach the hidden prover's account. A duplicate proof cannot trigger activity.
- `claimActivity(accountCapability, ruleEpoch)`: a fresh certified-key challenge records the target's own voluntary claim. It does not request peers, conversation identifiers or client-asserted counters.
- `settleAccount(accountId, throughEpoch)`: close prior epochs exactly once, apply eligible maturity, carry unissued budget, and create the next fixed allocation. Reading final issuance counts, retiring old allocations and setting new state must be atomic or use a durable idempotent transition.

Account capability means fresh cvld admission plus certified key possession; a client-supplied ID or boolean is insufficient. Endorsement insertion and its epoch activity marker must commit atomically, or a crash can lose a reward that cannot be replayed. The existing acknowledgement ledger stores a lifetime aggregate, not acceptance epochs; a small epoch marker is new required state. Epoch settlement must happen before a later event overwrites that marker. The interfaces above are specifications, not implemented APIs.

## Bounds and requirements still open

For a fixed set of `m` allocations over `T` renewal epochs, with one initial `n` and grants at most `gMax`, total distinct usable permits issued are bounded by `m × (n + T × gMax)`. Distinct successful ledger spends cannot exceed issuance. Nonoverlapping validity prevents carrying issued tokens alongside a fresh epoch's full budget. This bounds introductions accepted through compliant recipient gates, not raw network packets or malicious clients bypassing their own checks.

The permits are transferable bearer objects. A visible account can use permits supplied by other accounts, so its own issuance quota is **not** a strict bound on outreach under that visible ID. Pooling preserves the total minting/spend bound while concentrating its effect. A strict nontransferable per-ID outreach limit needs an additional identity-binding protocol; that is not provided by the current blind permit.

Likewise, an anonymous acknowledgement hides its prover. It cannot increment that prover's directional reply count. Two independent endorsements do not prove mutual replies or link a specific permit to its recipient. Unsolicited inbound traffic therefore causes no operator-side penalty, but the requested symmetric sent/received imbalance also cannot be enforced globally. Recipient-local queue caps, consent, known-contact history and blocks remain useful without pretending their state is operator-verifiable.

For the next bounded experiment, compare this explicitly named candidate with the omniscient simulator baseline. Report reservation counts, anonymous endorsement activity, mature accounts and accepted-gate bounds separately from synthetic delivered/reciprocated outcomes. If directional balance or nontransferable per-ID limits remain mandatory, keep those requirements open and investigate existing cryptographic mechanisms before claiming the accounting design complete. Do not replace missing evidence with ordinary hashes of member pairs, client-reported counters or operator-visible conversation records.

[Proposed fail-first acceptance cases](../experiments/private-reciprocity/ACCOUNTING-ACCEPTANCE.md) define the next reviewable milestone. No accounting implementation accompanies this study.
