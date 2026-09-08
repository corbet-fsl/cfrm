# Experimental rule policy

All values here are explicit experiment parameters. They are not settled community rules.

This simulator is omniscient. Its directional sent/received and delivery counts are not available to the current private protocol. The [private-accounting study](../studies/private-accounting-contract.md) maps the proven observations and proposes a separately named candidate for review; it does not claim these rules are already implemented privately.

The [directional blind-receipt study](../studies/directional-blind-receipts.md) separately investigates counters of mutually authorized acknowledgements, including receipt pooling and the original guarantees still unproven. Neither candidate is selected or implemented.

| Parameter | Default | Meaning |
|---|---:|---|
| `initialTokens` | 3 | New credential's first-contact allowance |
| `epochGrant` | 2 | Base allowance at each later epoch |
| `maxEpochGrant` | 6 | Maximum grant after maturity or votes |
| `tokenCap` | 8 | Maximum unspent balance |
| `growthPerActiveEpoch` | 1 | Extra grant for each earlier epoch with a newly reciprocated contact |
| `maxImbalance` | 3 | Maximum outbound or voluntarily accepted inbound first-contact imbalance |
| `pendingCap` | 3 | Pending introductions per recipient |
| `requestTtl` | 5 | Synthetic clock ticks before an unaccepted request expires |
| `presenceTtl` | 20 | Ticks before an unrenewed presence lease expires |
| `voting` | false | Enable one ±1 vote per eligible connected credential per epoch |
| `imbalanceEpochs` | 0 | Balance horizon: 0 means lifetime, positive values keep that many epochs |

One new introduction consumes one token when delivered and increments its sender's first-send count. Delivery does not change the recipient's balance. Only explicit acceptance increments the recipient's first-receive count. A first reply increments the recipient's first-send and original sender's first-receive counts. It costs no introduction token, allowing recovery from imbalance. Later conversation messages do not affect these counters.

New introductions stop when the sender's `sent − received` in the selected horizon reaches the limit. New acceptance stops when the recipient's `received − sent` reaches it. With a positive horizon, per-epoch event counts expire from the balance calculation; lifetime first-contact uniqueness, allowance spending and activity history do not reset. Existing first replies remain possible, including replies to approaches outside the current horizon. Declines, expiry and silence do not refund a delivered token; otherwise sequential spam could reuse one token. Failed delivery costs nothing. A local block or closed inbox denies a new request without allegations, reports or standing penalties.

An unordered pair can have only one first introduction for the lifetime of the synthetic credentials. Reconnection, changed display names and new groups do not reset it. A declined or expired approach is terminal in this candidate: there is no retry invitation protocol yet. This strong choice bounds replay but can prevent wanted reconnection after an accidental expiry.

Each epoch with at least one newly reciprocated contact gives at most one maturity increment. Repeating a conversation cannot farm increments. Idle accounts still receive the base grant, capped in storage, but gain no maturity. A colluding set can simulate sincere first contacts and gain bounded maturity: cryptography cannot establish sincerity.

For `m` credentials over `T` renewal grants, new approaches are bounded by:

```text
m × (initialTokens + T × maxEpochGrant)
```

Actual activity can be lower due to the balance, inbox and storage caps. More independently admitted credentials multiply the bound. The model does not prove one credential equals one person or protect against transport-layer denial of service.

Voting changes the **next base epoch grant**, by the sign of the sum of ±1 votes, clipped to `[0, maxEpochGrant]`. A tie or no votes holds the value. The initial grant stays unchanged. Each connected, eligible credential can vote once; no quorum or human-uniqueness guarantee exists. This is one explicit interpretation of stepwise governance, not a final policy.

## Groups

`GroupExperiment` models up to 100 consenting members. Each invitation to a new contact requires its own successfully delivered introduction. One token cannot invite 99 strangers. An invitation does not add the recipient to the group. Joining is explicit consent and counts as a first reply to the inviter when the invitation was their first contact. It does not manufacture 98 further reciprocal relationships with other group members.

An established contact can invite another without another first-contact charge, but still needs per-group consent. Pending contacts cannot form an alternate invitation stream. Normal group messages have no new-contact cost. The experiment checks group membership and eligibility; message transport, encryption, per-recipient filtering and group departure are not implemented here. Group rosters and invitation history are synthetic client-state models, not operator records.

## Known failure

Permanent imbalance conflates malicious nonreciprocity with ordinary rejection, selective conversation and unavailable peers. The measured lifetime baseline eventually stops cooperative initiators too. Bounded-window comparisons now exercise a recovery path without refunding delivered messages or removing the economic bound. Recovery also gives nonresponsive attackers renewed reach; the relevant result is the measured tradeoff, not a claim that rolling windows distinguish motives. The lifetime baseline remains the default for reproducibility, while `imbalanceEpochs: 2` selects the first candidate for comparison.
