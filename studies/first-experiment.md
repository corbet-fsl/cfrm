# First-contact rule experiment

Measured 2026-09-08 from source commit `b68b53b` on a standard public GitHub-hosted runner. Only synthetic inputs were used; no secrets, real profiles or network identities entered CI. [Green run with 26 tests, scenario and sweep](https://github.com/corbet-labs/cfrm/actions/runs/34255813647).

## Method and red/green evidence

Behavior tests preceded implementation. [Initial rule specification](https://github.com/corbet-labs/cfrm/commit/39f2765) produced [17 failing behavior tests and one passing validation test](https://github.com/corbet-labs/cfrm/actions/runs/34255314767). The implemented core then [passed all 18 tests](https://github.com/corbet-labs/cfrm/actions/runs/34255485633). The seeded adversarial scenario specification [failed against the missing scenario implementation](https://github.com/corbet-labs/cfrm/actions/runs/34255581311), before the 26-test green run above. Tests were executed in CI, not on a developer desktop.

The default uses 100 participants, eight epochs, 12 rounds per epoch, seed 42, initial allowance 3, base renewal 2, maximum renewal 6, saved cap 8 and imbalance limit 3. It grants seven renewals. The population is 64 cooperative participants, 10 flooders, 10 nonreciprocators, a colluding pair, an eight-member colluding ring and six reconnect-reset attackers.

## Results

| Measure | Observed |
|---|---:|
| First approaches | 661 |
| Reciprocated first contacts | 421 |
| Unreciprocated first approaches | 240 |
| Conservative total allowance bound | 4,500 |
| Tokens actually granted, including discarded accumulation | 3,365 |
| Highest saved balance | 8 |
| Active members after lease expiry | 0 |
| First epoch approaches | 223 |
| Final epoch new approaches | 1 |

| Behavior | Participants | Approaches | Maximum earned activity epochs |
|---|---:|---:|---:|
| Cooperative | 64 | 509 | 7 |
| Flooder | 10 | 74 | 4 |
| Nonreciprocator | 10 | 0 | 0 |
| Colluding pair | 2 | 1 | 1 |
| Colluding ring | 8 | 28 | 4 |
| Reconnect resetter | 6 | 49 | 4 |

The fixed pair cannot repeatedly farm one relationship. The ring can fabricate all 28 unordered internal relationships and gain four activity epochs. A separate matched-seed test compares all-flooder and all-resetter populations: reconnecting gives identical results. Unsolicited delivery does not alter recipient balances; nonreciprocators reach at most the voluntarily accepted inbound limit. A reply remains possible when no introduction tokens remain.

## The policy fails on fairness

All 64 cooperative participants end at the maximum outbound imbalance. A cooperative participant can accumulate permanent debt from ordinary rejection, silent recipients or peers leaving. Renewing tokens does not repair that debt. Aggregate new approaches consequently fall from 223 in the first epoch to one in the last.

This is a functional failure of the strict lifetime rule, not evidence that the allowance bound failed. A recipient's local choice must not become a permanent punishment imposed on another person. The [subsequent window comparison](window-comparison.md) now measures recovery while retaining nonrefundable introduction costs and a hard grant cap.

The parameter sweep confirms the tradeoff without solving it:

| Seed | Imbalance limit | Approaches | Reciprocated | Unreciprocated |
|---:|---:|---:|---:|---:|
| 42 | 1 | 256 | 176 | 80 |
| 42 | 3 | 661 | 421 | 240 |
| 42 | 6 | 1,276 | 824 | 452 |

All nine combinations of seeds 1/42/101 and limits 1/3/6 preserve the grant bound. A stricter bound reduces reach for everyone. Higher thresholds permit more unresolved approaches. Neither result proves a desirable equilibrium or sincere human interaction.

## Limits

The simulator has an omniscient contact graph and trusted synthetic eligibility oracle. Its arithmetic is not a proof of private production accounting. It does not model network anonymity, packet loss, adversarial scheduling, large Sybil markets, actual user response preferences, denial of service or incentives outside the system. Numerical safety is established only for the explicit simulated rules. The graph and plaintext counters must not become operator storage.

Raw numerical evidence: [seed 42 JSON](../experiments/results/seed-42.json), [all sweep rows](../experiments/results/sweep.csv). Other default-seed tests and group-consent tests run from current main; the recorded dataset above retains its exact source revision.
