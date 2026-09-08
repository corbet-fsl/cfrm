# Bounded imbalance recovery

A rolling imbalance window restores continued cooperative outreach in the tested mixtures, while allowing nonresponsive attackers renewed reach. It preserves the hard allowance bound. It does not identify malicious intent or establish an optimal participation policy.

## Evidence

Source commit `37a0533`, [green CI run](https://github.com/corbet-labs/cfrm/actions/runs/34256651299), measured 2026-09-08. All 37 behavioral tests passed, followed by the seeded baseline, parameter sweep and 36 policy-comparison runs. [Failing recovery specifications](https://github.com/corbet-labs/cfrm/commit/ea07a67) and [failing comparison specification](https://github.com/corbet-labs/cfrm/actions/runs/34256499610) preceded implementation.

Each comparison uses 100 synthetic participants, 16 epochs, 12 rounds per epoch and seeds 1, 42 and 101. A horizon of 0 uses lifetime imbalance; horizons 1, 2 and 4 keep only that many epochs in the imbalance calculation. First-contact uniqueness, actual token spending and earned activity remain durable. The last four epochs measure continued outreach. A horizon is measured in policy epochs, not necessarily calendar months.

| Population | Cooperative | Flooder | Nonreciprocator | Resetter | Colluders |
|---|---:|---:|---:|---:|---:|
| Balanced | 80 | 10 | 10 | 0 | 0 |
| Mixed | 64 | 10 | 10 | 6 | Pair of 2 and ring of 8 |
| Hostile | 40 | 30 | 20 | 10 | 0 |

Hostile reach below means approaches initiated by flooders and resetters. Their counterpart may still reply: a polite response does not make the initiator nonmalicious. Colluders are measured separately in the first experiment and are excluded from this reach column. Concentration is the maximum cumulative approaches received by any target from all behaviors; it is not exclusively hostile traffic.

## Means across three seeds

| Population | Horizon | Cooperative reciprocated approaches | Late cooperative approaches | Hostile approaches | Hostile unreciprocated | Highest target exposure |
|---|---:|---:|---:|---:|---:|---:|
| Balanced | Lifetime | 836.3 | 15.0 | 155.7 | 30.0 | 23.3 |
| Balanced | 1 | 1,923.7 | 409.7 | 785.0 | 145.0 | 47.3 |
| Balanced | 2 | 1,907.7 | 412.7 | 761.0 | 144.3 | 46.0 |
| Balanced | 4 | 1,788.0 | 433.3 | 530.0 | 103.3 | 40.0 |
| Mixed | Lifetime | 298.0 | 0.0 | 136.3 | 48.0 | 14.0 |
| Mixed | 1 | 1,235.0 | 335.0 | 1,254.3 | 439.3 | 49.0 |
| Mixed | 2 | 1,185.3 | 366.3 | 938.0 | 343.7 | 44.3 |
| Mixed | 4 | 955.3 | 334.0 | 530.0 | 190.0 | 33.7 |
| Hostile | Lifetime | 81.0 | 0.0 | 211.7 | 120.0 | 9.0 |
| Hostile | 1 | 464.7 | 152.3 | 2,804.7 | 1,572.7 | 59.3 |
| Hostile | 2 | 418.3 | 210.7 | 1,573.0 | 947.0 | 39.7 |
| Hostile | 4 | 294.7 | 171.3 | 812.0 | 480.0 | 24.3 |

All 36 runs satisfy `approaches ≤ actual granted tokens ≤ maximum grant bound`. The peak pending queue stays at the configured cap of three in every run. A bounded concurrent queue does not prevent cumulative pile-ons as recipients clear it. Nonreciprocators gain no maturity merely because old imbalance expires.

## What to use next

Four epochs is the conservative candidate for the next experiment: it maintains later cooperative progress with substantially less hostile reach than one or two epochs. The two-epoch candidate admits more cooperative introductions at the cost of more hostile reach. Neither dominates the other on all measures, and neither is a production default. The executable default remains lifetime imbalance so the original failure remains reproducible and visible.

Recovery changes the meaning of reciprocity from a permanent debt to a recent interaction measure. That is a deliberate policy compromise. It grants neither a token refund nor extra maturity. A sender who receives no replies gets repeated but bounded opportunities; an ordinary participant is no longer permanently silenced by historical rejection.

## Limits and next comparisons

Cooperative agents always accept and reply in these scenarios; that generosity can help flooders earn activity. These fixed strategies do not establish equilibrium behavior. Random-peer flooding does not cover coordinated targeting or adversarial timing. More realistic response rates, mobile absence, local inbox closure and targeted attacks should be varied before selecting a policy. Epoch windows may take an unacceptable amount of real time if one epoch is a month; calendar duration is an independent parameter.

This study demonstrates arithmetic and synthetic behavior. The simulator retains a contact graph internally. A private cryptographic implementation still needs authenticated events, hidden state, first-contact uniqueness and anti-replay without exposing that graph. The [state boundary](../docs/boundaries.md) remains unchanged.

Reproduce with `npm run experiment -- --compare --epochs 16 --json`. Raw per-seed results: [JSON](../experiments/results/window-comparison.json), [CSV](../experiments/results/window-comparison.csv).
