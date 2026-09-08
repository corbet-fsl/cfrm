# Reproducible experiments

The terminal runner uses synthetic participants only, Node 24 and no dependencies. It writes no member database and makes no network requests. Seeded pseudorandomness is reproducibility machinery, not cryptography.

```sh
npm run experiment -- --seed 42
npm run experiment -- --seed 42 --json --output result.json
npm run experiment -- --population '{"cooperative":80,"flooder":20}'
npm run experiment -- --policy '{"maxImbalance":6,"voting":true}'
npm run experiment -- --policy '{"imbalanceEpochs":2}' --epochs 16
npm run experiment -- --epochs 12 --rounds 8
npm run sweep
npm run experiment -- --compare --epochs 16
```

`--population` replaces the whole population; policy overrides merge into the explicitly documented example policy. The CLI rejects unknown switches. Maximum input sizes bound accidental workloads to 500 participants, 120 epochs and 64 rounds per epoch. `--output` writes to the requested file; it is optional.

| Behavior | Action |
|---|---|
| `cooperative` | Sometimes approaches a random participant; accepts and replies |
| `flooder` | Attempts 20 approaches per round; declines incoming requests |
| `nonreciprocator` | Accepts incoming requests up to the inbound limit; never replies or initiates |
| `colluding-pair` | Attempts reciprocal contact with its fixed partner; requires an even population |
| `colluding-ring` | Rotates through same-cohort partners across epochs |
| `resetter` | Disconnects and reconnects before the same 20-attempt flooding strategy |

Every participant renews presence during the active experiment. After the last round, the clock advances to force abrupt lease expiry. Clean disconnect, long absence, denied admission, blocking and reconnect behavior have separate behavioral tests. Group tests exercise 99 invitations and 99 consents for 100-member groups. They model costs and consent, not encrypted network performance.

`simulate(config)`, `sweep(config, seeds, imbalances)` and `comparePolicies(config, seeds, horizons)` in `src/simulate.js` export JSON-compatible aggregate results. No contact graph is serialized. `--compare` covers three population mixes, three seeds and horizons of 0/1/2/4 epochs. It records cooperative reciprocation and late outreach, hostile approaches and unreciprocated attempts, maximum cumulative introductions received by one target and peak pending depth. The last quarter of epochs is the late-progress interval. Target concentration includes approaches from all behaviors; it is not exclusively hostile traffic.

`ForumExperiment` and `GroupExperiment` intentionally use richer synthetic internal state; they must not be used as real operator state.

The [saved seed-42 output](results/seed-42.json) and [sweep CSV](results/sweep.csv) were extracted from the public CI run linked in the [study](../studies/first-experiment.md). They are measured outputs, not hand-invented fixtures. To change policy conclusions, run new scenarios and preserve the corresponding commit and CI evidence.

The later [window comparison](../studies/window-comparison.md) records all 36 rows as [JSON](results/window-comparison.json) and [CSV](results/window-comparison.csv), with the exact source commit and CI run.
