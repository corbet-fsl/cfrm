# cfrm

Ephemeral community rendezvous and numerical participation rules, with deterministic abuse simulations.

The [Rust core](docs/rust-core.md) provides a member-authenticated multi-device meeting board and a durable introduction-allocation ledger. Every board device requires a member-owned root signature in addition to external eligibility. Full snapshots retain the signed rows for independent verification. The optional SQLite ledger shares one allowance across devices and process restarts. Private answer/close accounting remains explicitly unsupported pending a member-bound proof backend.

The earlier certified onion rendezvous library and numerical experiments remain available separately. cfrm composes with externally operated eligibility verification and [cmsg](https://github.com/corbet-labs/cmsg) for private text messaging. No reports or adjudication are part of its model. It is not a complete deployed community service.

Run on Node 24 with no dependencies:

```sh
npm test
npm run experiment -- --seed 42
npm run sweep
```

| Read | Purpose |
|---|---|
| [Rules](docs/rules.md) | Precise experimental choices and abuse bounds |
| [Boundaries](docs/boundaries.md) | Live presence, stable IDs and the unsolved private accounting seam |
| [Experiments](experiments/README.md) | Reproducible terminal commands and behavior toggles |
| [Results](studies/first-experiment.md) | Measured collusion, limits and fairness failure |
| [Recovery comparison](studies/window-comparison.md) | 36 runs comparing bounded history with permanent debt |
| [Rendezvous library](studies/rendezvous.md) | Certified chat-key registration, onion discovery and ephemeral sessions |

The first 100-participant experiment limits flooding and reconnect resets, but its strict lifetime imbalance rule eventually stalls cooperative members. Bounded-window variants preserve later cooperative progress while allowing more hostile outreach; seeded comparisons measure both effects. These are experimental policy choices. The synthetic model knows relationships so that experiments can inspect them; an operator must not deploy that model as a member database.

Authored material is licensed under [FSL-1.1-ALv2](LICENSE.md).
