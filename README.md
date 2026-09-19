# cfrm

Ephemeral community rendezvous and numerical participation rules, with deterministic abuse simulations.

The [Rust core](docs/rust-core.md) provides a member-authenticated multi-device meeting board and a durable introduction-allocation ledger. Every board device requires a member-owned root signature in addition to external eligibility. Full snapshots retain the signed rows for independent verification. The optional SQLite ledger shares one allowance across devices and process restarts. RFC9474 blind permits gate first introductions through atomic anonymous redemption. The [browser bindings](browser/README.md) perform local roster verification and permit preparation, recovery and stamp verification in Rust/Wasm. The older allocation ledger's `resolve_private` entry point remains closed.

The earlier certified onion rendezvous library and numerical experiments remain available separately. cfrm composes with externally operated eligibility verification and [cmsg](https://github.com/cmtymeet/cmsg) for private information transport. Eligibility policy and numerical disapproval are separate integration concerns. This repository does not provide a complete deployed community service.

The experimental [private account ledger](docs/account-ledger.md) adds durable opaque-state updates, lifetime genesis uniqueness and authenticated recovery across devices. The [v2 reciprocity policy](docs/reciprocity-policy.md) defines live introductions, shared bidirectional capacity, newcomer limits, irreversible admission turns and bounded refill. Private peer proofs connect accepted Active reservations to cmsg's first-payload gate. [Operational tuning](docs/tuning.md) changes the waiting period prospectively while preserving existing deadlines. The host supplies the complete pinned verifier and trusted storage. The [account-state evidence](experiments/private-accounting/account-state/README.md) records passing v2 Answer/Close browser proofs, real Rust ledger acceptance and protected cmsg release, with explicit host and recovery limits; mobile readiness remains unverified.

[Product service integration](docs/product-services.md) connects the signed discovery API, expiring encrypted profile cache, per-device presence, browser key access and reusable accounting runtime. Discovery uses a Valkey ciphertext cache with separate durable quota/replay guards. Browser profile keys stay with members; independently budgeted [blind key-access tickets](docs/key-access-tickets.md) protect key requests. The [accounting runtime](runtime/accounting/README.md) extracts proving, verification and authenticated client operations for application embedding.

The core/browser CI runs on GHA, with Crow as the fallback. At `3bc89d0`, 63 actual Chromium checks passed for the roster and blind permits, alongside 21 Rust and 55 historical JavaScript tests and portable Wasm checking. That older run covers roster/permit behavior. Crow9/58 at `eddc9283` separately passed the v2 Answer/Close integration: 224/229 browser checks, 22 account proofs and four peer proofs, with independent Node verification and real Rust ledger checks.

Run the historical simulations on Node 24 with no dependencies:

```sh
npm test
npm run experiment -- --seed 42
npm run sweep
```

| Read | Purpose |
|---|---|
| [Reciprocity policy](docs/reciprocity-policy.md) | Selected live state machine, conservation, rate bounds and failure cases |
| [Rules](docs/rules.md) | Precise experimental choices and abuse bounds |
| [Boundaries](docs/boundaries.md) | Live presence, stable IDs and accounting integration boundaries |
| [Experiments](experiments/README.md) | Reproducible terminal commands and behavior toggles |
| [Results](studies/first-experiment.md) | Measured collusion, limits and fairness failure |
| [Recovery comparison](studies/window-comparison.md) | 36 runs comparing bounded history with permanent debt |
| [Rendezvous library](studies/rendezvous.md) | Certified chat-key registration, onion discovery and ephemeral sessions |

The first 100-participant experiment limits flooding and reconnect resets, but its strict lifetime imbalance rule eventually stalls cooperative members. Bounded-window variants preserve later cooperative progress while allowing more hostile outreach; seeded comparisons measure both effects. These are experimental policy choices. The synthetic model knows relationships so that experiments can inspect them; an operator must not deploy that model as a member database.

Authored material is licensed under [FSL-1.1-ALv2](LICENSE.md).
