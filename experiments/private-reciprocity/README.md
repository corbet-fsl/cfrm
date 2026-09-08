# Private acknowledgement experiment

This experiment assembles existing Semaphore membership proofs and a SQLite replay ledger. It explores one narrow claim: **another qualified identity endorsed a named sender, without disclosing which identity**. It does not prove delivery, message content, a sincere conversation or distinct human beings.

## Protocol

The trusted eligibility snapshot contains stable member IDs and one stable Semaphore commitment per member, with a community scope and finite epoch validity. It is an eligibility set, not a live profile directory. For a sender S, both client and verifier reconstruct the complete qualified set excluding S. The minimum set is 16 other commitments; this experiment supports 100 members with a fixed depth-7 circuit.

The client refuses a proposed context if it differs from that complete trusted set. This prevents a verifier from requesting a smaller subset **when the client already has an authentic complete snapshot**. Authentic publication, completeness and the binding of a single stable Semaphore commitment to each cvld member remain integration requirements. An operator-provided list cannot independently prove its own completeness.

The proof's scope is a stable hash of the community and sender ID, with no epoch. Its message binds the current epoch, eligibility digest and sender. Therefore the same hidden identity acknowledging the same sender produces the same nullifier even after an epoch or roster change. Acknowledging a different sender produces a different scoped nullifier. The actual Semaphore verifier checks the proof; the wrapper checks the exact trusted root, scope and message.

The ledger commits a new nullifier and one sender credit atomically. Concurrent replays and restarts cannot add another credit. Expiry is checked before verification and again inside the transaction. The ledger exposes no network API; its low-level `accept()` is trusted internal storage, called only after proof verification.

## Retention and limitations

The operator sees the credited sender and a scoped opaque nullifier, plus whatever its transport exposes. It does not receive the acknowledging member ID, commitment, Merkle path, message content or a sender-recipient pair. Hiding those proof fields does not hide network timing or IP addresses; anonymous submission transport is still required.

Lifetime pair uniqueness requires lifetime replay markers. This implementation stores a 32-byte scope and 32-byte nullifier per acknowledgement, plus SQLite overhead and an aggregate credit per sender scope. There is deliberately no epoch pruning of these markers. Deleting them while allowing the same identities to return would reopen credit farming. Retention ends only with a deliberate end of that community/accounting lifetime. The storage benchmark measures synthetic records separately from proof performance.

The [immutable enrollment contract](ENROLLMENT.md) specifies the stable cvld-member-to-Semaphore binding. Eleven enrollment tests failed against an explicit stub before its implementation was added; all eleven subsequently passed with real certified Ed25519 and Semaphore signatures. `npm test` runs both suites, and explicit `test:acknowledgement` / `test:enrollment` scripts isolate their results. Qualification renewal, signed checkpoint publication and the native client signing integration remain separate work.

A colluding qualified member can endorse a sender without receiving a message. Excluding S prevents direct self-credit only when its one stable commitment is honestly bound. Owning multiple qualified identities remains an accepted Sybil limitation. Rotating a Semaphore identity would reset its nullifiers, so commitment rotation cannot be an unauthenticated way to regain first-contact credit. Minimum set size is not a guarantee of honest anonymity: colluding or otherwise known members reduce the effective anonymity set.

This is an acknowledgement primitive, not complete private reciprocity accounting. It does not pair private sent/received counters, prove that an approach permit reached this particular recipient, or implement all numerical policies from the simulator.

## Dependencies and execution

- Semaphore identity/group/proof SDK **4.14.3**, with a locked npm dependency graph.
- Existing **4.13.0 depth-7** proving artifacts, fetched from the official artifact host and checked against [pinned SHA256 hashes and byte sizes](artifacts.json). No custom circuit or blockchain is used.
- The [Semaphore audit catalog](https://docs.semaphore.pse.dev/) lists v4.0.0 audits. The current circuit's Merkle index interface differs from that release, so this experiment claims audited protocol lineage, **not an audit of these exact artifacts or this wrapper**. [Upstream source comparison](https://github.com/semaphore-protocol/semaphore/compare/v4.0.0...v4.13.0).
- [Semaphore proof API](https://js.semaphore.pse.dev/modules/_semaphore_protocol_proof) documents proving and verification. Native Android/iOS proving performance and bindings remain untested; protocol inputs and outputs are portable values.

On a permitted test runner:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run artifacts
npm test
node storage-benchmark.js
```

Only synthetic data enters CI. The initial [red phase](https://github.com/corbet-labs/cfrm/actions/runs/34259540769) recorded nine failing behavioral tests before implementation. The complete acknowledgement suite subsequently passed **10/10 tests**, including altered-artifact rejection, in internal CI at source `a10bd27d4fa1cd1a50035b4d136604652511ac20`, while all eleven enrollment tests still exercised the stub. The next internal run at `e56ce6466f8c169a6ff6dce5ba12a1d0dec58092` passed **10 acknowledgement and 11 enrollment tests**, alongside the main 55-test suite and 16 blind-permit tests.

That run measured one proof at **968 ms / 1,035 serialized bytes** for a 99-member proof group after curve/identity initialization. A separate 10,000-record storage-only benchmark used **80.2816 incremental SQLite page bytes per marker**, including the single aggregate sender scope. See the [measured study](../../studies/private-acknowledgements.md) for scope and limits. No local desktop/laptop test execution occurred.

Authored experiment code uses the root FSL-1.1-ALv2 license. Upstream dependency licenses remain in their packages.
