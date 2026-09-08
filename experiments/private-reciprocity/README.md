# Private acknowledgement experiment

This experiment assembles existing Semaphore membership proofs and a SQLite replay ledger. It explores one narrow claim: **another qualified identity endorsed a named sender, without disclosing which identity**. It does not prove delivery, message content, a sincere conversation or distinct human beings.

## Protocol

The registered protocol uses a [signed commitment-only checkpoint](SNAPSHOTS.md), scoped to one community, policy and finite epoch. The publisher freezes every enrolled commitment whose verified cvld qualification covers that entire epoch; the checkpoint contains no member IDs. A separately authenticated immutable binding identifies only the credited sender's commitment, which the client excludes from the proof group. At least 16 other commitments are required. The earlier `freezeEligibility` API retains synthetic member-ID maps as a baseline; the registered API does not publish those maps.

The client authenticates the pinned checkpoint signer, exact ordered set and independent sender binding. It rejects changed signatures, altered lists and broken links to a retained previous checkpoint. This prevents unsupported member-selected subsets. A malicious issuer can still omit accounts or maintain isolated views; an issuer's own signature cannot independently prove honest completeness. Independent witnessing remains outside this experiment.

The proof's scope is a stable hash of the community and sender ID, with no epoch. Its message binds the current epoch, eligibility digest and sender. Therefore the same hidden identity acknowledging the same sender produces the same nullifier even after an epoch or roster change. Acknowledging a different sender produces a different scoped nullifier. The actual Semaphore verifier checks the proof; the wrapper checks the exact trusted root, scope and message.

The ledger commits a new nullifier and one sender credit atomically. Concurrent replays and restarts cannot add another credit. Expiry is checked before verification and again inside the transaction. The ledger exposes no network API; its low-level `accept()` is trusted internal storage, called only after proof verification.

## Retention and limitations

The operator sees the credited sender and a scoped opaque nullifier, plus whatever its transport exposes. It does not receive the acknowledging member ID, commitment, Merkle path, message content or a sender-recipient pair. Hiding those proof fields does not hide network timing or IP addresses; anonymous submission transport is still required.

Lifetime pair uniqueness requires lifetime replay markers. This implementation stores a 32-byte scope and 32-byte nullifier per acknowledgement, plus SQLite overhead and an aggregate credit per sender scope. There is deliberately no epoch pruning of these markers. Deleting them while allowing the same identities to return would reopen credit farming. Retention ends only with a deliberate end of that community/accounting lifetime. The storage benchmark measures synthetic records separately from proof performance.

The [immutable enrollment contract](ENROLLMENT.md) specifies the stable cvld-member-to-Semaphore binding. Fresh real cvld admission and certified key possession renew minimal registered qualification without replacing that binding. The publisher retains one current full checkpoint plus an explicitly capped collection of compact signed epoch links. Returning clients cannot silently bypass missing links. `npm test` runs acknowledgement, enrollment and checkpoint suites; explicit `test:acknowledgement`, `test:enrollment` and `test:checkpoints` scripts isolate their results. Native client signing, encrypted wallet checkpoint-state persistence and network delivery remain integrations.

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
CVLD_ADMISSION_MODULE=/absolute/path/to/pinned/cvld/src/admission.js npm test
node storage-benchmark.js
```

The checkpoint suite requires the actual pure cvld admission verifier; it does not substitute a fixture verifier. The recorded run pins cvld `c416d9edd6f7f7259d84b88838b8e607b2166671`.

Only synthetic data enters CI. The initial [red phase](https://github.com/corbet-labs/cfrm/actions/runs/34259540769) recorded nine failing behavioral tests before implementation. Enrollment and checkpoint suites also recorded their own genuine stub failures. The current registered protocol passed **13 checkpoint tests**, including a real 17-member proof and renewal across epochs, at source `11acb6a30c23b28abaafe4c10e228efdaed90aae`. The same run passed 10 baseline acknowledgement, 11 enrollment, 55 main and 16 blind-permit tests: **105 in total**.

The earlier run at `e56ce6466f8c169a6ff6dce5ba12a1d0dec58092` measured one baseline proof at **968 ms / 1,035 serialized bytes** for a 99-member proof group after curve/identity initialization. A separate 10,000-record storage-only benchmark used **80.2816 incremental SQLite page bytes per marker**, including the single aggregate sender scope. See the [measured study](../../studies/private-acknowledgements.md) for scope and limits. No local desktop/laptop test execution occurred.

Authored experiment code uses the root FSL-1.1-ALv2 license. Upstream dependency licenses remain in their packages.
