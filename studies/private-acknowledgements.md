# Private acknowledgements and immutable enrollment

Existing Semaphore proofs can give a named member one credit from another qualified identity without including that identity in the proof. The experiment also binds one immutable Semaphore identity to a certified community member. These are independently tested primitives; they do not establish sincere interaction, complete private accounting or an anonymously transported production system.

## Executed evidence

Only synthetic fixtures and public dependencies entered the runner. The source archive's checksum and embedded Git commit were checked before execution. No desktop/laptop build or test ran.

| Phase | Exact source | Result |
|---|---|---|
| Acknowledgement specification | `f621d700013ff5f62be2b175b4263f9891306bb5` | Nine failing tests against the initial stub in the recorded public CI red phase |
| Acknowledgements implemented; enrollment specification | `a10bd27d4fa1cd1a50035b4d136604652511ac20` | Ten acknowledgement tests passed; eleven enrollment tests failed against their explicit stub |
| Enrollment implemented | `e56ce6466f8c169a6ff6dce5ba12a1d0dec58092` | Ten acknowledgement and eleven enrollment tests passed; the full run also passed 55 main and 16 blind-permit tests |

The last two runs used internal CI after external execution became unavailable. [Machine-readable measurements](results/private-acknowledgements.json) record the exact tested source and runner-reported values without private infrastructure context.

## What passed

The acknowledgement suite uses actual existing Semaphore proofs with 100 enrolled identities and a 99-member sender-excluded proof group. It rejects self-credit, outsiders, smaller proposed sets, duplicate identities, incorrect roots/scopes/messages, forged proofs and modified proving artifacts. Independent SQLite connections and a reopened ledger admit only one copy of a proof. Changing the epoch or roster preserves the same recipient/sender nullifier; changing the sender changes the scope and nullifier. Expiry is rechecked after asynchronous proof verification inside the credit transaction.

Enrollment uses a real issuer-certified Ed25519 chat key plus an existing Semaphore EdDSA-Poseidon signature over a fresh authenticated challenge. It rejects copied keys without possession, neutral/torsion points, malformed encodings, duplicate commitments under different members and replacement commitments under one member. A new certified chat key preserves the same binding. Independent SQLite-backed services and a restarted service cannot replace a committed mapping; racing two different commitments commits one. These tests use a local real-signature admission fixture. Direct native cmsg enrollment signing and the full cvld wallet flow are not yet exercised by this suite.

The cryptographic library performs group arithmetic. Enrollment adds canonical scalar/point validation, nonneutral public keys and prime-subgroup membership checks using the existing Baby Jubjub primitives; it does not implement a new curve or circuit. The current circuit/artifacts have audited protocol lineage, but differ from the publicly listed v4.0 audit target. No claim is made that these exact artifacts or wrappers received an external audit.

## One measured sample

| Measurement | Result | Scope |
|---|---|---|
| Proof generation | 968 ms | One depth-7 proof, 99-member group, after curve and synthetic identity initialization |
| Serialized proof | 1,035 bytes | JSON proof object; excludes the snapshot, artifacts and transport |
| Raw markers for 10,000 credits | 640,000 bytes | 32-byte scope plus 32-byte nullifier per record |
| SQLite page allocation | 815,104 bytes filled; 12,288 empty | One aggregate sender scope, 10,000 synthetic markers |
| Incremental page allocation | 80.2816 bytes per marker | `(815104 - 12288) / 10000` |

The proof sample used Node 24.19.0 on one CI runner. It is not a throughput distribution or a mobile battery/latency measurement. The storage benchmark inserts synthetic scalar records directly into the trusted ledger; it does not generate 10,000 proofs. Page counts exclude WAL files, backups, filesystem overhead and additional sender scopes. Lifetime uniqueness needs lifetime markers; epoch pruning would reopen farming.

## Remaining functional boundaries

- Use `wallet.storageKey('cfrm-semaphore')` as stable client material. Rewrapping the same cvld wallet preserves it; creating a new wallet cannot silently replace the enrolled commitment. Portable derivation encoding is fixed, but independent native vectors remain unvalidated.
- The immutable registry establishes account binding, not permanent current eligibility. The [checkpoint design](../experiments/private-reciprocity/SNAPSHOTS.md) freezes the complete registered qualification state at the epoch cut. Qualification renewal and signed publication are not implemented. An issuer signature authenticates a list but cannot establish honest completeness or prevent isolated-client equivocation by itself.
- The present complete snapshot exposes offline eligible member IDs and commitments. A future commitment-only roster needs a trusted enrollment certificate binding the particular sender to the excluded commitment. A sender's unsupported assertion or existing cvld chat-key certificate is insufficient.
- The operator learns the credited sender, nullifier and request timing. Anonymous submission transport and sufficiently independent eligible peers remain necessary. A minimum of sixteen other commitments is not sixteen proven honest people.
- An endorsement can be collusive. The primitive neither proves an actual message nor cryptographically joins an approach permit to that particular receiver. It does not implement the simulator's full private sent/received counter state.
