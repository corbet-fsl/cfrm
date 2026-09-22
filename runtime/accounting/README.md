# Reusable private accounting

This package implements the existing account-state-v2 relation. It contains the
real Barretenberg 5 / Noir prover and verifier, canonical account witnesses,
pinned artifact loading, and a signed transport-neutral client. It does not
change credit, lease, settlement, admission, or waiting-period semantics.

`createAccountProver` and `createAccountVerifier` take:

```js
const options = {
  manifestBytes,              // Uint8Array from the released manifest
  manifestSha256,             // independently pinned by the embedding application
  readArtifact,               // async (fixedName, maximumBytes) => Uint8Array
  limits: { memoryPages: 32768, maxProofBytes: 20000 },
};
const runtime = await createAccountProver(options);
const checkpoint = await checkpointFromVerified(community, verifiedEntries, runtime.hashes);
const candidate = await AccountWitness.genesis({
  hashes: runtime.hashes, community, policy, checkpoint, ownerIndex, ownerSecret, now,
});
const record = await runtime.prove(candidate);
```

The application verifies enrollment signatures before supplying `verifiedEntries`.
The browser factory uses the existing WasmWorker backend and requires
cross-origin isolation/SharedArrayBuffer. Serve the hash-pinned
`barretenberg-threads.wasm` beside the other immutable release artifacts.
`readArtifact` is the only download path. The factory hashes private snapshots
of every artifact and passes the verified Wasm through an immutable Blob to
the backend; it never fetches a second network copy. The pinned bb.js 5 loader
adds `-threads` to a basename placed in the Blob URL fragment, preserving the
underlying Blob identity. The URL is revoked after backend initialization,
including failures. The embedding supplies the asset server, isolation/worker
headers and CSP allowing `connect-src 'self' blob:` for this local fetch.
No independently supplied backend Wasm URL or network fallback is used.
There is no synthetic roster or accepted-time list. `record` contains only the
statement, public proof and proof scope. `candidate.input` and `candidate.next`
contain private material and stay at the holder endpoint. A runtime permits one
proof or verification at a time; callers must also serialize witness hashing.
Run the runtime in an application-owned Worker if cancellation or UI isolation
is required, and terminate that Worker on cancellation. `destroy` releases the
backend after the current operation. It intentionally does not pretend an
abandoned Promise interrupts cryptographic work.

Persist an account witness with `witness.exportCheckpoint(checkpointLimits)`.
It returns UTF-8 JSON bytes containing private openings, map leaves and slots;
encrypt these bytes in the member wallet before storage. The exact resource
limits are required: `{ maxBytes, maxMapEntries, maxSlots }`, with positive
integers bounded respectively by 16 MiB, 65,536 entries per map (including its
sentinel), and 65,535 slots. These are engineering hard caps for parser/work
resources; the library supplies no product defaults.
The checkpoint excludes the owner secret, runtime functions and proof artifacts.
Preserve the owner secret separately in the same private wallet boundary.

```js
const restored = await AccountWitness.restoreCheckpoint({
  checkpointBytes,          // decrypted local-wallet bytes
  hashes: runtime.hashes,   // the trusted pinned runtime
  enrollment,              // independently verified checkpointFromVerified result
  ownerSecret,             // private wallet bytes; never server input
  expectedStatement,       // independently verified acceptance's statement
  limits: checkpointLimits,
});
```

Restoration validates the exact versioned schema and bounds, reconstructs ordered
maps at their original leaf positions, verifies the current owner membership path
and saved historical authority headers, recomputes slot markers/payloads and the
account commitment, and binds the result to the expected owner, community,
policy, version and time. By default, the enrollment root is pinned by the
expected statement. To restore old saved bytes with a newer verified roster,
pass `expectedEnrollmentRoot` from independently authenticated current
configuration as well. The serialized root must match either that current pin
or the expected acceptance; the supplied roster must match the current pin.
No new genesis or state reset occurs. A serialized checkpoint cannot authenticate
its own expected statement: verify the operator signature and use fresh authenticated
status to resolve uncertain acceptance/current-state questions. During a pending
write, its durable exact signed request supplies the successor's expected
statement; that reconstruction alone does not authorize installing the successor.
Keep both the old and pending successor checkpoints until acceptance is verified
and committed atomically. The library does not provide wallet encryption,
cross-device synchronization, rollback protection or atomic compare-and-swap.
Hashing remains serialized through the application-owned runtime/Worker.

When membership changes, use
`await witness.withEnrollment({ enrollment, expectedRoot })` with the independently
verified `checkpointFromVerified` result and independently admitted common root
(32 canonical bytes). It returns a new witness with the same permanent owner,
registered secret, commitment, version, opening and historical obligations.
Current member indexes may change. New reservations check the selected peer's
membership path; subsequent proofs use the refreshed owner enrollment and root.
Supply the intended time explicitly to the next operation, whose proof still
requires current owner eligibility. A context refresh is not ledger acceptance.

Each slot retains its original owner and peer authority records privately.
Their committed authority leaves never change when the roster changes. Removed
peers and completed slots do not prevent restoration, cancellation, outgoing
expiry, refill or incoming Close. Settlement defaults to the saved original
receipt/acknowledgment authorities. To use a receipt signed under a renewed
authority, pass the existing `settle` arguments `peerEnrollment` and/or
`receiptOwnerEnrollment` explicitly; replacements must match the original leaf
or prove current membership, and a replacement self authority must be the current
owner. The circuit independently checks validity at signing/proving times and
the actual signatures. After refreshing context without a new accepted state,
persist its checkpoint with the old acceptance and the separately authenticated
current root. Wallet atomicity and root distribution remain application-owned.

For peer presentations, the acceptance's common checkpoint may precede the
current roster. `enrollmentService.checkpoint(slot)` returns only the exact
already-installed signed publication, or `null` if unavailable. Expose this as
an authenticated, read-only lookup by common slot, with no peer identifier or
proof in the request. It never recreates past membership from today's registry.
Both stores bound retained history by slot count and total publication bytes;
configure both for supported live leases. Missing history must fail closed.

After verifying the operator acceptance, call
`enrollmentClient.historical({ slot, at: acceptance.statement.now,
expectedRoot: Uint8Array.from(acceptance.statement.enrollmentRoot) })`, where
`slot` is derived using the configured checkpoint period. It authenticates the
publication signature, historical delegation validity and recomputed root, and
returns `{ status: 'historical', publication, checkpoint, entries,
acceptanceCheckpoint: { slot, notBefore, expiresAt, root } }`.
This result grants no current eligibility. Current acquisition still rejects
stale publications; an application may retain authenticated results in a
bounded cache while their reservations remain live.

For an original reservation authority, a separate lookup may use its original
`openedAt` and slot without `expectedRoot`. The pinned operator signature and
full root reconstruction still authenticate that exact common publication;
the returned root never comes from the peer. Require `expectedRoot` when looking
up an acceptance certificate. An original authority must still match the current
member's immutable account-key and secret-commitment binding before use.

The actor's peer context may include that `acceptanceCheckpoint` alongside its
existing fields. `enrollmentRoot` still pins the **current** verified roster;
the optional checkpoint separately pins the certificate's original common
root and must contain both its proof and acceptance times. The actor's own
current signed status/version/commitment checks remain mandatory. The embedding
must still verify current membership and cmsg device authority, immutable
account-key/secret-commitment continuity, original slot authorities and the
absolute release deadline. Never manufacture the checkpoint from a peer's
certificate or pass historical membership as the current roster. Without the
optional field, actor contexts retain the original same-root-only behavior.

`AccountClient` receives `transport(envelope)`, `sign(bytes)` and the pinned
operator public key. `prepareApply` converts a public proof record to the exact
device-signed Rust request. **Persist that request together with the old and
successor private state before calling `apply`.** Only install the successor
after the verified acceptance is durable. Retry the exact signed request after a
lost reply. `prepareStatus` and `status` recover the latest acceptance or an exact
request with a fresh signed challenge. They do not recover lost private openings.
Transport receives no prover candidate. Grants and device authorizations retain
their existing camelCase wire formats.

`createAccountActor` composes that client with the genuine prover and private
`AccountWitness`. Supply independently verified enrollment and its separate root
pin, the owner secret, policy, operator key, clock, current authority, typed cmsg
`authorizeRequest`/`authorizeStatus` callbacks, and local storage callbacks
`{ load, seal, open, compareAndSwap }` with explicit journal/checkpoint bounds.
The actor serializes transitions, persists the exact signed pending request and
successor opening before submission, and installs only a verified, durably saved
acceptance. `recover` retries that request or resolves it through authenticated
status; ambiguous storage writes require an authenticated reload. It never
reconstructs missing private openings from public state. `reservation` retrieves
an existing private event only when peer, nonce, group, role, policy and lease
match, allowing interrupted activation to resume without another reservation.
`accepted` and `slots` return copies; these local slot handles are never transport
fields. `withEnrollment` refreshes the verified roster without changing the
accepted state. `provePeer` uses that retained opening; `verifyPeer` additionally
requires `authorityExpiresAt` and checks fresh authenticated status against the
retained local state for an own presentation. The embedding owns encryption,
CAS/rollback protection and a common conversation release lock: before every
apply, including retries, durably invalidate any cached own-state send gates.
After acceptance, cmsg must bind a fresh own presentation before releasing data.

The Rust `AccountService` exposes only authenticated `apply` and `status` on its
member JSON boundary. It owns the trusted clock and refreshes durable policy
before requests; the existing ledger rechecks time, policy, authority and state
at commit. Public policy retrieval and the local administrative checkpoint and
tuning methods are separate from member requests. An embedding must authorize
administrative calls and authenticate distribution of policy/artifact pins.
HTTP/onion transport, request-body streaming limits and response error mapping
belong to the embedding. No HTTP route or deployed service is installed here.

For protected first contact, opt into the existing peer-reservation-v3 circuit
with `createAccountProver({ ...artifactOptions, peerReservations: true,
operatorPublicKey })`. The operator key is a separately pinned 32-byte
`Uint8Array`. The manifest must additionally pin `peer-reservation/circuit.json`
and `peer-reservation/vk.bin`, their 389 public inputs and shared account setup.
These files count toward the same caller-configured artifact limits. The runtime
reuses its existing serialized Wasm backend and setup; it exposes `peerScope`,
`provePeer({ state, event, accountAcceptance, context })`, and
`verifyPeer(presentation, context)`. `createAccountVerifier` accepts the same
options and exposes verification only. The prover requires the retained opening
of an actually accepted state and verifies both the generated proof and the real
operator signature before returning a presentation.

The trusted context contains `{ now, expected, accountPolicy, enrollmentRoot }`.
`expected` must bind the existing cmsg fresh challenge, owner/peer/device authority,
role, nonce, group, contact policy, history, original opening/expiry, Active phase,
immutable state policy, and accepted state version/commitment. The embedding must
independently verify current enrollment/delegation and must additionally compare
its own presentation with its latest durable accepted local state. Peer evidence
does not establish that a remote accepted state was never superseded. Successful
proof verification does not itself consume cmsg's challenge or permit plaintext:
pass the verified result through cmsg's persisted incoming-reservation consent and
two-sided Active reservation gates. Presentations reveal the contact pair and
belong only on the authenticated peer channel, never in named account requests,
operator storage or diagnostic logs.

`ProcessAccountVerifier` invokes the concrete `node-verifier.mjs` with an
operator-owned absolute configuration file:

```json
{"directory":"/absolute/release/public","manifestSha256":"<independent release manifest SHA-256>","limits":{"maxProofBytes":20000,"memoryPages":32768}}
```

Configure the same circuit/VK digests in its Rust `scope`. Member inputs cannot
choose executable paths, configuration, artifacts, a clock or a roster. Worker
count, input/output sizes, deadline, Node heap and Wasm linear-memory maximum are
bounded. Excess work fails with `Capacity`; it is not queued indefinitely. The
Rust parent kills and reaps timed-out workers. These are component limits, not a
claim about exact process RSS or mobile memory. The shipped worker spawns no
children. Deploy only the trusted shipped script; arbitrary replacement workers
are outside the trust boundary.

Cryptographic verification alone does not accept a state. The Rust ledger is
the authoritative boundary for current enrollment roots, policy, server time,
root/device authority, permanent genesis, exact retries and state continuity.
This separation is why the generic cryptographic runtime has no member roster
or synthetic time allow-list.

Validation is split explicitly: `test/*.test.mjs` exercises artifact bounds,
live statement encoding and real Ed25519 client signatures; Rust
`tests/accounting_service.rs` covers service authority and process limits with a
storage-only verifier. The real browser proof suite calls the shared production
`proveAccountCandidate` core. After that suite, run:

```sh
node runtime/accounting/real-proof-check.mjs /absolute/config.json /absolute/browser-evidence.json
```

This independently runs the shipped cryptographic runtime over every reported
account proof and rejects corrupted proofs and changed proof scopes. Both
verifiers use the same backend; this does not establish implementation diversity.
