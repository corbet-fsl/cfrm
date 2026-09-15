# Peer reservation proof foundation

**Peer version3 passed in Answer and Close on Crow 9/61.**
Two real browser peer proofs per scenario verified against genuine Rust account
acceptances
after waiting-period tuning and fed the native cmsg protected-release gate.
Archived peer-v2 integrations are retained separately below. Production
`AllocationLedger::resolve_private` remains closed; this fixture does not
establish deployment, complete recovery or mobile feasibility. The older v1
relation only compiled on Crow 9/51 at `0ae9b897490bd48810b89fcc561e9e04128a80bc`.

This separate Noir relation proves membership of one Prepared (`1`) or Active
(`2`) obligation in an already accepted account state. Settled (`3`), Canceled
(`4`) and Expired (`5`) never qualify. Both roles use this same circuit. Its public statement is for the
authenticated peer channel only; it must never accompany a named operator
request. Balance, total reserved credit, other slots, map positions/paths and
the owner's secret remain private.

## Wire and verification contract

```
{ version: 3,
  statement: {
    community, owner, peer, role, nonce, group, contactPolicyDigest,
    historyDigest, phase, openedAt, expiresAt, ownerAuthority, statePolicyDigest, stateVersion,
    stateCommitment, challenge, presentationBinding
  },
  proofScope: { circuitDigest, verifyingKeyDigest },
  proof, accountAcceptance }
```

Every digest/identifier/challenge is a canonical array of 32 bytes. Proof is
lowercase hex. Role `0` is the original initiator's outgoing obligation; role
`1` is the original recipient's incoming obligation. `accountAcceptance` is
the original signed Rust `AccountAcceptance`, including its entire named
statement and account-circuit proof scope. That account scope differs from the
new peer circuit scope. The peer learns the certificate's metadata as well as
the selected tuple; no certificate or presentation goes into its named update.

The relation has **389 public field elements**, ordered exactly as `main.nr`
and `publicInputValues()`. Arbitrary bytes32 use two big-endian u128 limbs;
state, owner-authority and presentation field outputs require canonical BN254 encoding.

Peer-only `ownerAuthority` is the exact enrollment leaf committed when this
owner reserved the slot. The native verifier supplies the initial MLS device
key; its trusted Node adapter matches that key and permanent owner to the
independently retained original cmsg delegation and recomputes the leaf. A
sibling device cannot substitute its own enrollment for that reservation.
This field never enters the named account statement.

The public peer-only `openedAt` and `expiresAt` are tied to the selected slot's
immutable common lease. Both peers must independently expect those same values.
The host rejects `now >= expiresAt`; reloading a different current waiting
period cannot move that deadline. Prepared evidence never authorizes incoming
debit or payload. Account acceptance uses protocol2 with its common validity
horizon; its original acceptance time must lie within that signed window.

`createPeerVerifier()` receives locally pinned peer and account circuit/VK
digests, exact compiled circuit/VK bytes and the host's actual
`verifyAccountAcceptance(certificate)` adapter. This adapter must invoke
`cfrm::accounting::verify_account_acceptance` under a pinned operator key and return `true`
only on success. There is no default verifier. An arbitrary success callback
would bypass that required trust boundary; it is not a supported substitute.

For each verification the host supplies:

- `expected`: all statement fields except `presentationBinding`, obtained from
  the authenticated cmsg exchange and the selected accepted state/version;
- `now`, the current trusted time, the common `accountPolicy`, and the trusted
  `enrollmentRoot` for the acceptance's common checkpoint.

The verifier checks the signature, scope, accepted commitment/version,
community/owner, stable policy digest and current validity, expected tuple and
fresh challenge, then verifies the actual proof under the pinned peer VK. The
host must bound transport JSON before parsing and must never accept expected
values or verifier implementations supplied by the presenting peer.

The success result does **not** consume the challenge or authorize data. cmsg
must durably consume the exact challenge, check current closure/consent/nonce
and its own current Active slot, and enforce the gate on every protected path.
Prepared evidence cannot authorize release. Caller state must retain challenge
use across device restore; repeat proof verification is deliberately stateless.

## Relation and context limits

The circuit repeats only the existing account encodings (secret, event, state,
slot, leaf and internal-node transcripts). JavaScript uses the existing
`account-state` hashes and `AccountWitness` maps. Poseidon2 itself comes from
the same pinned upstream library; no permutation or sponge is implemented here.
Selected membership authenticates the complete indexed leaf, including both
links, against a 32-level path. Linked-map ordering and count induction come
from the **accepted account-state relation**. Arbitrary imported roots or an
operator certificate for an unproved state do not establish that invariant.

The new fixed-length presentation hash is:

```
Poseidon2_fixed_10(
  ASCII("cfrm.peer-reservation.v3"), 1,
  ownerSecretHi128, ownerSecretLo128, acceptedState, selectedSlotHash,
  challengeHi128, challengeLo128, historyHi128, historyLo128)
```

It binds the challenge and history to the same secret and selected slot.
**History is presentation context:** the current account-state obligation does
not contain `historyDigest`. The owner can prepare a new valid presentation
under a different context; the verifying host must independently require the
actual cmsg history. This proof does not authenticate the contents or evolution
of an opaque history hash, or prove original recipient consent by itself.

A new challenge does not make a historical account certificate current. Current
local cmsg gates and monotonic slot transitions remain necessary. Malicious
operator forks require an independently consistent ledger/log assumption or
additional witnessing; this membership proof cannot establish non-equivocation.

## Bounded integration entrypoints

Compile-only, from `experiments/private-accounting` on the existing Crow worker
after its normal locked dependency installation:

```sh
timeout 600 node peer-reservation/compile.mjs "$PEER_ARTIFACT_DIR"
```

The helper uses the existing pinned Noir WASM compiler and file-manager
resolver, writing compiled JSON and source hashes to the mandatory separate
output directory. Only pinned `p2hash` is a dependency; no SHA or signature
circuit is required. It does not fetch setup or prove. Subsequent circuit stats
and VK also need a **separate peer artifact namespace**. No existing build
selector is required for this command. The shared CI also supports
`CHECK_PHASE=compile CIRCUIT_PACKAGE=peer-reservation`.

`runPeerReservationContract()` in `browser.mjs` is callable once the host has:

1. Compiled/pinned this relation and initialized the existing BB API with pinned
   public setup sufficient for it.
2. Retained an actual accepted live `AccountWitness`, selected event, and the
   real signed operator acceptance for that exact version/state.
3. Provided independent cmsg context/current policy and a real Rust acceptance
   verifier adapter, with a peer-generated challenge.

It creates one real proof and bounded adversarial witness/host cases, checks
public-input equality and repeats the positive proof after negatives. The
result contains peer-only presentation data; real deployments must not log it.
`createPeerVerifier()` is portable to Node for independent public-proof
verification using separately loaded/pinned artifacts and the real adapter.

The current source wires driver IPC to obtain the real acceptance **while the
browser retains its private opening**, browser/Rust verification and the trusted
Node adapter below. Peer-v3 with explicit expiry and stable policy binding passed
both current integrations; all downloaded artifacts match the final suite manifest.
Account browser results do not retain openings outside the page.
Do not serialize witnesses to the driver or
replace this step with a synthetic acceptance.

### Live fixture bridge

Account-mode builds also compile this relation and pin its separate circuit/VK
under `public/peer-reservation/`. Its padded degree must fit the already pinned
account setup; no additional setup service is contacted by the browser.

The test-only loopback `/account-ledger` accepts public account proofs and real
cmsg device authorizations. It reconstructs admission/device objects from the
server-retained native enrollment and calls the actual Rust ledger. Each
chronological proof receives its genuine signed acceptance before the page
advances its private witness. The bridge accepts no opening or Merkle path.

Native cmsg supplies independent challenges, context and initial device keys.
Its trusted process adapter invokes `verify-request.mjs` with locally pinned
manifest/enrollment/config paths. The adapter reconstructs the enrollment root,
verifies the peer proof and calls the real Rust acceptance verifier. For the
native own-current path only, it additionally queries the trusted own ledger
for the exact accepted version/commitment. It never queries a counterpart's
current account. Browser IPC exposes no current-account lookup.

The trusted CLI returns `{verified:true, statement, validUntil}`. This expiry is
metadata, separate from the peer proof statement: the minimum of common policy
expiry, the slot's original `expiresAt` and the exact reservation-device
delegation expiry. Native verification already bounds that delegation within
its original admission and root-device certificate. cmsg must recheck its own
current clock against this absolute bound after asynchronous verification and
before release; verification need not finish in the same clock second.
The account acceptance's original `statement.validUntil` bounds when its state
transition could commit. It does **not** expire an accepted Active obligation
at the next rate-window boundary and is not used as the release expiry.

Peer `statePolicyDigest` binds the immutable economic policy, excluding only
the operational waiting period. The original acceptance still contains its
full signed account policy. The verifier checks that full digest and signature,
then requires its stable digest to match the configured current policy and
presented state. An old genuine certificate remains usable after waiting-only
tuning while its original slot lease and device authority remain valid. The
native cmsg gate retains that same stable digest and original lease. Incoming
reservation copies the exact sender lease only after the real outgoing proof
and local consent; the account circuit by itself does not establish that
cross-owner authorization.

The live bridge's bounded checks query every newly accepted own state, reject
absent/altered identities and states, and reject a previous accepted state after
its successor, including settlement. This is a **read-only snapshot**, not a
lock through delivery or evidence of distributed first-payload serialization.
cmsg must separately enforce initial device ownership, durable payload
consumption, closure history and lease validity. Historical Active certificates
cannot grant a new pair/nonce/group/lease, but proof verification alone does
not establish that a certificate is the latest one.

Only synthetic fixture pair presentations appear in test evidence. Production
must keep these artifacts on the authenticated peer channel.

## Peer-v3 evidence

Crow 9/61 passed Answer and Close at cfrm
`96c1884a08e0b7aaba0dea38c238517ae0261f9c`, with cmsg
`ef1483c0a709e86975c44f6f8c84e833e7aa6ac4`: Answer's 231 and Close's 243
Chromium checks each include **42 checks for each of two real Active peer proofs**.
All ten downloaded metadata/artifact files match final `SHA256SUMS` (SHA256
`05e0d14f8a62949c72d00cc0c6c1d617ad9d8c2398c86b7a09d9188f5012bfaa`).
The downloaded files are a verified partial set, not the complete browser package.
The [account evidence](../account-state/README.md#revision3-integration-evidence)
records both scenario evidence hashes.

All four proofs are 14,656 bytes. Answer takes 1.864–1.943 seconds to prove and
33.56–39.48 ms to verify; Close takes 1.910–1.930 seconds and 32.32–34.96 ms.
The circuit has 19,987 gates, padded to 32,768, with
389 public fields. Its circuit/VK hashes are
`cbd57dc1f2ae45e11cfc39c4d1c1e3fa5b8aa73ef3021e4068d41a32ce22913b` /
`29ddebe6e7e0d22b34c1e6dfbe5168fb170841d5222a004b97a930127300f5a4`.

The native gate verifies the original Active presentations after the real
operator changes waiting time 500→900; the original expiry 600 remains fixed.
Cases reject altered expiry, authority, tuple, stable policy, history,
challenge, path, terminal phase, certificate, scope and proof. State openings
remain in the page. Answer's live bridge accepts 10 chronological account proofs
and passes 21 current-own checks; Close accepts 12 and passes 25. Separately,
Node passes 23 account checks in Answer and 25 in Close; Rust ledger replay
passes 22 checks across 31 child processes and 24 across 35, respectively. These are distinct
integration boundaries, not distinct cryptographic implementations.

Each one-thread Chrome 152.0.7977.64 flow loads 47,032,566 bytes. Whole-flow
Chromium-family PSS reaches 1,286,292,480 bytes (about 1.20 GiB) in Answer and
1,258,962,944 bytes (about 1.17 GiB) in Close. Answer has 2380/2386 complete samples
and a maximum 8.418-second gap; Close has 2757/2761 and an 8.789-second gap.
This includes account proving,
excludes native/Node processes and does not measure the peer circuit's isolated
memory or an exact peak. Mobile feasibility, native renewal and delivery-wide
locking are not established by this run. See the
[current account evidence](../account-state/README.md#revision3-integration-evidence).

## Archived peer-v2 evidence

Crow 9/58 at cfrm `eddc92835b2e2b08bc431852c8ff3332203198eb`, with cmsg
`80bbcf30e777b56a9ce6f8ea4a261f440c349eb0`, passed 224 Chromium checks in Answer
and 229 in Close. Each includes 41 checks for each of two real Active peer
proofs. All four 14,656-byte proofs verified against genuine signed Rust
acceptances while their state openings remained in the page. Proving took
1.92–1.98 seconds; browser verification took 34.7–35.2 ms. The native cmsg process then invoked
the independently pinned Node verifier and real Rust certificate verifier
before recipient consent and protected release.

Cases cover altered original-device authority, owner, pair, role, nonce,
group, policy, history and challenge; changed authenticated paths; terminal
phases; altered certificates/scopes and corrupted proofs. Positive verification
is repeated after negatives. Answer's live account bridge accepted 10
chronological proofs and passed 21 current-own checks; Close accepted 12 and
passed 25. Both include old accepted state rejection after settlement.
Separately, Answer passed 23 Node account checks and 19 Rust ledger checks
across 27 child processes; Close passed 25 and 21 across 31 processes.
These counts cover different boundaries and
must not be presented as independent cryptographic implementations.

Evidence is retained as `answer/browser-evidence.json` and
`close/browser-evidence.json`. Whole-flow sampled Chromium PSS peaked at
1,259,763,712 bytes in Answer and 1,256,017,920 bytes in Close (about 1.17 GiB
each). Answer had 2328/2334 complete samples and a maximum 8.67-second gap;
Close had 2679/2682 complete samples and a maximum 8.77-second gap. These figures
include account proving; they are not this smaller peer circuit's isolated
memory requirement. Exact peak and mobile feasibility remain unmeasured.

See [the reservation protocol](../../../docs/private-reservation-protocol.md)
for the two-sided release and durable recovery requirements, and the
[account evidence](../account-state/README.md#archived-revision2-integration-evidence) for
the larger state-transition proof and remaining renewal/recovery limitations.
