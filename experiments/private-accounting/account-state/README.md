# Account-state foundation

**Revision3 Answer, Close and runtime waiting-period tuning passed on Crow 9/61.**
Real proofs validate confirmed-Answer and fixed-deadline refunds, immediate
recipient Close settlement, and waiting-only tuning with peer-v3. All downloaded
artifacts match the final suite checksum manifest. The archived revision2
integrations below used the former
Close/expiry burn rule. Real
browser account and peer proofs compose with signed Rust ledger acceptance and
the native cmsg release gate. This does not enable production
`AllocationLedger::resolve_private`, select numerical product policy, or establish
complete recovery or mobile feasibility. Archived version 1 evidence below
describes a different policy.

## Relation

One named permanent owner opens its last accepted hiding commitment and proves
one successor. Its registered accounting-secret commitment, owner, community,
immutable economic policy and state version are bound throughout. The current enrollment path
contains the actual root/device-authorized P256 delegation digest. An operator
cannot replace the secret through a renewed enrollment and still open the old
state. Lifetime genesis uniqueness and competing-device acceptance additionally
require the durable Rust ledger; a valid genesis proof alone proves no uniqueness.

Genesis commits exactly the configured initial available credit, zero reserved
credit, three empty authenticated maps, permanent creation time and refill
frontier conservatively anchored at `validUntil`, and zero admissions in the
current window. Outgoing and
incoming reservations debit **one available balance**. Each map entry records
the role, full original peer/nonce/group/contact policy, amount, opened-at and original expiry,
historical peer and owner authority and Prepared/Active/Settled/Canceled/Expired phase. Every terminal transition retains
the entry as a tombstone. New reservations prove event absence in both role
maps, preventing role changes from resetting an event. A third map retains
lifetime pair membership; repeated pairs receive no invented extra reward.

Reservation moves configured units from available to reserved and consumes one
shared admission in the fixed time window. Refunds never restore that count.
Activation changes only Prepared to Active. Answer restores both reservations;
recipient Close restores its own reservation immediately. It cannot settle,
burn or refund the sender's reservation early. The outgoing bond remains locked
until confirmed Answer or its original fixed deadline. Prepared cancellation
refunds capacity and retains a counted admission and permanent tombstone.
Active outgoing expiry refunds exactly once without a counterpart signature,
resolving no recipient obligation and reopening no contact. Suppressing a Close
receipt therefore cannot improve the sender's refund timing or amount.

Total `available + reserved` cannot exceed `initialCredit` while young or
`maximumAvailable` after `newcomerPeriod` since permanent genesis. Maturity
creates headroom, not credit. A due refill grants exactly
`min(refillUnits, capacity - available - reserved)` once and sets its committed
frontier to `validUntil`, including zero grants. Due time is measured from that
frontier; backdated proofs cannot collect repeated grants in one window. Offline
time never multiplies the grant. Conservation permits
only that refill issuance; refunds move reserved units back to available. Other paths, genesis
age and admission counters remain fixed.

The immutable slot `admittedAt` means the common introduction **opened-at**.
Outgoing reserve requires `openedAt == now` and commits
`expiresAt = now + current abandonAfter`. Incoming reserve explicitly adopts
both values from the genuinely verified outgoing Active presentation. That
cross-owner proof/consent boundary belongs to the native peer gate, not the
incoming account circuit alone. The gate requires matching pair, role, nonce,
group, opened-at and expiry before protected release.
Reserve/activate/Answer must fit inside the stored lease. Close can clear an
incoming obligation after the deadline; late Answer cannot revive a tombstone.
Every original expiry must precede immutable `policyValidUntil`, leaving time
to prove its refund. New admissions near that final policy boundary are rejected.

The public policy supplies initial credit, maximum available, per-role amounts,
revision and validity interval, plus `newcomerPeriod:u64`, `rateWindow:u64`,
`newcomerAdmissions:u32`, `maximumAdmissions:u32`, `refillPeriod:u64`,
`refillUnits:u32`, `abandonAfter:u64`. Its 140-byte SHA256 transcript is ASCII
`cfrm.account-policy.v2\0`, community digest32, the original four u32 amounts and
three u64 values, those seven new fields in listed order, then byte32. Integers
are big-endian; every field is required.
`ACCOUNT_POLICY_JSON` is required at build time; the manifest pins its exact
contents. Synthetic CI values are test configuration, not product defaults.

Protocol2 statement signing uses `cfrm.account.statement.v2\0`. Public
`validUntil`, immediately after `now`, is the common
`min(next rate-window boundary, policyValidUntil)`. The ledger requires request
expiry within it and rechecks after proof verification. Reserve/activate/Answer
fit the entire proof interval within the lease; reproving near a boundary may
be necessary. No contact deadline, private action or role enters the named wire.

### Operational waiting-period tuning

`abandonAfter` is the sole economic setting reloadable within this development
circuit scope. The operator changes it through the durable Rust tuning CAS;
policy revision, credit amounts, rate limits, refill terms and validity interval
remain immutable. All values are validated and no product defaults are chosen.
Changing other terms requires a separately designed migration, not a JSON edit.

The public account `policyDigest` still binds the exact full current policy.
Account commitments instead bind `statePolicyDigest`: SHA256 of the29-byte
`cfrm.account-state-policy.v1\0` domain, community32, the first76 numeric policy
bytes through `refillUnits` (excluding only `abandonAfter`), then depth byte32.
This stable transcript is138 bytes and retains `policyRevision=3` across
waiting-only tuning. Reloading a different wait preserves existing openings;
every existing slot retains its original `expiresAt`. New outgoing reservations
alone derive a new deadline. There is no implicit import of an older circuit scope.

The ledger requires its exact current full policy before and after proof
verification, rejecting stale writers. An already accepted exact retry remains
recoverable after tuning. The test harness records its own fixed500→900 tuning
step and supplies the independently trusted old/new policies to verification;
a browser-supplied policy does not authorize operator tuning.

## Maps and retained authority

The depth32 map follows the
[Aztec indexed Merkle construction](https://docs.aztec.network/developers/docs/foundational-topics/advanced/storage/indexed_merkle_tree).
Leaves contain a full field key, payload and successor index/key. An authenticated
ordered gap proves absence. Insertion updates the predecessor, then proves the
append position empty against that intermediate root. Updates preserve the full
key and both pointers. Genesis anchors the sentinel and count1; inserts increment
the authenticated counter, and other updates preserve it. There is no arbitrary
root import. Map capacity is an implementation bound, not a contact allowance.

The hash primitive remains the exact upstream fixed-length Poseidon2 sponge.
Arbitrary bytes32 IDs/keys/nonces retain two checked u128 limbs. Ordering compares
canonical full field representatives, never truncated path prefixes. The owner
secret and event-marker domains remain the measured P2 domains; account-state
and delegation-leaf encodings are separately versioned. This is not a migration
proof for existing single-slot commitments or a key-rotation/reset mechanism.

Current owner eligibility is required throughout the common proof horizon;
the owner and any new/renewed counterpart delegation must expire no earlier
than `validUntil`. For a counterpart signature, an exact
match to the slot's reservation-time authority permits an archived receipt or
acknowledgment signed during that authority's validity. A different delegated
key requires current independently verified enrollment. Receipt and acknowledgment
times must match the original event's ordering. A recipient can close after its
silent counterpart expires.

The slot also retains the exact reservation-time owner delegation leaf. An
incoming receipt may use that original authority or the owner's currently
proved authority, while current account authorization remains independently
mandatory. The acknowledgment hashes the original receipt and original signer
delegation. A bounded ACVM case uses a synthetic renewed checkpoint with a real
original receipt; actual native renewal interoperability remains untested.

## Actual cmsg signatures

The fixture constructs real cmsg root/device delegations and durable MLS
Answer/Close events. Private accounting/P256 keys remain in the browser. cmsg
returns the exact unsigned versioned receipt; the browser signs it, and the
fixture verifies the resulting original object.

The receipt357 transcript binds community, responder, peer, original initiator,
nonce, group, delegation, contact policy, history, original Ed25519 receipt
digest, decision, recipient role and time. Outgoing settlement requires the
recipient's receipt. Incoming Close uses the owner's receipt. Incoming Answer
also verifies the original sender's P256 acknowledgment of the exact signed
Answer digest. Both signatures require low-S P1363 encoding. The acknowledgment
cannot swap peer, nonce, group, delegation or answer.

Signed history and original-receipt digests authenticate context. The circuit
does not parse those original Ed25519 objects or prove their Inbox history.
Cryptography cannot prove sincere engagement or prevent consenting members
from exchanging valid signatures. Private peer reservation evidence and cmsg
block/consent enforcement remain necessary for protected release.

## Browser and host boundary

Select `ACCOUNTING_MODE=account-state-v2` and
`HASH_SCHEME=poseidon2-bn254-fixed-128-v1`. Separate `ACCOUNT_SCENARIO=answer`
and `close` runs use fresh actual cmsg fixtures and the same compiled circuit/VK.
The browser submits every proof to a real persistent Rust ledger
before advancing the page-local opening. Two separate Active peer proofs then
feed the native cmsg gate through its trusted verifier; see the
[peer bridge contract](../peer-reservation/README.md#live-fixture-bridge).
Both current revision3 integrations passed as recorded below, including real
fixed-deadline refunds and waiting-only tuning through the native ledger.
Setup hashes live in `account-state/setup-lock.json`; only explicit initial
`RESOLVE_SETUP=1` may create it. No browser witness is sent for remote proving.

BB5's [compressed setup initializer](https://github.com/AztecProtocol/aztec-packages/blob/v5.0.0/barretenberg/cpp/src/barretenberg/bbapi/bbapi_srs.cpp)
requires complete [131,072-point /4MiB chunks](https://github.com/AztecProtocol/aztec-packages/blob/v5.0.0/barretenberg/cpp/src/barretenberg/srs/factories/bn254_g1_chunk_hashes.hpp).
The build rounds the required padded circuit size plus one upward to this chunk
size, retaining the existing 524,288-point floor. A padded size of 524,288 thus
uses 655,360 points (20MiB compressed), not a power-of-two doubling. The
[memory CRS factory](https://github.com/AztecProtocol/aztec-packages/blob/v5.0.0/barretenberg/cpp/src/barretenberg/srs/factories/mem_bn254_crs_factory.cpp)
requires enough points for the requested degree. `public/circuit-stats.json`
is written before setup initialization so a later failure retains circuit
identity, gate counts and the setup plan. A new lock is written only after the
backend accepts the setup; run9/45's rejected partial-chunk lock is not a pin.

The browser proves both genesis states, both initial reservations and activations,
and an additional outgoing obligation for the recipient. Answer then proves
outgoing settlement and incoming settlement with the archived sender acknowledgment.
Answer adds Prepared cancellation and retains sender authority expiry200.
The new Close fixture instead keeps both actual device authorities valid,
proves immediate incoming Close at100, the original sender's fixed-deadline
refund at600, another outgoing refund, and one refill. Both cases tune500→900
after original Active reservations but before the native release gate binds;
the original expiry600 stays fixed. Times and values are synthetic controls.

After each proof, while the actual device is still authorized, cmsg signs its
exact named request hashes and two independent random retry IDs. Reports contain
public statements/proofs and these signatures; private state openings and map
paths remain in the browser. Batched synthetic reporting is not an operator
request format or evidence of traffic unlinkability.

`verify-request.mjs` takes trusted manifest and native-verified enrollment paths,
then only `{statement, proof, proofScope}` on stdin. It reconstructs all243 public
inputs, independently derives the checkpoint and pins policy/time/circuit/VK
before actual Barretenberg verification. Rust's durable ledger independently
checks the real device authorization, lifetime genesis, exact retry and CAS.
The common checkpoint and accepted test times come from retained native data,
not browser claims. Both proof verifiers use Barretenberg; this is not independent
implementation diversity.

## Revision3 integration evidence

Crow 9/61 passed Answer and Close at cfrm
`96c1884a08e0b7aaba0dea38c238517ae0261f9c`, with cmsg
`ef1483c0a709e86975c44f6f8c84e833e7aa6ac4`. All ten downloaded metadata/artifact
files were verified against the final suite `SHA256SUMS`, whose SHA256 is
`05e0d14f8a62949c72d00cc0c6c1d617ad9d8c2398c86b7a09d9188f5012bfaa`.
This local set is a verified **partial set**, not the complete browser package.
Evidence hashes for `answer/browser-evidence.json` and
`close/browser-evidence.json` are, respectively:

- `9fc8e278642c6336f8a8ae75bd1215f738b85843c8099074596ba9ec061798b7`
- `cbf746597767c8693b894d01b55a0148c099f50323fb00bcc8a3e0009bb4b09f`

| Boundary | Answer | Close |
| --- | --- | --- |
| Actual Chromium checks | 231 | 243 |
| Account proofs / Active peer proofs | 10 / 2 | 12 / 2 |
| Independent Node account checks | 23 | 25 |
| Live chronological Rust applies | 10 | 12 |
| Current-own state checks | 21 | 25 |
| Separate Rust ledger checks / child processes | 22 / 31 | 24 / 35 |

Each browser count includes 42 checks for each peer proof. The real operator
changes the waiting period from 500 to 900 after both original Active states,
before the native gate binds. Existing commitments and the original expiry 600
remain unchanged. Confirmed Answer refunds the sender early; incoming Answer
settles using the original acknowledgment after sender authority expires.
Prepared cancellation also receives real acceptance. Separate Rust replay
checks include tuning, recovery of an exact accepted old-policy retry, and
rejection of an unused signed old-policy request. ACVM-only mutation cases are
counted as browser checks, not additional proofs or ledger transitions.

Close proves the recipient's immediate refund at time 100, then the original
sender's refund at its unchanged deadline 600, a second unanswered outgoing
refund and one bounded mature refill. Both actual fixture authorities remain
valid for these requests. Coherent ACVM cases reject outgoing Close as either
early refund or burn, premature or altered expiry, duplicate refund and a later
recipient-signed Answer against the expired tombstone. Withholding or delivering
the genuine Close produces the same deadline-refund successor without peer
eligibility. New reservations alone adopt the tuned wait; refunds retain the
admission count and tombstone. These times are synthetic test controls.

The account circuit has 343,939 gates (padded to 524,288); peer-v3 has 19,987
(padded to 32,768). Account circuit/VK hashes are
`e499d4f7d9cda9c7dd22e3a96f36318c88f6101db9106d02aa52c9d4abe467f7` /
`cca35478eed52601593fbd253ace56da26066160a6db2afd3b0cca86d8675144`;
peer circuit/VK hashes are
`cbd57dc1f2ae45e11cfc39c4d1c1e3fa5b8aa73ef3021e4068d41a32ce22913b` /
`29ddebe6e7e0d22b34c1e6dfbe5168fb170841d5222a004b97a930127300f5a4`.

Every proof is 14,656 bytes. Account proving took 28.174–28.661 seconds per
transition in Answer and 28.016–29.575 seconds in Close; browser verification
took 21.64–50.16 ms and 21.28–54.32 ms, respectively. Peer proving took
1.864–1.943 seconds in Answer and 1.910–1.930 seconds in Close, with verification
33.56–39.48 ms and 32.32–34.96 ms. These are individual proof timings, not full
first-contact latency. Chrome 152.0.7977.64 and Node 24.19.0 used one browser
proving thread; each flow loaded 47,032,566 bytes. Sampled Chromium-family PSS
peaked at 1,286,292,480 bytes (about 1.20 GiB) in Answer and 1,258,962,944 bytes
(about 1.17 GiB) in Close. Answer had 2380/2386 complete samples and a maximum
8.418-second gap; Close had 2757/2761 complete samples and a maximum
8.789-second gap. These whole-flow
samples exclude native/Node processes, can miss peaks, and do not measure
isolated Wasm memory or establish mobile feasibility. Actual native renewal
remains untested; current-own queries remain snapshots and both proof verifiers
use the same BB engine.

## Archived revision2 integration evidence

Crow 9/58 passed the former Close/expiry burn policy in both scenarios at cfrm
`eddc92835b2e2b08bc431852c8ff3332203198eb`, with cmsg
`80bbcf30e777b56a9ce6f8ea4a261f440c349eb0`:

| Boundary | Answer | Close |
| --- | --- | --- |
| Actual Chromium checks | 224 | 229 |
| Account proofs / Active peer proofs | 10 / 2 | 12 / 2 |
| Independent Node account checks | 23 | 25 |
| Live chronological Rust applies | 10 | 12 |
| Current-own state checks | 21 | 25 |
| Separate Rust ledger checks / child processes | 19 / 27 | 21 / 31 |

The retained suite is `private-accounting-account-state-v2` under the tested
cfrm revision. Its `SHA256SUMS` manifest hashes to
`3cb58348d9991c06271c2c321fd16a40e1a1c1a2f72431bd565dc14322a6b980`.
Downloaded evidence, manifests, nested peer artifacts and CI formatting were
verified against it; the local metadata set is not the complete browser package.
The account circuit/VK hashes are
`76b2da89ccb347875dfcd90e380f120b30138c36d8a2556d47b62659a1fa65ea` /
`1b05f243e422cf1a6a765af4dffffa1dd5255188ccf8ab31e6e562de3924c1bb`;
the peer circuit/VK hashes are
`5e856def181114a416cb0dbab4a55d7d15cace611e87b6f4d308d507354f9efd` /
`f05a9e9e422e0850fe414a00087ae9269f7e8ef6b63cd8809644a05832f26b37`.

Each browser count includes both peer contracts' 41 checks each. Genuine cmsg
delegations supply the original device authority. The native gate verifies
outgoing Active evidence before recipient consent, then both Active proofs
before the actual introduction and decision. Answer restores both reservations;
incoming settlement uses the original sender acknowledgment after that sender's
credentials expire. Prepared cancellation receives real acceptance. Close spends
the sender's reservation and restores the recipient's; recipient settlement
succeeds after sender expiry. The additional outgoing obligation is activated,
expires without a refund, and is followed by one due refill. Across the two
scenarios all six private actions have real accepted proofs.

Current-own checks reject absent/altered states and superseded states after
settlement. Separate Rust contracts exercise competing signed successors,
commit/response loss and exact retries. Evidence is retained in
`answer/browser-evidence.json` and `close/browser-evidence.json`; these contain
synthetic fixture data, not private witness paths or balances.

Every proof is 14,656 bytes. Account proving took 27.23–28.07 seconds per
transition in Answer and 26.99–29.59 seconds in Close. Peer proving took
1.92–1.98 seconds in Answer and 1.93–1.97 seconds in Close. These are individual
proof timings, not complete first-contact latency. The run used
Chrome 152.0.7977.64, Node 24.19.0 and one browser proving thread. It loaded
47,020,888 bytes in each scenario. Sampled Chromium-family PSS peaked at
1,259,763,712 bytes in Answer and 1,256,017,920 bytes in Close (both about
1.17 GiB). Answer had 2328/2334 complete samples and a maximum 8.67-second gap;
Close had 2679/2682 complete samples and a maximum 8.77-second gap.
These figures include the whole browser flow, exclude native/Node processes and are
neither isolated prover memory nor an exact peak. Shared-host timing and
sampling gaps prevent mobile or minimum-memory conclusions.

The old-self renewal case is a successful ACVM execution using a synthetic
renewed checkpoint and a real original receipt, not native renewal
interoperability. Current-own checks remain snapshots rather than a lock
through network delivery. Proof verification and durable ledger behavior are
distinct boundaries; the browser and independent verifier use the same BB
cryptographic engine.

## Archived version 1 evidence

These runs predate the current lifecycle/rate/refill policy. There is no v1
state import or migration; changing scope must
not permit a second lifetime genesis.

Crow 9/46 at `79708b7251e6a983b3478bd9530068778940a436` passed nine actual
Answer-flow browser proofs, 85 browser checks and 19 independently pinned Node
checks. The Rust integration then exposed a SQLite lock timeout during slow
verifier startup. The corrected ledger passed 13 native storage/authorization
tests on Crow 9/48 at `524956395852696c1d3f6ac4bd57ef5f8652c261`.

Crow 9/49 at that corrected source reused the hash-verified run 46 public proofs
and retained native enrollment. All 18 real Rust integration checks passed,
including independent-process contention, durable acceptance, process exit
after commit, expired exact retry and malformed-proof rejection. This replay
did not rerun the browser or receive private witnesses.

Crow 9/50 at `1b404017b9bde8cffe9c27efff76bb8c275057b7` passed the separate
Close flow: eight real browser proofs, 69 browser checks, 18 independent Node
checks and 17 real Rust ledger checks. The recipient settled after the silent
sender's credentials expired. The additional outgoing obligation remained
reserved. This run measured 26.4–27.5 seconds per proof and sampled PSS of
1,203,539,968 bytes (~1.12 GiB), with 1212/1238 complete samples and a maximum
271 ms sampling gap. It used the same circuit/VK and synthetic policy as Answer.

The circuit has 319,319 gates, padded to 524,288. Run 46 measured 26.4–27.4 seconds
per proof, 14,656 bytes per proof and 46,599,980 loaded bytes. Sampled Chromium-family
PSS reached 1,192,218,624 bytes (~1.11 GiB), with 1352/1379 complete samples and a
maximum 238 ms sampling gap. This is a desktop, single-thread measurement;
sampling can miss peaks and shared-host load affects timing. The cost prevents
claiming readiness for the intended browser experience. Mobile viability and
exact peak Wasm memory remain unverified.

Private matching Active proofs and the native release gate are exercised in
both current refund/tuning scenarios and both archived fixtures above.
Recovery/opening synchronization, authenticated
policy/key migration, proof of opaque history evolution, operator consistency
and target-browser measurements remain outside this evidence. Additional
rewards/disapproval are unselected. This is neither a complete production
release nor a cryptographic audit.
