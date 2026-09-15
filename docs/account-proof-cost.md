# Browser account proof cost

The [account-state evidence](../experiments/private-accounting/account-state/README.md)
records real browser proofs and Rust ledger concurrency/retry. Account proofs
take roughly 28 seconds and sampled Chromium memory exceeds 1 GiB on the
measured desktop. Multiple owner transitions precede a first introduction;
per-proof latency is not the full interaction time. Acceptability needs a
complete interaction and target-browser measurement. Mobile viability remains
unverified. The [waiting period is an operational tunable](tuning.md), and must
allow for proving, acceptance and connection delays as well as user response
time. Existing reservation deadlines do not move when that setting changes.

## Fixed-wait refund relation

Crow9/61 at `96c1884a08e0b7aaba0dea38c238517ae0261f9c` passed Answer and
Close with a trusted waiting-period change from 500 to 900 synthetic seconds.
Answer measured the following costs.
Its ten account proofs took 28.174–28.661 seconds each; its two peer-v3 proofs
took 1.864–1.943 seconds each. All proofs are 14,656 bytes. The account relation
has 343,939 gates, padded to 524,288; the peer relation has 19,987, padded to
32,768. Both reuse the pinned 655,360-point setup.

Answer loaded 47,032,566 bytes and sampled Chromium-family PSS up to
1,286,292,480 bytes (about 1.20 GiB), with 2380/2386 complete samples and a
maximum 8.418-second gap. These samples exclude native fixtures and Node
verifiers and can miss peaks. Exact peak Wasm memory remains unknown.

Close's twelve account proofs took 28.016–29.575 seconds each and its two peer
proofs took 1.910–1.930 seconds. It loaded the same 47,032,566 bytes. Sampled
Chromium-family PSS reached 1,258,962,944 bytes (about 1.17 GiB), with 2757/2761
complete samples and a maximum 8.789-second gap. Both scenarios use synthetic
policy clocks and include extra obligations, negative cases and verifier
startup. Neither is a real-time lease or isolated first-contact benchmark.

## Earlier relation

The v2 Answer scenario on Crow9/58 at `eddc92835b2e2b08bc431852c8ff3332203198eb`
measured 27.23–28.07 seconds for each of ten account proofs. Its two peer proofs
took 1.92–1.98 seconds each. Both proof types are 14,656 bytes. The account
relation has 331,970 gates, padded to 524,288; the peer relation has 19,971,
padded to 32,768. Both reuse the pinned 655,360-point setup.

That Answer fixture loaded 47,020,888 bytes and sampled Chromium-family PSS up
to 1,259,763,712 bytes (about 1.17 GiB). It obtained 2328/2334 complete samples,
with a maximum 8.67-second gap during the broader integration. Sampling excludes
native fixtures and Node verifiers and can miss peaks; exact peak Wasm memory
is unknown. The configured 2 GiB Wasm maximum is a limit, not measured usage.
The fixture includes genesis, an extra obligation, negative cases and fresh
verifier-process startup. Its full duration is not an isolated first-contact
latency benchmark.

The same run's Close scenario generated twelve account proofs in 26.99–29.59
seconds each and two peer proofs in 1.93–1.97 seconds. Its sampled Chromium PSS
reached 1,256,017,920 bytes, with 2679/2682 complete samples and an 8.77-second
maximum gap. Both scenarios passed; neither uses real elapsed time as its
account-policy clock, so these results do not establish a usable end-to-end
lease duration.

The following optimization ideas are not measured improvements. They have not
been applied to the implemented relation or receipt formats.

Crow 9/52 profiled the existing hash-pinned compiled circuit without creating
new proofs. Of 319,319 gates, debug-source attribution assigns 84,198 to SHA-256
and 84,596 to P-256; the deepest Poseidon2 permutation source accounts for
92,584. These are source attributions, not isolated primitive timings. Byte
packing, bounds and remaining control/map constraints also contribute. The
profile supports targeting both signatures/transcripts and map work; it does
not establish savings from any proposed edit.

## First implementation to evaluate

Keep existing cmsg signatures and account-state encodings. Separate the circuit
classes that the current public statement already reveals:

| Class | Existing public distinction | Required private behavior |
| --- | --- | --- |
| Genesis | `genesis == true` | Exact initial state and current owner enrollment |
| Reservation/activation | Non-genesis, zero settlement marker | Both roles, one balance, all maps and private phase selection |
| Settlement | Non-genesis, nonzero settlement marker | Both roles, exact receipt/ACK authority, conservation and tombstones |

Reservation and activation must share a circuit and format. Outgoing and incoming
must also share them. Splitting either pair would expose information the current
public statement hides. Each circuit must enforce its class, not merely rely on
a label supplied by the caller.

This could remove signature and receipt-hash constraints from the path before
an introduction. It requires a common pinned registry of circuit/VK digests in
the Rust ledger and verifiers, selected from the validated public statement.
Device signatures must bind the selected proof scope. Every class must preserve
the exact state commitment encoding, owner-secret continuity, common policy,
version rules and unchanged map invariants. A second genesis or alternate class
must never reset credit or skip a required transition.

Acceptance tests must cross class boundaries with real proofs and adversarial
scope substitution, expired authority, stale states, duplicate settlement and
independent-process contention. Measure the complete first-introduction sequence
and settlement separately. A smaller gate count alone establishes no browser
latency or memory guarantee.

## Additional candidates

- Share duplicate authority/path computations before changing their semantics.
- Incoming Answer can potentially use the original sender's acknowledgment as
  its sole P-256 check. Retain current owner enrollment/secret/device authority,
  the accepted active slot, full receipt context and time checks, historical
  sender authority, exact signed-receipt digest and one-time consumption. One
  selected signature check could cover outgoing receipt, incoming ACK and
  incoming Close receipt. This narrows the proof claim: it would no longer
  independently verify the embedded recipient signature for incoming Answer.
  Native/Wasm cmsg must retain full receipt and ACK validation.
- A separately versioned compact commitment-signing transcript could reduce
  SHA-256 constraints. It must retain every field, canonical encoding, all bits
  of existing byte identifiers, domain separation and exact ACK meaning. Native,
  WebCrypto and circuit interoperability would need new evidence. No new hash
  implementation or transcript is selected here.

Performance work must keep private witnesses at the endpoint and preserve
contact privacy, protected release, durable recovery and the selected v2
refill/rate policy. Extra rewards and numerical disapproval are separate policy
questions.
