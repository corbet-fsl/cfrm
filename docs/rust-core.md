# Rust meeting board and introduction allocations

The Rust library provides independently authenticated public presence and a
durable operator-side allocation ledger. Its default feature set contains only
portable verification and board code. `--features sqlite` adds the native
operator ledger; `permits` adds portable bearer permit preparation and public
verification; `permit-issuer` adds native OpenSSL signing and durable redemption.
It contains no message transport, profile payloads or browser networking.

## Identity and presence

An externally signed eligibility grant is necessary but insufficient. Every
device also needs a member-owned root signature using the shared
`cmsg.device.v1` format. The permanent member ID is a community-scoped hash of
the root public key (`cmsg.member.v1`). A suspicious eligibility issuer can
deny service or qualify extra identities, but its signing key cannot authorize
a new device as an existing member.

`MeetingBoard::apply` verifies both credentials and the device's signed
`cfrm.presence.v1` update. It accepts only canonical checksum-valid v3 onion
endpoints and explicit ports. Member/device capacity, lease duration and replay
storage limits are supplied by the host. Device sequences prevent old online
updates undoing a newer disconnect during the lifetime of this board instance.
Disconnect markers remain until older authorized leases must have expired.

`snapshot` returns the same full roster shape without a target-member argument.
Every row retains the original eligibility, root authorization and signed
update. Clients use `verify_presence` against their own pinned trust to reject
operator route substitution. The operator can still omit rows, observe presence
and correlate request timing. Full snapshots have a bandwidth cost; they are
not PIR. Profile content stays with the member endpoint.

The board is deliberately ephemeral. A restart loses its sequence floors; a
previously signed, still-valid presence lease may be replayed until expiry.
Durable immediate revocation requires a separate persisted device-revocation
mechanism and is not established by this board. Losing presence never resets
the separate durable allowance.

## Durable allocation boundary

`AllocationLedger::reserve` requires current eligibility, root device
authorization and a device signature over the exact blinded request, member,
community, immutable policy digest, nonce and expiry. A SQLite immediate
transaction performs expiry/clock checks, initial or periodic funding and one
debit together. Repeated identical requests recover their original reservation;
the same nonce with different content rejects. Different devices and database
connections share one member balance. Clock floors and configuration bindings
survive restarts. SQLite uses WAL and FULL synchronous mode; deployment storage
and backup integrity remain the operator's responsibility.

All policy values are explicit. No product allowance or deadline is selected.
Periods are fixed-duration intervals from Unix epoch; the host must choose the
intended schedule before deployment. Periodic funding is capped, and the first
registration does not retroactively earn earlier grants. Nonces are retained;
there is no pruning or administrative balance-reset endpoint.

A bare reservation is **not** a spend permit. `PermitIssuer::issue` performs the
actual signature operation inside the same immediate transaction as its debit
and cached response. Provider failure rolls back both. Retries return the
original blind signature; a bare reservation cannot later be upgraded into a
signature. Existing Node experiments remain separate from this Rust path.

## Aggregate permits and anonymous redemption

`PreparedPermit` uses RFC 9474 RSABSSA-SHA384-PSS-Randomized with a dedicated
RSA-3072 public key. It samples a private random serial and blinding state.
Its 416-byte issuance envelope is the shared epoch context digest followed by
the 384-byte blinded message. The existing allocation signature covers every
envelope byte. Save `export_private()` in encrypted local storage before issuing;
`restore_private()` permits finalization after a client restart or lost reply.
Finalization verifies the issuer's response before producing a permit.
Issuance retries still require a currently valid grant/device authorization and
the original unexpired request. An expired attempt is not automatically refunded
or signed again; hosts must choose a suitable retry window and retain checkpoints.

Each `PermitEpoch` fixes community, epoch ID, RSA public key, redemption public
key and common validity/issuance/expiry times. These descriptors must come from
a pinned, shared catalogue; accepting a personalized key or epoch would let an
issuer tag a member. The allocation database rejects reuse of an RSA key under
another context. This local guard does not prove that an operator has no other
database or protocol using its key. Dedicated keys and consistent catalogue
distribution remain deployment requirements.

The recipient obtains the authenticated sender from cmsg, generates a fresh
challenge and creates a private `RecipientClaim`. A random 32-byte salt hides
its member pair, introduction ID and challenge in a SHA-256 commitment. The
recipient durably saves the full claim, then sends **only `claim.request`** over
the anonymous transport. `PermitRedeemer` verifies the public permit and commits
its serial to exactly that commitment and claim ID. Every replica must use the
same authoritative spent-token store. An identical retry returns the same signed
stamp; another claim for the same permit loses, including concurrent requests.

The recipient checks `verify_stamp` against its saved opening before accepting
the introduction. cmsg must bind the opening to its locally known identity and
validated invitation, and journal it before attempting redemption. Network or
storage failure is indeterminate and retried; it must never be treated as
admission. The spent-token database contains random token/claim IDs, hiding
commitments and stamps, with no member pair. It still exposes redemption counts
and timing; Tor, separation of issuance/redemption, shared cohorts and adequate
traffic are necessary to reduce correlation. These library tests do not measure
an anonymity set or defeat a global traffic observer.

The client code itself must be trustworthy. An operator that can replace the
browser's JavaScript or Wasm can steal keys, contact data and blinding secrets
before these protocols run. Independent client distribution and integrity are
part of the threat model; Wasm alone is not that protection.

**These are transferable bearer credits.** A member can buy a permit and pass
it to a collaborator. The gate limits successful aggregate redemptions to paid
issuances, but does not prove that the sender paid, prevent collusive pooling,
or charge an unanswered receiver. Recipient binding prevents a spent permit
being accepted for another opening; it does not make the original credit
nontransferable. A malicious recipient can consume a ticket without answering.
No refund or reciprocity reward is inferred from the redemption stamp.

That supply limit assumes an authority honestly enforcing its ledger. An
authority holding the signing keys can mint extra permits or stamps; recipients
do not receive a public proof that every signature had a corresponding debit.
The current accounting is operator-enforced. Hiding honest members' contact
pairs does not make the permit supply independently auditable.

### Cryptographic provider boundary

The portable `blind-rsa-signatures` dependency implements the RFC blind/unblind
and public verification operations. Its current RSA dependency is affected by
[RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html), including
the 0.10 release candidate; upgrading from 0.9 alone does not resolve that
private-operation timing advisory. This crate never creates a RustCrypto RSA
private key or invokes that provider's private operation. This is a restricted
use boundary, not a claim that the dependency advisory has been patched.

The native issuer imports its private key into OpenSSL and uses
[`EVP_PKEY_sign` through `PkeyCtx`](https://docs.rs/openssl/latest/openssl/pkey_ctx/struct.PkeyCtxRef.html)
with RSA_NO_PADDING for the RFC's raw private operation. It retains OpenSSL's
default blinding and performs an explicit public fault check before returning.
The host must provide a maintained OpenSSL build and protect the dedicated
private key. No vendored or host-installed provider is silently introduced.
Provider availability and timing assumptions require deployment review.

[RFC 9474](https://www.rfc-editor.org/rfc/rfc9474.html#section-7) explains the
randomized suite's protection against malicious signer keys, dedicated-key
requirements, randomness requirements and private-operation side channels.
The surrounding application protocol and its composition with cmsg have not
received an independent cryptographic audit.

## Experimental reciprocal accounting

cmsg owns member-controlled pair restrictions and signed private resolution
receipts. The experimental [private account ledger](account-ledger.md) proves
owner/obligation binding without disclosing the pair, and private Active
presentations gate cmsg application release. The old blind receipt experiment
does not establish that binding.

Both sending without a resolution and receiving without answering or closing
consume the same member capacity under the [v2 policy](reciprocity-policy.md).
Answer refunds both reservations on their respective accepted evidence;
recipient Close refunds the recipient while the sender waits until the original
deadline. Outgoing expiry returns that reservation once without a peer receipt,
and refill is bounded by shared capacity
and its authenticated frontier. The aggregate bearer gate above remains separate.
All amounts and durations require explicit configuration.

The older allocation API's `resolve_private` still returns `UnsupportedCapability` for every input.
It cannot mint credits from an asserted answer, close flag, encrypted counter
or copied receipt. That closed endpoint is not the experimental account ledger.
Initial/periodic allocation tests do not establish
the unanswered-receive rule, permanent pair accounting or resistance to collusive
credit farming. The separate [account-state evidence](account-ledger.md) records
actual proofs and adversarial composition; it is not production activation or
an independent cryptographic audit.

## Verification

The Rust behavioral tests use real independently constructed Ed25519 signatures,
hostile-issuer substitution attempts and real SQLite transactions/restarts.
They exercise expiry inside a transaction, concurrent devices, nonce replay,
immutable policy, signed directory rows, and rejection of unsupported private
resolution. Permit tests additionally exercise real blind issuance/finalization,
client checkpoints, device races, single-spend races, recipient/challenge
substitution, key/context reuse and common expiry. Run on an authorized runner:

```sh
cargo test --features sqlite
cargo test --all-features
cargo check --no-default-features --features permits --target wasm32-unknown-unknown
```

These checks establish their stated library boundaries, not Tor-in-browser
availability or a complete private messaging product.
