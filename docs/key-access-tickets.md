# Profile key resource tickets

Profile reads and key requests do not consume introduction credit. The
`key_access` module provides a separate per-member resource quota and anonymous
single-use bearer tickets using the existing RFC 9474 implementation. It never
opens or calls `AccountLedger` or `AllocationLedger`.

An operator publishes one common pinned `PermitEpoch` whose `epochId` starts
with `cfrm.key-access.v1/`. The RSA-3072 issuance key and Ed25519 redemption key
must be dedicated to this purpose and epoch. A personalized descriptor would
tag readers; client applications must pin the common catalogue. The ordinary
introduction issuer rejects this namespace. A shared database's existing
`cfrm_permit_epochs` registry also rejects using one RSA key for different
contexts. **Separate databases cannot prove global key uniqueness:** the
operator must generate distinct keys across all separate stores and purposes.
Blind signing prevents an issuer from inspecting the hidden message, so
namespace strings alone cannot make unsafe RSA-key reuse safe.

The reader creates and durably saves the existing Wasm `BrowserPreparedPermit`.
Its root-authorized device signs `KeyAccessIssueRequest`, covering the epoch
context, independent random request ID, blinded-request digest and validity
window under `cfrm.key-access.issue.v1`. `KeyAccessIssuer` verifies admission and
device authority and atomically counts issuance against the permanent member,
across devices. The configured member/epoch quotas and request duration are
mandatory. Counts and exact-request recovery are durable. A currently authorized
replacement device can recover the same cached blind signature after the
original request expires, until the ticket epoch expires. Altering an accepted
request ID's content fails. Fresh issuance rechecks its deadline after signing.
This issuer holds member issuance counters and blinded-request digests, with no
profile, holder or challenge identifier. It shares no introduction budget.

The browser finalizes the blind signature using the existing portable RFC 9474
implementation. For a fresh holder-generated profile-key challenge it submits
`KeyAccessRedemption {permit, challengeDigest, expiresAt, claim}` over the
anonymous transport. `claim` is a fresh random 32-byte value persisted before
transmission. The challenge digest includes fresh random material from the key
exchange; it must not be a deterministic profile or member identifier.

The server constructs the opaque commitment:

```text
base64url(SHA256(JSON([
  "cfrm.profile-key-ticket.v1", epochContextId, challengeDigest, expiresAt
])))
```

`KeyAccessRedeemer` reuses the durable `PermitRedeemer`, with one shared spent
store for every replica in the epoch. It atomically spends the token for the
exact commitment and claim. An exact retry returns the same signed
`RedemptionStamp`; changing either value cannot spend it again. Its stored
columns are only token ID, random claim, opaque commitment and signed stamp.
There is no named reader, profile or holder in that store.

The holder verifies the existing redemption signature and pinned epoch, checks
the expected challenge commitment and expiry, and consumes its local random
challenge once before releasing the encrypted key. The stamp's `expiresAt` is
the epoch deadline; the tighter challenge expiry is included in the commitment.
`verify_key_access_stamp` and the browser `createProfileTicketVerifier` implement
the same checks. A stamp alone does not stop repeated use of the same local
challenge; the profile-key service's durable challenge consumption is required.
Cross-device block/owner-filter eligibility remains part of that key service.

Bearer tickets are transferable. Colluding members may pool tickets, and
timing/low traffic can correlate issuance and redemption. This gate bounds
issuance per admitted account; it does not prove a ticket stayed with its first
holder or prevent an authorized reader from sharing a recovered key.

Call `prune_expired` after epoch expiry to remove quota/retry or spent-token
records. The database keeps immutable key-use history/configuration as applicable
and a monotonic clock floor, so pruning and reopening cannot revive old tickets.
Do not copy spent stores independently, roll them back, or delete their clock
and key-use history while continuing to accept an epoch. No per-reader target
logging or metrics collection is implemented by these APIs.

The native integration tests use actual RSA blinding/signing/finalization and
Ed25519 redemption, independent-connection races, new-device exact retries,
expiry rollback, cross-purpose refusal and pruning. They also pass a genuine
native redemption stamp through the actual browser JavaScript verifier and
compare issuance signing bytes across runtimes. These tests are evidence only
after the corresponding CI revision passes; no local workstation test run is
required or implied.
