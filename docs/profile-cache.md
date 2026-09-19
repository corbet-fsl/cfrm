# Encrypted profile client and member key access

`cfrm/profiles` exports a portable WebCrypto client for the discovery cache,
profile encryption, owner/eligible-holder key grants and private read access.
It contains no UI, operator credential, plaintext upload, accounting call or
network fallback. The application supplies authenticated cache transport,
member-owned anonymous P2P transport, its private wallet and real eligibility
and contact-policy verifiers.

The operator receives signed ciphertext and validated public discriminators.
The owner or an explicitly chosen member holder delivers the decryption key
over the separate member channel. A resource ticket limits key acquisition;
it is unrelated to first-contact reciprocity capacity. Query and profile reads
do not reserve or debit an account.

## Wire format and cryptography

The self-contained cache record is `{admission, authorization, envelope}`.
Admission and root/device authorization use the existing cfrm Ed25519
transcripts. The browser validates the pinned issuer, community and policy,
derives the permanent member ID from the root, verifies the root's device
signature, then verifies the admitted device's profile signature. Public keys,
signatures and nonces use canonical unpadded base64url. Integers are positive
JavaScript-safe integers; timestamps are Unix seconds.

The envelope contains exactly:

```text
{version:1, communityId, memberId, chatPublicKey, profileEpoch, sequence,
 issuedAt, expiresAt, nonce, profileDigest, discriminators, ciphertext, signature}
```

Each publication generates an independent 256-bit AES key, a random 32-byte
`profileEpoch` and a random 12-byte nonce. AES-256-GCM encrypts the UTF-8 profile
and appends its 16-byte authentication tag. `profileDigest` is SHA-256 of these
ciphertext bytes, not of plaintext. No plaintext digest is exposed for
dictionary lookup. `sequence` increases across all the owner's devices and
epochs. A new device or profile edit cannot create another member slot.

`discriminators` is an object of u32 values. Field names match
`[A-Za-z][A-Za-z0-9_]{0,31}`. The server additionally validates its explicitly
configured closed registry and update quotas. The byte format sorts fields
lexicographically into `[name,value]` pairs. The signature covers UTF-8 compact
JSON in this exact order:

```text
["cfrm.cached-profile.v1",communityId,memberId,chatPublicKey,profileEpoch,
 sequence,issuedAt,expiresAt,nonce,profileDigest,sortedDiscriminatorPairs]
```

AES-GCM associated data uses `cfrm.cached-profile.aad.v1` with the same array
but omits `profileDigest`, avoiding a circular digest. This matches Rust
`discovery::profile_signing_bytes` and `profile_aad_bytes`. Signature and AEAD
bind the same public metadata. Swapping filters, epochs, ciphertext or owner
authority is rejected.

## Publisher durability and rotation

`createProfilePublisher` requires `identity`, `trust`, `limits`, `clock`,
`cache.publish`, `reserveSequence` and `saveCheckpoint`.

The identity contains `{authority:{admission,authorization}, sign(bytes)}`.
`sign` is a trusted member device-key capability. It must never be implemented
by an operator signing service or exposed as an unauthenticated general-purpose
signing endpoint. The module verifies every returned signature before use.

`reserveSequence({memberId,after})` must atomically reserve a greater sequence
from the member's shared device state. Server-side monotonic checks remain the
final write guard when a device has a stale local checkpoint.

`saveCheckpoint(checkpoint)` must durably encrypt the checkpoint in the
member's local wallet. It contains private DEKs and must never use the cache
API. The publisher saves a pending key and the exact signed publication before
network I/O. A lost cache reply leaves that pending publication intact;
`retryPending()` resends the identical ciphertext. Restoring the checkpoint
preserves this retry. It never regenerates a key for an uncertain write.
Only a successful publication replaces the active local key. An old grant
still awaiting a proof, policy decision or ticket then fails its state check.
Call `expire()` when the application's wallet expiry scheduler runs: it erases
expired active/pending keys and durably saves the retained sequence floor.
An expired uncertain publication can then be replaced with a new sequence.

`publish({text,discriminators,expiresAt})` returns the public cache record.
`currentPublication()` returns only that record. `close()` stops local serving
and clears byte-array keys. `checkpoint` is accepted only as an explicit
member-wallet restore input. Expired restored keys are discarded while the
sequence floor remains. DEK erasure is best effort in JavaScript; string copies,
browser process memory and an already authorized reader are not revocable.

`createDiscoveryClient` supplies `publish`, `fetch`, `query`, `heartbeat` and
`disconnect` methods over an injected `send(signedRequest)` callback. Its
request signatures match Rust `discovery::request_signing_bytes`, including
recursive sorting of operation keys and the pinned policy digest. The HTTP
adapter posts to `/v1/discovery` as `application/json` and bounds response bytes
before parsing. `lease()` supplies the current device's explicitly managed
lease, with this client's session ID. Heartbeats do not re-upload ciphertext.
The required `savePending(requestOrNull)` durably journals signed writes in the
member wallet; `pendingRequest` restores that journal. It never journals read
queries. An uncertain publication retries the identical outer request, ID and
lease while valid. After the outer request expires it signs the same immutable
publication with a freshly allocated lease sequence. The server treats that
exact current publication as a quota-neutral repair. Acknowledged publication
requests remain journaled until the publisher durably saves its active key and
calls `confirmPublication`. Other writes cannot overtake that pending commit.

## Anonymous reads and key release

`createProfileReader` first fetches and verifies the cached publication. Its
required `acceptPublication(publication)` callback must atomically persist a
per-owner sequence/digest high-water mark in the reader's private wallet,
reject lower sequences and conflicting digests at the same sequence. Return
`true` only after durable acceptance. This protects a reader that has already
seen a newer publication; a new reader cannot detect an operator serving an
older, still-valid owner signature without additional shared state.

The reader creates a fresh nonextractable P-256 ECDH key and nonce, then opens
`memberTransport.open({memberId:holderMemberId})`. This is a trusted,
member-owned anonymity-routing capability, not a URL or an operator relay.
The resulting connection exchanges bounded byte frames and supports `close`.
Transport operations have deadlines derived from the configured challenge
lifetime. The application must implement actual onion routing and resource
cleanup; an in-memory test adapter does not establish anonymity.

The holder signs a fresh challenge containing the exact envelope digest,
holder member/device key, random service session, both nonces, reader wrapping
key, community, policy and deadline. The reader verifies the holder's current
authority and any owner delegation before asking its wallet for proofs.

`proveEligibility(request)` and `verifyEligibilityProof(request,presentation)`
connect the real cvld wallet and verifier. The module constructs the request
itself: shared community and policy are revealed, eligibility and validity
through the challenge expiry are predicates, and the full 256-bit challenge
digest is the presentation nonce. It rejects extra revealed identifiers,
self-attestation, unrelated credential definitions and modified raw/encoded
attributes. This is the existing owner-direct experiment's AnonCreds request
shape with a new key-challenge transcript. It does not fabricate an eligibility
proof from a public admission certificate.

`proveAccess({challenge,publication})` supplies a separately bounded contact
policy proof. `authorizeAccess({challenge,publication,presentation,accessProof})`
must verify owner contact filters on proven attributes and the selected block
policy; it returns `true` only for an allowed request. Both callbacks are
required. They are a real integration boundary: the minimal eligibility proof
does not prove arbitrary attributes, block status or a stable private rate
pseudonym. Applications must supply those mechanisms or explicitly configure
an applicable unrestricted policy. Self-asserted profile fields are not proof.

The holder also verifies the fresh anonymous resource ticket. It reserves
each signed challenge before asynchronous verification, bounds concurrent
proofs and rejects replay. Failed verifications consume that challenge too.
The holder checks time, current publication and delegation again after every
asynchronous gate. Disconnect, rotation, deadline expiry and clock rollback
fail closed.

The DEK is wrapped to the reader's ephemeral key using fresh sender P-256
ECDH, HKDF-SHA256 and AES-256-GCM. HKDF uses the SHA-256 of the associated-data
transcript as salt and `cfrm.profile-key-wrap.v1` as info. A holder Ed25519
signature authenticates the wrapped response and deadline. The reader checks
the challenge binding, signature and expiry, unwraps locally, authenticates
the encrypted profile, returns inert text and clears its byte-array key.
No HTML rendering, link fetching, preview fetching or media request occurs.

## Eligible peer holders

Holder choice, discovery, desired replication count and rotation schedule
remain explicit application policy. There is no community-wide decryption key
and no automatic holder selection.

A prospective holder creates `wrappingKeyPair()` and calls
`createHolderKeyOffer({identity,wrappingKeys,expiresAt},config)`. The offer
authenticates its wrapping key with its current admitted device signature.
The owner calls `publisher.seedHolder({holderOffer,expiresAt})`; the owner
checks the holder's actual authority and signs a delegation bound to that
member/device/wrapping key and one exact publication. The seed encrypts the
DEK to that wrapping key and has another owner signature.

Send this seed only through a member-owned private channel. The operator
cache must never receive key seeds, including encrypted seeds. The holder
imports with `createSeededProfileHolder({seed,wrappingKeys,identity,...})` and
serves the same key protocol. It cannot delegate onward using this API.
Wrong recipients, key substitution, extended expiry and a changed publication
fail verification. A delegated peer cannot issue a key for the next rotation
until the owner explicitly seeds it again. Expiry bounds honest serving;
neither revocation nor rotation makes a copied old key/plaintext disappear.

## Separate per-member resource quota

`KeyAccessIssuer` and `KeyAccessRedeemer` implement the resource quota on the
Rust side. They reuse RFC9474 blind permits with a dedicated pinned shared
epoch whose name starts `cfrm.key-access.v1/` and dedicated RSA/redemption keys.
The issuer authenticates the permanent member across devices and limits ticket
issuance. It receives no profile or holder target. The anonymous redeemer
atomically consumes the token and returns a signed stamp bound to an opaque
fresh challenge digest. This store is shared by all redeemer replicas.

The browser uses the existing `BrowserPreparedPermit` for real blinding,
encrypted private checkpoints and verified finalization. Use
`signProfileTicketIssue` with its `issuanceRequest()` bytes, save the prepared
permit plus exact signed request before sending, and reuse them on retry.
Finalize the returned blind signature in Rust/Wasm before adding the public
bearer permit to the private wallet. A new request ID is a new quota request.

`createProfileTicketAcquirer` integrates that wallet with anonymous redemption.
`takePermit` atomically reserves a real finalized permit; `savePending` durably
saves the exact claim before `redeem`; `complete` marks the permit spent and
removes the pending intent. `retryPending()` preserves an uncertain request.
`retireExpired()` calls the required durable `retire(pending)` callback to mark
an expired uncertain reservation spent, then clears it so a fresh challenge
can acquire a new permit. Never recycle an uncertain/expired reserved permit
into the available pool. The redeem payload is exactly
`{permit,challengeDigest,expiresAt,claim}`. It contains no member or profile ID.

`createProfileTicketVerifier` verifies the actual Ed25519 redemption stamp
against that same pinned epoch and the exact key challenge. Pass the resulting
function as the key service's required `verifyTicket`; pass the acquirer's
`acquireTicket` to the reader. Global token consumption plus local one-use
challenge consumption prevents reuse at another holder. Blind permits remain
transferable bearer objects: the bound is per-member issuance, not a guarantee
against members colluding or giving their tickets away. Timing correlation
between issuance and redemption remains possible.

## Required tunables and evidence

No product amounts or durations are selected by the module. Supply all of:

| Limit | Purpose |
| --- | --- |
| `maxProfileBytes`, `maxEnvelopeBytes`, `maxFrameBytes` | Bound plaintext, complete cached record and P2P frames |
| `maxProofBytes` | Bound each eligibility/contact-policy proof |
| `maxProfileSeconds` | Maximum signed ciphertext lifetime |
| `maxChallengeSeconds` | Fresh challenge/transport deadline; at most 300 seconds |
| `maxKeySeconds` | Maximum grant/delegation/holder-key-offer lifetime |
| `maxReplayEntries`, `maxConcurrentProofs` | Bound challenge memory and verification work |
| `maxRequestsPerWindow`, `requestWindowSeconds` | Bound overall local key-service work |

The resource issuer separately requires its per-member/per-epoch issuance
quota, total member bound and signed-request lifetime. Member allocation and
redemption state are resource controls, not a profile access log. Operators
must not log request bodies, per-reader profile targets, tickets or challenge
digests. Safe metrics include aggregate accepted/rejected operations,
verification latency, queue depth and capacity pressure without identifiers.
Profile-cache hit timing and sizes remain observable at the operator; this
implementation does not claim traffic-analysis resistance.

`test/profile-client.test.js` runs the portable contract from
`browser/profiles/contract.mjs`. `runProfileClientContract()` runs the same
contract in actual browser WebCrypto. It exercises encryption, authority,
mutation/replay rejection, rotation during proof work, failed storage, lost
replies, holder seeding, ticket stamps and canonical Rust wire bytes. Its
eligibility/contact-policy and some ticket fixtures are explicitly synthetic;
they do not prove cvld private-attribute/block interoperability or actual Tor
transport. Native ticket tests separately exercise RFC9474 issuance and
global redemption. Test sources alone are not a claim of a passing CI run.
