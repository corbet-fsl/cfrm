# Encrypted profile discovery

cfrm supplies an authenticated discovery service, a bounded HTTP adapter, an
in-memory reference store and a pooled Valkey adapter. Profiles are encrypted on
member devices. The service verifies public authority, signatures, ciphertext
digests and a configured registry of public numeric fields. It has no decryption
key, plaintext-profile endpoint, message queue, introduction ledger call or
reader-history interface.

This is implementation documentation. A deployed service, load target, Tor
transport and privacy certification require separate evidence.

## Public records and signatures

`CachedProfile` contains exactly `admission`, `authorization` and `envelope`.
The first two objects are the existing issuer admission certificate and
member-root-signed device authorization. `ProfileEnvelope` contains exactly:

```text
{version:1, communityId, memberId, chatPublicKey, profileEpoch, sequence,
 issuedAt, expiresAt, nonce, profileDigest, discriminators, ciphertext, signature}
```

IDs, keys, `profileEpoch` and digests are canonical unpadded base64url32. A fresh
client-generated `profileEpoch` identifies the profile encryption key; the key
never enters this record or a discovery request. `nonce` is base64url12.
`ciphertext` is AES-256-GCM ciphertext including its 16-byte authentication tag.
`profileDigest` is SHA-256 of those ciphertext bytes, not a plaintext digest.
`signature` is base64url64 Ed25519 under the certified owner device key.
Sequences and Unix seconds are positive integers within JavaScript's safe range.

The signed bytes are compact UTF-8 JSON in this exact array order:

```text
["cfrm.cached-profile.v1",communityId,memberId,chatPublicKey,profileEpoch,
 sequence,issuedAt,expiresAt,nonce,profileDigest,sortedDiscriminatorPairs]
```

`discriminators` is an object with ASCII field names and unsigned 32-bit integer
values. The signed representation is `[[name,value],...]`, sorted by ASCII name.
Names are 1–32 bytes, start with a letter, and contain only letters, digits and
underscore. The trusted server registry assigns each field either an inclusive
integer range or a sorted, unique integer enumeration. Unknown names and values
outside those domains are rejected. The registry is deployment configuration;
there are no implicit demographic fields or product defaults.
Domain validation and an owner signature establish permitted encoding and
ownership, not the truth of a claimed attribute. Issuer-backed attribute proofs
remain a separate eligibility integration.

AES-GCM additional authenticated data uses the same ordered metadata, a separate
domain and no ciphertext digest:

```text
["cfrm.cached-profile.aad.v1",communityId,memberId,chatPublicKey,profileEpoch,
 sequence,issuedAt,expiresAt,nonce,sortedDiscriminatorPairs]
```

This omission avoids a circular dependency during encryption. The owner
signature separately binds the actual ciphertext digest and all public filters.
A cached record cannot substitute the old filters beside a different profile.
The reusable signature replaces the earlier experiment's reader-challenge-bound
response signature for this cache path.

## Authenticated operations

`POST /v1/discovery` accepts `Content-Type: application/json`. A request contains
exactly `version:1`, `admission`, `authorization`, `sessionId`, `requestId`,
`issuedAt`, `expiresAt`, `operation` and `signature`. Both IDs are random
base64url32 values. The outer device signature is over:

```text
["cfrm.discovery-request.v1",communityId,policyDigest,memberId,chatPublicKey,
 sessionId,requestId,issuedAt,expiresAt,operation]
```

The operation is a JSON object with recursively lexicographically sorted keys,
including any nested admission, authorization and envelope objects. Arrays retain
their declared order. There is no whitespace. Rust's
`request_signing_bytes` is the authoritative encoder.

| Operation | Fields beyond `kind` | Result |
|---|---|---|
| `publish` | `publication`, `lease` | `{"kind":"updated"}` |
| `heartbeat` | `lease` | `{"kind":"updated"}` |
| `disconnect` | `leaseId`, `sequence` | `{"kind":"updated"}` |
| `query` | `filters`, `limit`, `after` | `{"kind":"page","entries":[...],"nextCursor":...}` |
| `fetch` | `memberId` | `{"kind":"profile","publication":...}` |

A lease has `leaseId`, `sequence`, `expiresAt`; its ID must equal the outer
`sessionId`. Publication identity and both certificates must equal the request
identity and certificates. The server verifies admission against independently
configured community, policy and issuer trust; it then verifies the root-owned
device authorization and request signature. Copying an admission certificate
does not confer request-signing authority.

Queries use exact matches on configured discriminator values. `after` is null or
a canonical member ID. Query summaries are index hints; the client verifies the
fetched original certificates and envelope before displaying decrypted content.
Pagination can return an empty page with a non-null cursor when the bounded scan
found no matches. Callers must advance that cursor rather than treating the empty
page as proof that no more results exist.
The response byte limit also ends a page. Its cursor stops before the first
matching entry that would exceed that limit, so a following page cannot skip the
unreturned result. A configuration too small for one summary returns an explicit
capacity error rather than a nonadvancing continuation.

Reads and key acquisition are not introductions and do not debit the reciprocity
ledger. The HTTP path has no dependency on an accounting provider. Eligibility
alone does not give the service a profile decryption key; member-to-member key
authorization is a separate client protocol.

## Lease and storage semantics

The cache has one ciphertext slot per community/member and a member-wide profile
revision floor. Device leases are independently keyed by authenticated device
key. Disconnecting one device does not erase another device's live lease. The
visible lifetime is bounded by both the profile expiry and the final live device
lease. A heartbeat contains no profile bytes and cannot resurrect evicted or
expired ciphertext. An owner must republish from its locally retained profile.

The store atomically consumes a replay marker, applies member-wide quota and
sequence checks, and changes the cache entry. Exact signed write retries return
the existing success without reapplying the change. Read retries are rejected;
the reader creates a fresh request ID. Stored replay markers contain opaque
digests and expiries, not a read target, filter or response. Counts are per
member, shared across that member's devices and sessions.

After an outer request expires, the owner may submit a fresh signed request for
the identical current publication, with a strictly newer device lease sequence.
This repairs an evicted ciphertext slot without charging another publication or
discriminator update. The full stored publication hash must match; changed
bytes, signatures, filters or profile expiry are a different publication and
remain subject to revision and quota checks. Repair never extends the signed
profile expiry. Expired profile authority must be renewed through publication.

`MemoryDiscoveryStore` is a reference implementation and a single-process
embedding. It loses ephemeral state on restart. Production Valkey use requires
`SqliteDiscoveryControl`: all replicas share the same durable control database.
Per-member quotas, opaque replay markers, profile revision/hash and bounded
device lease guards survive ciphertext eviction. The database contains no
ciphertext, plaintext, key, query filters or fetched-profile target. It is
separate from the introduction ledger.

The authority commits the accepted intent before cache I/O. A second transaction
checks its revision and holds a writer fence during the bounded cache mutation.
A superseded intent cannot overwrite a newer publication; scope-wide revisions
prevent a delayed intent from matching an expired and recreated member row.
An exact signed retry can finish a cache write after a crash without a second
quota debit. Fetches compare cache content to current durable authority and fail
closed when the cache and authority disagree. The durable scope pins both issuer
trust and the complete limits configuration; uncoordinated configuration changes
are rejected. Changing that policy requires a separate explicit operation.

`ValkeyDiscoveryStore` uses bounded pooled connections and TLS for
remote connections. Its only plaintext transport exception is an explicitly
enabled numeric loopback endpoint for isolated tests. Cache eviction does not
reset anti-abuse guards. Loss or rollback of the durable database requires
operator recovery; substituting an empty or per-replica database is not a safe
recovery procedure. The control constructor requires an explicit SQLite busy
timeout. The implementation supplies this existing SQLite backend without
selecting a new managed database vendor.

## Explicit operational configuration

Every `DiscoveryLimits` field is required. `validate()` rejects zero capacities
and windows, malformed registry definitions, unsupported sizes and a page limit
greater than the scan bound. The limits are trusted server configuration; request
bodies cannot replace them.

| Settings | Purpose |
|---|---|
| `maxRequestBytes`, `maxRecordBytes`, `maxResponseBytes` | Bound decoded request/record/response JSON storage and transfer |
| `maxCiphertextBytes`, `maxDiscriminatorBytes` | Bound opaque payload and canonical public fields |
| `maxProfileTtlSeconds`, `maxLeaseSeconds`, `maxRequestSeconds` | Bound profile retention, device visibility and signed-request lifetime |
| `maxMembers`, `maxDevicesPerMember`, `maxReplayEntries` | Bound ephemeral control and replay state |
| `maxResults`, `maxScan` | Bound query results and work even with selective filters |
| `publishLimit`, `publishWindowSeconds` | Bound member-wide blob replacement |
| `discriminatorLimit`, `discriminatorWindowSeconds` | Independently bound changes to public fields |
| `readLimit`, `readWindowSeconds` | Bound authenticated query/fetch traffic |
| `registry` | Define accepted public fields and their closed value domains |

HTTP configuration additionally requires `maxConcurrentRequests` and
`bodyTimeoutMillis`. The handler acquires capacity before buffering a body,
limits incoming bytes, reads the trusted clock after receiving the body, and
runs blocking storage work off the async executor. Responses use `Cache-Control:
no-store`; failures have fixed public messages. No access logger is installed.
Hosts must also avoid request-body, URL-target or per-reader logs in their proxy
and monitoring configuration.

`allowedHosts` is optional trusted HTTP routing configuration. When present it
must be nonempty and contains exact ASCII authorities, optionally including
ports. The handler normalizes ASCII case, rejects ambiguous or repeated `Host`
headers and ignores `X-Forwarded-Host`. A hostname grants no role or key access.
The signed community must still match the server's independently configured
admission trust. Browser frontend hostnames and privileged administration roles
are outside this generic library.

Suggested aggregate metrics are operation count, fixed error-category count,
latency, pool saturation, live record count and bytes. Do not attach member IDs,
profile digests, filters or reader/target pairs to those metrics. The operator can
still observe which ciphertext bytes were requested and their timing; absence
of retained per-reader telemetry is not absence of runtime timing exposure.

## Verification

`tests/discovery.rs` includes actual issuer/root/device signatures and covers
forgery, signed-body substitution, cross-community requests, unknown fields,
public-field domains, ciphertext sizes and digest mismatches, time bounds,
multi-device leases, stale sessions, member-wide quotas, write retries, read
replay and concurrent profile revisions. The HTTP feature adds actual router
requests for signature validation, body limits and Host enforcement. Remote CI
results, Valkey parity and browser interoperability are recorded by the caller's
validation workflow; merely compiling these modules is not deployment evidence.
