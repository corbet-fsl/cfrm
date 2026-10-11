# cfrm — Forum

Authenticated, ephemeral forum API. All frontends use the member door; Forum exposes no admin or root operation.

## Scope

Compose Assurance, Gather and Volatile through one versioned Rust action registry, projected into HTTP/OpenAPI, TypeScript and MCP. Require current credential, device possession, whole-profile Guard validation. Hold no permanent member state, profile keys, accounting ledger or request log. Every success and refusal must be noncacheable; exact configured host and origin checks precede bounded body parsing. Link owns both connection classes: authenticated device sessions for presence/search and unlinkable anonymous room-pass sessions for Assembly. Room requests carry no presence credentials. The door owns no evaluator, quota algorithm, room protocol, compression or storage beyond its single Volatile handle.

## Current state

The candidate source composes real Assurance/Gather/Volatile admission, request
possession, committed Search and ciphertext through a supervised controller.
The Rust registry now includes typed replies, and concrete native/browser HTTPS
transports have bounded bodies, exact origins and no ambient credentials or retries.
These successors are **uncompiled and unreleased** while owner dependencies qualify.
The legacy router without a controller refuses. Bounded Watch and original
Assembly admission passes are composed in source. Mandatory G2 frontier/ZK
currentness and public punishment, complete client-version enforcement, member
MLS and authenticated MCP hosting remain unfinished. No deployed Forum or
complete higher-owner qualification is claimed.

The former identity, accounting and SQL service implementation has been removed from the Rust door. The historical JavaScript experiments, studies and prototype documents were deleted on 2026-10-11 (they described durable member state, an operator-visible accounting ledger and administration routes that the Forum door does not have; Git history keeps them). Existing bounded-body, concurrency, timeout and no-logging HTTP mechanisms informed the new adapter; current authorization belongs to the owning libraries.

## Maintained dependencies

Serde preserves exact typed wire bodies; Schemars derives JSON Schema; ts-rs derives TypeScript from the same Rust types; Axum owns HTTP routing and body limits; URL validates configured origins. The maintained [Rust MCP SDK](https://github.com/modelcontextprotocol/rust-sdk) checks the generated catalog and refusal shape in tests; it is not an exposed unauthenticated listener. No cryptographic primitive or policy evaluator is implemented here. The registry is the source for all routes and authorization metadata.

See [the contract](docs/CONTRACT.md) for the open acceptance gates.

## Native service candidate

The `serve` feature builds the native `cfrm` executable:
`cfrm serve --config /run/forum/config.json`. `src/serve.rs::Configuration` is the
canonical strict JSON configuration. It has no deployment defaults. Supply the
independently trusted community key ring, exact feed origin/revision floors,
common rollout incarnation, exact HTTP hosts/origins, listener address, storage
and all capacity/timing limits. The configured maximum lease is a storage ceiling;
actual heartbeat/lease, client-version floor and common-epoch room quota come from
current signed Rulebook settings. The storage TTL must also accommodate nonce
retention through the full current authority interval.

One Volatile handle is shared by Assembly, Switchboard, Lookup and controller
maintenance. Valkey uses ThrottleStore over that same backend; Memory uses the
original single-process throttle. Envoy's actual HTTPS client fetches only the
community trust feed and changes, with no member credentials. Initial requests
refuse until that original signed feed is current. A successful `settings` action
reports original signed settings plus their bounded public projection; cmsg must
verify them through its own retained Charter and use Rulebook's maintained version
comparison before member work. No separate readiness boolean grants authority.

SIGTERM/interrupt stops the transport futures and drains the bounded controller
queue until the explicit shutdown limit; timeout/panic closes every storage clone.
Every restart requires the coordinated fresh incarnation described in the runtime
contract. The service emits only value-free failure/persistence diagnostics, with
no access or body logging. There is no automatic storage fallback or write retry.

The built-in contact detector returns `Unavailable`. Schemas requiring contact
checking for public text therefore refuse those publications until a real detector
is integrated; unrestricted fields retain the original schema validation. The room issuer and anonymous Assembly routes are now composed in source;
member MLS handover, G2 epoch authority and full browser/coverage
qualification remain unfinished. This candidate has not been compiled, packaged or deployed.

The single issuer process uses required `room_epoch` configuration containing
`epoch`, `valid_from_ms` and exclusive `valid_until_ms`. After original current
admission and signed Rulebook quota verification, it activates one fresh common
issuer in the existing Volatile scope. `room_epoch` returns that same descriptor
and incarnation; `room_issue` accepts only an operation ID and original blinded
request under a new device-possession transcript. The original issuer owns quota
CAS and exact-request retry receipts. A quota change, expired epoch, or lost anchor
refuses use; it never resets the existing key or reactivates a retained allowance.
Anonymous connect/renew/disconnect/read/order/relay/resume routes check the original
pass and exact action through Assembly, with no member lookup. Room handover still
requires the original member MLS authority and remains unavailable here.

The explicit integration TEST deployment policy selected on 2026-10-02 is a
24-hour common epoch, quota 16, heartbeat 3000ms and lease 10000ms. These values
are configuration inputs, not library defaults. Storage TTL must accommodate the
entire epoch. Process loss requires a fresh shared storage incarnation and common
issuer key before traffic, replacing descriptor and verifier together; only one
process may serve the incarnation. Portable DTO and actual native blind-issuance
round-trip vectors are written but unexecuted.

Bounded Lookup polling and Board/Link pass custody are now composed in source.
The newest MVP requirement restores public-record currentness and punishment;
original G2 proof/Charter integration remains mandatory before admission release.
Hosting origin is explicit configuration and currently under renewed review;
this source performs no vault-origin deployment or origin rewriting.
