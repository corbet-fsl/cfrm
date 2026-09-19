# Product service integration

cfrm supplies Rust services and portable browser modules. An application chooses
its hostnames, trusted community configuration, storage locations and deployment.
A Svelte application can call these modules from browser code while rendering
ordinary application state. Initialize browser keys and Wasm after hydration.

| Component | Entry point | Embedding supplies |
|---|---|---|
| Discovery HTTP | `discovery_api::router`, POST `/v1/discovery` | Trusted clock, explicit limits, service instance and API Host allowlist |
| Durable discovery cache | `ValkeyDiscoveryStore`, `SqliteDiscoveryControl` | TLS Valkey configuration and one shared durable control database |
| Browser discovery and profiles | Package export `cfrm/profiles` | Authenticated device, encrypted wallet, bounded request transport, lease sequence persistence and private holder transport |
| Key resource tickets | `key_access::KeyAccessIssuer`, `KeyAccessRedeemer`; browser ticket helpers | Dedicated epoch/signing keys, shared durable quota and spent-token databases, public epoch distribution |
| Account service | `accounting_service::AccountService` | HTTP or private transport adapter, durable ledger, trusted clock and pinned real verifier |
| Account client/prover | Package export `cfrm/accounting` | Public circuit manifest pin, same-origin Wasm/setup assets, authenticated device, private account witness and atomic successor persistence |

See [discovery](discovery.md), [profiles](profile-cache.md),
[key tickets](key-access-tickets.md) and the [accounting runtime](../runtime/accounting/README.md)
for exact schemas, limits and recovery contracts. AccountService's member JSON
surface exposes apply/status. Checkpoint publication and live policy tuning are
trusted local administration methods; a host must authorize any route exposing
them. The accounting service is an embeddable adapter, not an installed server.

## Community and transport boundaries

Resolve an accepted hostname to a preconfigured community and its issuer/policy
trust. The discovery API's optional exact Host allowlist validates this routing
boundary. It does not consume forwarded-host headers. Member requests also carry
signed community and policy bindings, independently verified by the service.
Administrative authorization belongs to authenticated credentials and explicit
scopes. Provisioning names and reserved-name policy belong to the application.

An MCP adapter can use the same public operation schemas and API authorization.
Keep browser private keys, decrypted profiles and private account witnesses out
of API and MCP servers. Key access uses the existing private member transport;
cfrm does not deploy a message relay. Additional private profile-policy proofs
require a concrete verifier adapter as described in the profile documentation.

Serve the proof worker and its checksum-pinned artifacts on an origin with the
cross-origin isolation headers required by the accounting runtime. All remote
imports, browser asset paths and request destinations are embedding choices.
Keep proving off the UI thread and present its asynchronous lifecycle explicitly.
Desktop proof measurements do not establish mobile memory or latency feasibility.

## Storage and recovery

Valkey may evict profile ciphertext and indexes. Durable controls preserve
resource quotas, replay protection and the latest accepted publication identity.
A missing cache entry affects availability until the owner repairs it. Replicas
must use the same control database; unrelated SQLite copies do not form a shared
authority. The key-ticket spent store and account ledger have the same shared
authority requirement. These are storage contracts, not a distributed database
deployment recipe.

Discovery/profile operations and key-ticket budgets never debit reciprocity
credit. The durable discovery controls contain bounded current metadata, with no
profile plaintext, decryption keys or read-target history. Infrastructure logging
and backups must preserve those application boundaries.

Persist pending browser writes before transport, preserve their exact retry
identity, and install confirmed private successors atomically. The application
owns its encrypted wallet's durability, device synchronization and recovery.
The profile module's storage contract and accounting ledger's expected-successor
contract describe where these transactions are required.

## Validation

The product-services CI runs native behavior and concurrency tests, browser-feature
Wasm compilation, JavaScript contracts, actual Chromium WebCrypto and an isolated
Valkey process. Native interoperability tests independently accept browser-signed
discovery records and verify native key-ticket transcripts in JavaScript.

The separate private-accounting CI generates actual browser account/peer proofs,
applies them through the Rust ledger, and checks the reusable browser prover and
shipped Node verifier against the pinned artifact bundle. Cryptographic browser
proofs, storage tests using synthetic verifier verdicts, and deployment validation
are separate evidence scopes. This page describes the validation machinery;
individual CI receipts establish which source revision has passed.

At `ef5c675d7ab2c1ca71dcdfa2cd071391168fc1f2`, Crow9/67 passed 101 native
tests, browser-feature Wasm checking, 75 JavaScript tests, 20 actual Chromium
profile contract groups and five accounting-runtime tests. It used Rust1.97.1,
Node24.19.0, Chromium152.0.7977.64 and an isolated Valkey9.1.2 process. The native
checks include TLS trust/hostname rejection, cache eviction and durable recovery,
concurrent updates, actual blind tickets and cross-runtime signature validation.
The profile browser contract uses explicitly synthetic eligibility and private
transport adapters; it does not establish cvld proof or live Tor integration.
Artifact manifest SHA256:
`c879a070152934b839825fe6c6cca0f13d86f526e29b9c7cd17302b0c70b764a`.
