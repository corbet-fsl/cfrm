# cfrm — Forum

Authenticated, ephemeral forum API. All frontends use the member door; Forum exposes no admin or root operation.

## Scope

Compose Assurance, Gather and Volatile through one versioned Rust action registry, projected into HTTP/OpenAPI, TypeScript and MCP. Require current credential, device possession, whole-profile Guard validation and local public-record verification. Hold no permanent member state, profile keys, accounting ledger or request log. Every success and refusal must be noncacheable; exact configured host and origin checks precede bounded body parsing. Link owns both connection classes: authenticated device sessions for presence/search and unlinkable anonymous room-pass sessions for Assembly. Room requests carry no presence credentials. The door owns no evaluator, quota algorithm, room protocol, compression or storage beyond its single Volatile handle.

## Current state

The registry, generated TypeScript/OpenAPI/MCP and bounded HTTP/client refusal transport are implemented; current scope changes are undergoing CI. **Every action currently returns AuthorityUnavailable.** There is no accepting admission stub and no deployed forum. Current child capability integration, proof-bound sessions, policy-supplied minimum client version, authenticated MCP hosting and live discovery remain incomplete. The MCP projection and raw-argument dispatcher do not expose an unauthenticated service.

The former identity, accounting and SQL service implementation has been removed from the Rust door. Historical experiments are research only and are not a service or acceptance evidence. Existing bounded-body, concurrency, timeout and no-logging HTTP mechanisms informed the new adapter; current authorization belongs to the owning libraries.

## Maintained dependencies

Serde preserves exact typed wire bodies; Schemars derives JSON Schema; ts-rs derives TypeScript from the same Rust types; Axum owns HTTP routing and body limits; URL validates configured origins. The maintained [Rust MCP SDK](https://github.com/modelcontextprotocol/rust-sdk) checks the generated catalog and refusal shape in tests; it is not an exposed unauthenticated listener. No cryptographic primitive or policy evaluator is implemented here. The registry is the source for all routes and authorization metadata.

See [the contract](docs/CONTRACT.md) for the open acceptance gates.
