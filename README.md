# cfrm — Forum

Authenticated, ephemeral forum API. All frontends use the member door; Forum exposes no admin or root operation.

## Scope

Compose Assurance, Gather and Volatile through one versioned Rust action registry. Require current credential, device possession, whole-profile Guard validation and local public-record verification. Hold no permanent member state, profile keys, accounting ledger or request log. Every success and refusal must be noncacheable; exact configured host and origin checks precede bounded body parsing.

## Current state

The registry, generated TypeScript/OpenAPI and bounded HTTP/client transport are being implemented. **Every action currently returns AuthorityUnavailable.** There is no accepting admission stub and no deployed forum. Current child capability integration, proof-bound sessions and live discovery remain incomplete.

The former identity, accounting and SQL service implementation has been removed from the Rust door. Historical experiments are research only and are not a service or acceptance evidence. Existing bounded-body, concurrency, timeout and no-logging HTTP mechanisms informed the new adapter; current authorization belongs to the owning libraries.

## Maintained dependencies

Serde preserves exact typed wire bodies; Schemars derives JSON Schema; ts-rs derives TypeScript from the same Rust types; Axum owns HTTP routing and body limits; URL validates configured origins. No cryptographic primitive or policy evaluator is implemented here. The registry is the source for all routes and authorization metadata.

See [the contract](docs/CONTRACT.md) for the open acceptance gates.
