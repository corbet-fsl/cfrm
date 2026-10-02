# cfrm — Forum

Authenticated, ephemeral forum API. All frontends use the member door; Forum exposes no admin or root operation.

## Scope

### Purpose

cfrm is the ephemeral meeting place of admitted community members, exposing an authenticated-member API over Assurance, Gather and Volatile that leaves no permanent trace.

### Owns

- The single versioned action definition of the forum API, projected into HTTP/OpenAPI and a generated TypeScript client.
- Composition of the Assurance, Gather and Volatile facades, with exactly one service-owned storage connection through cvtl.
- Refusal of every unauthenticated request.
- Publication of the minimum client version below which clients refuse to run.
- Cheap rejection and per-community quotas before expensive work, including cutting off a community with excessive issues without affecting other communities.
- Serverless operation against managed expiring storage, deployable independently of cvld.

### Never

- Keeps a permanent trace: no durable store, backups, request or body logs, or IP and login-time records.
- Holds credential material or SQL storage handles.
- Queries cvld about a member at runtime or performs cvld work.
- Accepts or forwards admin or root edits.
- Serves any client other than the member door.
- Compresses data.
- Sees private plaintext, profile keys, or message content.
- Runs an onion service or depends on Tor on the server side.
- Adds paid tiers or automatic billing.
- Holds domain logic in the door itself; the door only wires facades.
- Grows a separate protocol or statement library.

### States

Service lifecycle only: Starting to Ready, or Refused/Unavailable. All domain state is derived from the facades, and a restart forgets every member.

### Test obligations

- Unauthenticated, foreign-community, and replayed requests cannot read forum state or invoke domain work, and cheap quota checks run before verification.
- Authentication requires a valid community credential and proven device possession before granting anything, without revealing member data.
- Member traffic never causes a member query to cvld; only trust feed updates are fetched.
- A restart forgets all member state, and the Memory and disposable Valkey backends pass the same forum scenario.
- Generated HTTP, OpenAPI, and TypeScript stay in parity, with non-cacheable successes and errors and exact origin and host checks.
- Retained server state after a scenario is limited to the approved public projection, ciphertext, and expiring derived state, with no IPs, history, private plaintext, or keys.
- Request floods are refused before storage or proof work, and one community at quota does not make another community unusable.

## Current state

The registry, generated TypeScript/OpenAPI/MCP and bounded HTTP/client refusal transport are implemented. **Every action currently returns AuthorityUnavailable.** There is no accepting admission stub and no deployed forum. Current child capability integration, proof-bound sessions, policy-supplied minimum client version, authenticated MCP hosting and live discovery remain incomplete. The MCP projection and raw-argument dispatcher do not expose an unauthenticated service.

The former identity, accounting and SQL service implementation has been removed from the Rust door. Historical experiments are research only and are not a service or acceptance evidence. Existing bounded-body, concurrency, timeout and no-logging HTTP mechanisms informed the new adapter; current authorization belongs to the owning libraries.

## Maintained dependencies

Serde preserves exact typed wire bodies; Schemars derives JSON Schema; ts-rs derives TypeScript from the same Rust types; Axum owns HTTP routing and body limits; URL validates configured origins. The maintained [Rust MCP SDK](https://github.com/modelcontextprotocol/rust-sdk) checks the generated catalog and refusal shape in tests; it is not an exposed unauthenticated listener. No cryptographic primitive or policy evaluator is implemented here. The registry is the source for all routes and authorization metadata.

See [the contract](docs/CONTRACT.md) for the open acceptance gates.
