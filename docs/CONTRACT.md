# Forum contract

Forum is a server door over Assurance, Gather and Volatile. It is an authenticated-member interface. Frontends call cmsg; Board's Link alone calls Forum. Admin/root changes travel through Foyer to cvld, never through Forum.

## Registry and transport

One Rust action declaration generates request variants, route names, authority requirements, JSON Schema/OpenAPI and TypeScript. Call contains version=1 plus a tagged request. HTTP is POST /v1/<action>; path and tagged action must agree. Unknown versions, actions, fields and duplicate fields refuse. Client transport uses those same action names and typed bodies.

Host and Origin must each occur exactly once and match explicit configured canonical values. Forwarded headers never grant authority. Body size, body receipt duration and concurrent parsing are bounded. Every returned response, including routing/method/parser failures, has Cache-Control: no-store. No request logger is installed. Credential-gated challenges precede device possession; a reusable bundle or credential is not a session proof.

## Current implementation boundary

The transport currently returns only typed AuthorityUnavailable. This is an explicit fail-closed boundary, not working admission. No server success response exists yet; it must be added from child-owned capabilities to the same registry. Session challenge/nonce/deadline/body binding, fresh device possession, shared Throttle before proof work, current Assurance, verified public record, cpfl publication verification and anonymous Assembly permits remain required integration work. No alternative verifier is supplied.

Switchboard owns the authoritative attendance generation. Lookup owns derived indexes and opaque expiring cursor positions; each page, delta and ciphertext read must recheck both current entries, trust and reciprocal Guard rules. Only committed entries may become candidates. Assembly owns all room state, anonymous permit checking and order recovery. Gather routes these children; Forum stores no domain records. Storage is one service-owned cvtl handle per service, with fresh incarnation on restart.

## Acceptance still open

Real trust/credential/profile/record/device round trips; replay, revocation and stale-generation denial through every generated surface; live typed pages/deltas and ciphertext refusal races; Memory/Valkey parity; no retained member state across restart; real anonymous room protocol; full line and branch coverage; security review. Refusal and transport tests establish none of the missing admission successes.
