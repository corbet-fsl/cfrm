# Forum contract

Forum is a server door over Assurance, Gather and Volatile. Presence and search form an authenticated-member interface; room operations use unlinkable anonymous sessions and blind room passes. Frontends call cmsg; Board's Link alone calls Forum. Admin/root changes travel through Foyer to cvld, never through Forum.

## Registry and transport

One Rust action declaration generates request variants, route names, authority requirements, JSON Schema/OpenAPI, TypeScript and MCP. Call contains version=1 plus a tagged request. HTTP is POST /v1/<action>; path and tagged action must agree. Unknown versions, actions, fields and duplicate fields refuse. Client transport uses those same action names and typed bodies.

Host and Origin must each occur exactly once and match explicit configured canonical values. Forwarded headers never grant authority. Body size, body receipt duration and concurrent parsing are bounded. Every returned response, including routing/method/parser failures, has Cache-Control: no-store. No request logger is installed. Credential-gated challenges precede device possession; a reusable bundle or credential is not a session proof.

Configured hosts are parsed with a fixed HTTPS scheme, for which URL rejects empty hosts before returning success. A redundant post-parse absent-host branch was removed; empty-host regression vectors remain. This follows [URL's special-scheme host parser](https://github.com/servo/rust-url/blob/v2.5.8/url/src/parser.rs#L992), not a coverage exclusion. All reachable line and branch thresholds remain 100%.

## Current implementation boundary

The candidate `runtime::Service` composes one Volatile handle, current Assurance,
and actual Gather children. `spawn` returns a concrete bounded Handle and worker;
queued mutations complete after caller cancellation, and worker drop/panic fences
the shared store. `router_with` consumes that Handle, never an accepting callback.
The unconfigured constructor exposes Settings and original credential challenges;
it refuses every governed admission/attendance action. The native host requires
explicit current Rulebook period key/value, issuer action, authenticated public
artifact pin and bounded verifier execution. Its consuming `with_accounting`
constructor installs the concrete Gather/Balance owner once. Fresh entry decodes
an original record Presentation bound to the actual pending Challenge payload;
replacement decodes the original public Record and proof. Device possession signs
the unchanged complete request. No caller supplies a verifier or admission verdict.
Gather retains the exact verified public evidence only in expiring attendance,
rechecks cached records before disclosure, and excludes invalid candidates before
cursor observations. The serial actor retains current Charter authority through
native verification and each final storage cut. Room actions remain explicitly
unavailable until their common-epoch accounting join is complete.

The native executable uses two Tokio workers, with one serial Forum actor and one
native proof operation at a time. `shutdown_ms` is the graceful command-drain
budget. At its expiry the host fences storage, permanently cancels the native
owner, aborts the actor and joins cleanup. The original process owner kills and
reaps its subprocess before joining pipe threads. This prevents waiting for the
full proof timeout; it is not a hard operating-system wall-clock guarantee.
Source review is complete; genuine native/transport and coverage qualification
remain pending and must use the actual retained four-circuit fixture.
The unsigned request transcript includes the canonical versioned action and every
input except its signature. Ciphertext's requested Profile revision is eight-byte
big-endian; attendance storage revisions are exact sixteen-byte tokens.

The legacy router and static MCP refusal dispatcher remain unavailable without
the actual controller. Watch now forwards bounded Lookup window deltas. Member MLS handover,
the client version floor, generated artifacts and complete
native/browser/coverage qualification remain open. No deployed acceptance is claimed.

Switchboard owns the authoritative attendance generation. Lookup owns derived indexes and opaque expiring cursor positions; each page, delta and ciphertext read must recheck both current entries, trust and reciprocal Guard rules. Only committed entries may become candidates. Assembly owns all room state, anonymous permit checking and order recovery. Gather routes these children; Forum stores no domain records. Storage is one configured cvtl scope per community rollout. The reviewed MVP
runs ONE issuer process per incarnation. Process loss or Valkey restart rotates
the incarnation and common issuer key before admission can resume; no serverless
cold-start key recreation is permitted under the old scope. The door
must supervise mutation completion and explicit reopen/reconciliation independently
of request cancellation; see [the Valkey deployment contract](https://github.com/corbet-foss/cvlk/blob/main/docs/CONTRACT.md#deployment-incarnation-and-request-supervision).
No deployed incarnation controller or accepting integration is claimed yet.

## Acceptance still open

Complete admission including original accounting currentness; replay, revocation
and stale-generation denial through every generated surface; live typed
pages/deltas and ciphertext refusal races; Memory/Valkey parity; no retained
member state across restart; real anonymous room protocol qualification; full
line and branch coverage; security review. Real partial
trust/credential/profile/device, attendance, Lookup and
anonymous room scenarios exercise the owning libraries directly. They do not
establish complete Forum admission. Runtime refusal tests retain the actual
controller and HTTP boundary and check that refused requests create no attendance.

## Anonymous rooms and MCP

The accounting composition for `room_epoch` and `room_issue` uses the actual
current device session, native record proof and final presence revision, with
the original signed quota and common configured epoch. Its entire lifetime fits
the authenticated record and policy bounds. Issuance requires member authority
through that common expiry. The latter carries only operation and original BlindRequest,
never a room/hash/tag. All anonymous command inputs contain only the room owner's
opaque pass and command. The registry marks those AnonymousRoomPass; they never include authenticated presence session
credentials. Link owns both independent session classes. Assembly alone verifies
permits; this projection does not define a blind-pass protocol or link rooms to
members. Gather freezes the original descriptor, economic policy digest, quota
and common permit lifetime. A metadata refresh cannot extend that lifetime;
changing descriptor, policy or quota fences the original issuer. Anonymous use
continues after presence departure but requires the current common accounting
epoch and original permit, with an exclusive final deadline check. Losing the
issuer anchor never creates a replacement in the same incarnation. MLS history
handover remains unavailable until its original member capability is joined.
These paths require actual native and transport qualification; source review
alone does not establish runtime acceptance.

`mcp_tools` projects the same action-bound Call schema used by HTTP. Its tools
accept the full versioned Call as arguments. `execute_tool` checks the tool name
against that Call, applies the same strict byte decoder and invokes the same
owner refusal. An MCP host must retain the original tools/call arguments; a JSON
map that already discarded duplicate fields is not an acceptable input. The
[maintained rmcp model](https://docs.rs/rmcp/latest/rmcp/model/index.html) validates the generated catalog and typed error
shape in CI, alongside browser and AJV schema vectors. JSON-RPC negotiation and
transport remain SDK responsibilities, never a new protocol engine here.

This is a projection and dispatch port, not an authenticated MCP listener.
Production hosting, session custody and the policy-supplied client version floor
remain blocked on the same verified owner capabilities as HTTP admission. No
request may skip those checks merely because it arrived through MCP.

G1 credential/Guard checks belong to `cgrd::check_published`, referenced through
Charter and Assurance. Envoy (`cnvy`) fetches/follows feeds; it does not verify
authority. Current credential-bound device authority and per-request possession must be
composed with those owner checks. The05:45 binding MVP correction restores G2
frontier/ZK currentness and public punishment as requirements. Their original
owner capabilities must be integrated before complete admission is claimed; no
second verifier, optional check or accepting substitute is introduced here.

The first publishing root for each community comes only from deployment
configuration. Feed responses cannot provide their own initial authority. Charter
verifies signed ring continuity and nondecreasing revision floors; Envoy only
fetches. These owner ports must be integrated before the door can leave its
current AuthorityUnavailable state.

## Concrete client transport candidate

HttpTransport and BrowserTransport use exact configured HTTPS origins, bounded
request/streamed response bytes and a whole-response timeout. No cookies, redirect,
referrer or automatic effect retry is used. Browser Fetch also validates its real
application Origin and aborts the request/body reader on cancellation. Unknown
outcomes require reconciliation. Cross-origin OPTIONS allows only POST with
Content-Type for one exact configured origin and never enables shared credentials.
These adapters are source candidates; actual HTTPS/browser round trips are still
required. Axum in-process scenario tests are not presented as browser evidence.

SearchOutput carries separate pagination `cursor` and bounded-window `watch`.
WatchInput uses only the latter under a new current-device request. WatchOutput
contains upserts, previously visible removed IDs, current pagination and a new
watch cursor. Original Lookup owns every context, currentness and reciprocal
check; the transport retains no second listing or event journal. Generated
artifacts and these source paths still require actual native/browser CI.

The 2026-10-02 05:45 binding MVP correction restores G2 frontier commitments and
zero-knowledge currentness plus public punishment. Earlier record-disabled
admission source is therefore NOT release-complete. Both empty and nonempty
record_proof inputs are refused; original accounting/Guard/Charter capability
integration is required before deploying or claiming MVP admission acceptance.
The public runtime therefore refuses all actions that would require that missing
capability before calling their owners. No person-specific current-record lookup
or accepting substitute is permitted.
