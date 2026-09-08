# State and composition boundaries

cfrm is one of three repository boundaries: cvld handles passkeys and independent-provider eligibility; cfrm owns live community discovery and numerical participation rules; cmsg owns encrypted private text conversations. There is no separate rules repository.

The simulator's delivered, sent and received counts are **simulator-only observations**. The current private protocol exposes permit reservations, anonymous spends and endorsements instead. See the [private-accounting contract](../studies/private-accounting-contract.md) before treating any numerical rule as privately enforceable: directional sent/received imbalance remains unsupported, and the proposed reservation/endorsement controller is not implemented.

The follow-up [directional blind-receipt study](../studies/directional-blind-receipts.md) investigates a conditional sent/received acknowledgement protocol without discarding that original requirement. Its collusion, identity-binding and delivery limits are explicit; no accounting controller has been added.

## Stable identity, temporary presence

A participant has a stable, authenticated platform ID for counterparts in the community and private conversations. Disconnecting does not create a new identity, erase a local block or grant a fresh allowance. Separate communities must not automatically share an operator-visible identity or rule history. Raw phone numbers, payment details and provider-account lookup access do not belong to cfrm.

Presence is a lease with a bounded expiry, removed immediately on a clean disconnect and after missed renewal on an abrupt loss. A mobile client may suspend, lose its network or change its route. It must resume the same durable accounting state after reconnecting; continuous background execution is not assumed. Node is a test runtime, not a requirement on Android or iOS clients. Cross-component inputs must remain portable bytes and JSON.

Profiles stay with members. The rule experiment stores no profile text, pictures, IP addresses or network endpoints. The separate [real rendezvous library](../studies/rendezvous.md) verifies cvld certificates and signed chat-key challenges, retaining only live IDs, checksum-validated onion routes and bounded ephemeral session/replay state. It performs no network connection or content fetch. Peer discovery must not expose a member's network IP to malicious counterparts. No direct-network fallback or sender-controlled URL fetch is implemented or authorized by these libraries.

| Information | Intended holder | Current cfrm implementation |
|---|---|---|
| Profile | Member client | Experimental [owner/reader handler](../experiments/member-profiles/README.md) with real anonymous eligibility proofs and 23 passing tests; no actual profile Tor listener or native app |
| Presence lease and rendezvous capability | Ephemeral rendezvous system | Real certified IDs, onion routes and bounded ephemeral sessions; synthetic presence also exists in the rule model |
| Private first-contact history and local blocks | Member client, with cryptographic validity proofs as needed | Omniscient simulator maps |
| Durable allowance and double-spend prevention | Hidden state commitments and minimal spent markers | Real [blind first-contact permits](../experiments/anonymous-permits/README.md) with SQLite anti-replay; complete private reciprocity/rule accounting remains incomplete |
| Group roster and consent | Group participants | Synthetic `GroupExperiment` state |
| Operational health | Aggregated, delayed measurements, privacy design unresolved | Aggregate experiment diagnostics |

The intended operator contract excludes relationship maps, sender-recipient pairs and group IDs. The simulator deliberately contains these to exercise policy. Its `state`, `requestsFor` and `GroupExperiment` methods are diagnostic interfaces, not remotely callable production APIs. Even aggregate production metrics can reveal people in small groups; these synthetic results are not a differential-privacy implementation.

## cvld admission seam

The production shape is a trusted verifier receiving a holder-bound proof and authenticated challenge for the current community/session. cfrm must independently bind the resulting admission to that session's stable platform ID. It must not trust a browser-supplied `true`, an asserted ID, or an unbound copied credential.

The current cvld verifier exposes `begin(credentialId, audience, chatPublicKey)` for an enrolled credential and `authenticate(...)`, which returns `{eligible: true, communityId, memberId, admission}` or `false`. Its one-use challenge authenticates the chat-key binding as well as eligibility. The resulting Ed25519 admission is checked locally through `cvld/admission`; rendezvous also requires a fresh signature from that certified chat key. The boolean-only `verify(...)` consumes the same kind of challenge but does not provide the reusable signed grant. Expiry and renewal are eligibility matters; cfrm's numerical rules remain separate. The simulator constructor takes an explicitly named synthetic eligibility oracle so experiments can change admission without pretending to implement that protocol.

## cmsg accounting seam

A private introduction needs authorization for one permitted first-contact action, without exposing its counterpart to the operator. Existing conversation replies must not repeatedly consume first-contact tokens. A copied permit cannot be double-spent, changing the platform ID cannot reset a quota, and a participant cannot forge a reciprocal event alone.

Private reciprocity needs authenticated distinct participants, first-contact uniqueness, consent, hidden state transitions and replay protection. The real blind-permit experiment addresses finite allowance spending without sending a recipient ID to the issuer; it does not prove recipient consent, private counter correctness, noncollusion or absence of timing correlation. The separate [Semaphore acknowledgement experiment](../studies/private-acknowledgements.md) validates private eligible-member endorsements, lifetime nullifiers and a sender-excluded set. It binds one immutable Semaphore commitment to a certified stable member through two real signatures, refreshes qualification using actual cvld admission, and publishes signed commitment-only checkpoints covering the full validity interval. An independently signed sender binding replaces the public offline-member-ID map. Bounded signed links support checked catch-up; global issuer honesty/completeness, anonymous transport and native client integration remain assumptions or work. It does not prove delivery or sincere interaction. No complete production cryptographic accounting backend is implemented in the simulator.
