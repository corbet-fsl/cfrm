# Member-held profile experiment

A live, text-only profile protocol experiment. The owner is authenticated by its stable cvld identity and cmsg chat key. Passive readers prove anonymous eligibility using AnonCreds; they do not disclose their member ID. The rendezvous operator never receives profile text or a per-view lookup.

This is **an experimental client handler awaiting its first complete acceptance run**, not a supported package export or deployed profile service. The original 21-test contract ran on Crow at `49f85e491edbaece0781a174c202d43d77113f86`: the real AnonCreds prerequisite passed and 18 tests failed on absent implementation. Two additional negative tests passed against the stubs; that alone did not establish their security behavior. The implementation and two additional regression tests now require a complete green run.

- [Functional and exact byte contract](SPEC.md)
- [Acceptance tests](profiles.test.js)
- [Synthetic real-cryptography fixtures](fixtures.js)
- [Explicit Node cryptography adapter](crypto-runtime.js)
- [Cross-runtime cmsg owner-signature consumer](cmsg-signatures.js)
- [Dedicated public CI workflow](../../.github/workflows/member-profiles.yml)

The workflows use pinned public cvld and cmsg revisions, synthetic keys and existing libraries. Real AnonCreds generation and verification with a full SHA-256 transcript nonce passed on the pinned native runtime. This deliberately differs from the specification's nominal 80-bit nonce guidance; compatibility with other implementations is not established. cmsg's fixed-purpose signatures have a separate cross-runtime consumer.

The protocol uses byte frames and a narrow cryptography adapter for CSPRNG, SHA-256, SHA3-256 and Ed25519 verification. This experiment's adapter uses maintained Node crypto; a browser or native mobile client must supply equivalent reviewed operations and its own AnonCreds holder integration. No mobile or browser profile implementation is claimed. The owner handler is local to the member: application glue must publish it through the onion listener and activate/disconnect it with the local forum lease.

The in-memory onion adapter tests routing and failure behavior only. It does not demonstrate Tor transport, peer IP privacy or resistance to traffic analysis. No local cryptographic tests, provider accounts, phone checks, paid services or real onion services were used here.
