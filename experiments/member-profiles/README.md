# Member-held profile experiment

A proposed live, text-only profile exchange. The owner is authenticated by its stable cvld identity and cmsg chat key. Passive readers prove anonymous eligibility using AnonCreds; they do not disclose their member ID. The rendezvous operator never receives profile text or a per-view lookup.

This is **a specification and unimplemented fail-first contract**, not a working profile feature. The tests have been authored but not executed. GitHub Actions scheduling was unavailable during this work. Existing library functionality must not be inferred from these stubs.

- [Functional and exact byte contract](SPEC.md)
- [Acceptance tests](profiles.test.js)
- [Synthetic real-cryptography fixtures](fixtures.js)
- [Cross-runtime cmsg owner-signature consumer](cmsg-signatures.js)
- [Dedicated public CI workflow](../../.github/workflows/member-profiles.yml)

The workflow uses pinned public cvld and cmsg revisions, synthetic keys and existing libraries. It must first validate real AnonCreds generation and verification with a full SHA-256 transcript nonce. This deliberately differs from the specification's nominal 80-bit nonce guidance and remains unavailable until that prerequisite passes. The remaining acceptance tests should fail on absent profile behavior; cmsg's new fixed-purpose signing methods also initially remain unimplemented.

The in-memory onion adapter tests routing and failure behavior only. It does not demonstrate Tor transport, peer IP privacy or resistance to traffic analysis. No local cryptographic tests, provider accounts, phone checks, paid services or real onion services were used here.
