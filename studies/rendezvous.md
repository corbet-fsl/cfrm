# Certified live rendezvous

`src/rendezvous.js` is a real ephemeral roster library, separate from the omniscient rule simulator. It verifies cvld admission through an explicitly trusted verifier and requires possession of the certified Ed25519 chat key before creating a session. A copied public certificate alone cannot register as its owner.

## Tested boundary

The initial specification preceded implementation at `5e8d94b`. Implementation `b680c6d` passed all 16 rendezvous tests against the actual standalone cvld verifier at `0f1ee4df3cc72294ba624de85542cc112c1bbbd7`: [dedicated integration CI](https://github.com/corbet-labs/cfrm/actions/runs/34258629336). The complete 53-test suite and rule experiments also [passed](https://github.com/corbet-labs/cfrm/actions/runs/34258629199). Two further regressions cover expiry during asynchronous verification and certificate-limited leases.

Tests use actual Ed25519 signatures, synthetic admission keys, a fake clock and controlled timer callbacks. No real member, profile, network address, live Tor service or credential provider is involved. The dedicated workflow loads the real pure cvld verifier; ordinary isolated unit tests use a small independently signed Ed25519 fixture verifier. Neither path mocks chat-key signature verification.

## API

```js
import { createRendezvous } from 'cfrm/rendezvous';
import { verifyAdmission } from 'cvld/admission';

const registry = createRendezvous({
  communityId, policyDigest, trustedPublicKey, verifyAdmission, clock,
  leaseSeconds: 30, challengeSeconds: 10,
  maxMembers: 100, maxReplayEntries: 1000,
});

const { challenge, authenticator } = await registry.begin(grant, { host, port });
// The member's cmsg client signs challenge with its certified chat key.
const session = await registry.register({ grant, challenge, authenticator, signature });
const roster = registry.list(session.token);
registry.disconnect(session.token);
registry.close();
```

The numeric values in this example are explicit configuration choices, not production recommendations. `trustedPublicKey` is the configured cvld issuer's raw 32-byte Ed25519 key; it does not come from a requester. `clock` returns integer Unix seconds and must not move backward. The verification dependency and all limits belong to trusted host configuration. A network wrapper must never allow requests to replace them or supply a purported verification result.

The challenge is exactly:

```text
{communityId, memberId, chatPublicKey, endpoint:{host,port},
 challengeId, issuedAt, expiresAt}
```

Its signing bytes are UTF-8 JSON with this fixed array order:

```text
["cfrm.rendezvous.v1", "register", communityId, memberId, chatPublicKey,
 endpoint.host, endpoint.port, challengeId, issuedAt, expiresAt]
```

The chat key signs those bytes using Ed25519. The signature is raw 64 bytes encoded as canonical unpadded base64url. The fresh challenge ID is 32 random bytes in the same encoding. The challenge envelope also carries a separate HMAC authenticator, which only the registry can produce. cmsg's `Member::sign_rendezvous` uses this same byte contract and binds the challenge to its own certified identity. This is a portable JSON/byte protocol; Android and iOS clients do not need Node.

## Minimal state and lifecycle

Challenge issuance is stateless. Repeated presentation of somebody else's certificate cannot fill a pending-challenge table. Registration validates the server authenticator, current cvld grant and certified-key signature, then rechecks expiry and capacity after asynchronous verification. Committing the session and replay marker is synchronous within this instance.

| State | Retention |
|---|---|
| Active stable member ID, onion endpoint, lease expiry | Until disconnect, replacement or lease expiry |
| Hash of the opaque session capability | Same live lease |
| Hash of a consumed challenge nonce, with no member ID | Until the short challenge expiry |
| Ephemeral server HMAC key | Current process only |

Successful signed re-registration replaces the old session for that member. It does not touch durable numerical accounting. A mobile client may suspend past lease expiry and return with the same identity using a new signed challenge. Expiry timers delete state even without another member request; `prune()` also performs immediate expiry checks. `close()` clears state and the ephemeral HMAC secret. Process restart forgets all presence and invalidates earlier challenges and sessions.

`list()` requires an active, unexpired session. It returns only current `{memberId, endpoint}` records. It stores no profile text, search query, contact graph or historical last-seen time. Session capabilities are bearer secrets returned to their owner; only their hashes are retained. Network wrappers must protect them and exclude them from logs.

## Onion validation and limits

Endpoints are exactly `{host, port}` with a lowercase v3 onion hostname and an integer port from 1 to 65535. Validation checks decoded key length, version and SHA3 checksum according to the [Tor onion address specification](https://spec.torproject.org/rend-spec/encoding-onion-addresses.html). IP addresses, ordinary DNS names, URLs, paths, query strings, extra routing fields and invalid checksums are rejected. The registry advertises addresses and performs no DNS lookup, URL fetch or network connection.

This library does not prove that an advertised onion service is reachable or controlled by the registrant. The subsequent cmsg handshake must verify the expected certified peer identity. It also does not make the registry connection anonymous: the application must use the intended anonymous transport for that connection. No HTTP server, Tor daemon or deployment is supplied here.

The live roster and replay cache have explicit caps; saturation fails closed. A legitimately admitted malicious participant can still spend resources or fill capacity, so these bounds are not a complete denial-of-service defense. Timers and synchronous commit semantics apply to one process; a distributed registry requires its own consistent ephemeral state implementation. Statistical privacy of operational counts and traffic-analysis resistance are not claimed. Do not add logging or durable profile storage around the library and call that the same privacy boundary.
