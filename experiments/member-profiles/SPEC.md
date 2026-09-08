# Member-held public profiles: experimental protocol

Status: all 23 client protocol acceptance tests passed on Crow repository 9, pipeline 7, at source `080cf7435acf8c23c2caa9a5bd50c7d5ae6a14a5`. The native nonce prerequisite passed before implementation and 18 tests failed against the original stubs. This directory is not a supported package export or deployed onion service.

## Functional boundary

A profile is bounded UTF-8 text held by its owner's client. The owner activates its local endpoint only while its own live forum lease is valid, and closes it on disconnect, suspension past expiry or replacement. The rendezvous service continues to store only current member IDs and onion endpoints. It receives no profile text, reader identity, per-read lookup or view log.

Every currently eligible credential holder may read. The reader does not disclose a member ID, chat key, passkey identifier, gate, receipt or exact credential expiry. It proves possession of its private holder secret through AnonCreds; copying another member's public admission certificate is insufficient. Passkey unlocking remains local. No report, profile moderation, administrator read, block-reader or HTML/URL fetching API is introduced.

The owner remains identifiable: the reader verifies the expected stable member ID from live discovery, the owner's cvld certificate, its certified chat key and its signed challenge before producing any eligibility proof. The owner signs the response using that same chat key. An owner learns that an eligible anonymous holder requested the profile, plus the shared community/policy and ordinary transport timing; it does not receive the holder's stable member ID.

An honest client stops serving when its own lease expires. Peers cannot prove instantaneous remote disconnect without an online presence lookup, which would disclose activity. Previously received text can be saved or reshared. A malicious owner can serve its own text elsewhere. Neither behavior is cryptographically reversible.

## Transport and state

The trusted application supplies an onion-only transport capability. It accepts only an explicit checksum-valid v3 onion host and integer port, never a URL, ordinary DNS name, IP address or direct fallback. Tor provides transport encryption; this experiment adds no encryption construction. A fake or in-memory adapter can test routing behavior but establishes no real anonymity.

The owner uses a fresh random profile `sessionId` for each activation. It is distinct from and never contains the secret rendezvous bearer token. Owner challenges are signed and can be stateless; only consumed challenge digests and short expiries need an in-memory replay cache. All capacities, frame/profile byte limits, proof concurrency and challenge lifetime are explicit. No durable profile/discovery/viewer record is created.

Disconnect or expiry invalidates challenges and responses in flight. Both sides recheck time/session state after asynchronous cryptographic or transport work. Anonymous pre-proof requests can still impose load; resource bounds are not a proof of denial-of-service resistance.

## Exact owner challenge

The object contains exactly:

```text
{version:1, communityId, ownerMemberId, ownerChatPublicKey,
 onionHost, onionPort, sessionId, readerNonce, ownerNonce,
 policyDigest, issuedAt, expiresAt}
```

Its signed bytes are UTF-8 compact JSON in this exact array order:

```text
["cfrm.profile.v1","challenge",communityId,ownerMemberId,ownerChatPublicKey,
 onionHost,onionPort,sessionId,readerNonce,ownerNonce,policyDigest,issuedAt,expiresAt]
```

IDs, chat key, nonces and digests are canonical unpadded base64url of 32 bytes. Signatures are canonical unpadded base64url of 64 Ed25519 bytes. Community scope uses ASCII `[A-Za-z0-9._:/-]{1,256}`. Onion hosts are lowercase v3 addresses; ports are integers 1..65535. Integer Unix seconds obey `issuedAt <= now < expiresAt`. Deployments choose `maxChallengeSeconds` explicitly within 1..300; no challenge exceeds 300 seconds, its owner's certificate expiry or its local live-lease expiry.

The owner signature API is narrow: `cmsg::Member::sign_profile_challenge(challenge, now)`. It validates its own certified ID/key/community/policy and grant-bounded times before signing. The owner client separately validates the live lease. There is no arbitrary signing oracle or signing-key export.

The reader creates a fresh random `readerNonce` per attempt. It accepts only a challenge for that nonce, its expected owner and endpoint, its configured issuer/policy/community, a fresh time window and a valid owner signature. Owner-supplied proof requests or extra disclosure fields are rejected rather than delegated to the wallet.

## Anonymous eligibility proof

Both sides independently construct the same AnonCreds presentation request. It reveals only `community_id` and `policy`, and proves `eligible >= 1` and `valid_until >= challenge.expiresAt`. The signed `member_id`, factor details, link secret and exact expiry remain hidden. Only the configured shared schema and credential definition are accepted; per-reader issuer parameters are not accepted from the owner.

The proposal binds the full owner transcript using:

```text
nonce = decimal_integer_big_endian(SHA256(challengeSigningBytes))
```

The [AnonCreds specification](https://anoncreds.github.io/anoncreds-spec/) describes an 80-bit nonce. The pinned [anoncreds-rs 0.2.3 parser](https://github.com/anoncreds/anoncreds-rs/blob/v0.2.3/src/data_types/nonce.rs) accepts larger positive decimal integers. The first acceptance test passed on Crow against revision `49f85e491edbaece0781a174c202d43d77113f86`: actual issuance, proof generation and verification used the full 256-bit transcript digest, and altered transcripts failed verification. No silent 80-bit truncation or claim of universal standards interoperability is permitted.

The protocol checks both the displayed `raw` attribute and its authenticated AnonCreds `encoded` value for the configured community and policy. Checking the display string alone would not bind the claimed scope. It rejects unsolicited revealed attributes, self-attestation, unexpected credential identifiers and extra frame fields before releasing text.

Fresh randomized presentations are an existing AnonCreds mechanism. Serialization tests can show absent stable values and different presentations; they cannot prove a deployed client or transport is unlinkable. The future reusable holder/proof API belongs inside cvld; this cfrm experiment exercises the boundary without modifying cvld's published holder API.

## Signed response

The response object is exactly:

```text
{version:1, challengeDigest, profileDigest, text, signature}
```

`challengeDigest` is SHA256 of the challenge signing bytes, and `profileDigest` is SHA256 of the exact validated UTF-8 text bytes. Both are canonical base64url32. The signature covers:

```text
["cfrm.profile.v1","response",challengeDigest,profileDigest]
```

`cmsg::Member::sign_profile_response(challenge, profileDigest, now)` accepts the full challenge, validates owner identity and time again, and derives the challenge digest internally. The reader verifies the signature, both digests, its own outstanding context, time and byte bounds. URL-looking text is inert text. Unpaired UTF-16 surrogates and invalid UTF-8 frames are rejected instead of silently replaced.

The byte-framed request/response envelopes are exactly one of:

```text
{"hello":{"version":1,"readerNonce":"..."}}
{"challenge":{"ownerGrant":{...},"value":{...},"signature":"..."}}
{"read":{"challenge":{...},"ownerSignature":"...","presentation":{...}}}
{"profile":{"version":1,"challengeDigest":"...","profileDigest":"...","text":"...","signature":"..."}}
```

Frames are bounded before decoding or parsing. Unknown fields, malformed encodings, unexpected message stages and missing proof fail closed without a profile response. A challenge is consumed at most once on successful proof authorization; use a bounded opaque replay marker before returning text. There is no central per-view receipt or accounting call.

## Executable boundary and remaining evidence

Acceptance tests use real cvld issuance, AnonCreds proofs and Ed25519 owner signatures with synthetic facts. Native dependencies come from an explicitly pinned public cvld checkout in the dedicated CI workflow. The test transport is an in-memory onion-capability double, deliberately not evidence of Tor anonymity. cmsg's real fixed-purpose methods require a separate cross-runtime vector/integration check after their implementation; the local signing fixture alone does not establish that integration.

No local tests, installs, paid services, provider authentication or real Tor endpoint were used. The core exchanges plain byte arrays and JSON. `crypto-runtime.js` is an explicit Node adapter to maintained CSPRNG, SHA-256, SHA3-256 and Ed25519 operations; it is the replacement boundary for a native/mobile runtime. The owner remains a local handler; the experiment does not publish an onion listener or demonstrate IP privacy.
