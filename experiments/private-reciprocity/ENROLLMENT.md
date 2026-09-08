# Immutable Semaphore enrollment contract

This is a bounded contract and adversarial specification. Eleven tests failed against the explicit stub in the internal CI run for source `a10bd27d4fa1cd1a50035b4d136604652511ac20`; the subsequent implementation is awaiting its first execution. It is not yet a validated key-possession protocol or a completed cvld integration.

## Identity lifetime

One stable community member ID may have one immutable Semaphore commitment. Different member IDs cannot share a commitment within a community. A second passkey or a changed certified chat key may authenticate the same binding; neither operation may rotate it. Otherwise lifetime acknowledgement nullifiers would reset.

The client derivation uses **`wallet.storageKey('cfrm-semaphore')`**, stable purpose-separated material from the random cvld wallet root. The root itself remains unexported. This input is neither a passkey-specific PRF result nor a chat signing key. The version-one encoding is:

```text
IKM  = wallet.storageKey("cfrm-semaphore") # exactly 32 stable client-held bytes
salt = UTF8("cfrm.semaphore.wallet.v1")
info = UTF8(JSON.stringify(["cfrm.semaphore.identity.v1", communityId]))
seed = HKDF-SHA256(IKM, salt, info, 32)    # bytes, never a hexadecimal string
identity = new Identity(seed)
```

The community follows the existing canonical ASCII scope grammar; there is no environment, deployment host, current time, passkey ID or chat key in the derivation. Restoring or rewrapping the same encrypted wallet must reproduce the same commitment. The additional cfrm purpose/community separation is intentional even though cvld already separates storage-key purposes. Cross-runtime vectors remain to be executed before claiming portable compatibility. Losing the wallet requires restoring the same encrypted wallet; silently enrolling a replacement commitment is forbidden.

The durable enrollment store contains only `(communityId, memberId, commitment)` plus indexes. It contains no profile, network endpoint, current-presence flag, passkey, phone number, payment detail or behavioral ban. This mapping enables a qualified eligibility snapshot; snapshot publication and completeness remain separate.

## Two required proofs of possession

The service validates a cvld admission grant and issues a fresh, short-lived server-authenticated challenge. A candidate binding must prove both:

1. Control of the grant's certified Ed25519 chat key, binding the request to the stable member ID.
2. Control of the Semaphore key whose public point hashes to the requested commitment.

The portable enrollment challenge contains `communityId`, `memberId`, `chatPublicKey`, `commitment`, `challengeId`, `issuedAt`, `expiresAt`. Its Ed25519 signing bytes are UTF-8 JSON:

```text
["cfrm.semaphore.enroll.v1", communityId, memberId, chatPublicKey,
 commitment, challengeId, issuedAt, expiresAt]
```

The EdDSA-Poseidon message is the unsigned SHA256 digest of those bytes shifted right by eight bits, represented as a canonical decimal integer. This fits the field and separates the signature's purpose. Canonical wire values use decimal strings for Baby Jubjub coordinates and scalars; the Ed25519 signature uses unpadded base64url.

The client uses existing APIs inspected in `@semaphore-protocol/identity` 4.14.3: `identity.publicKey`, `identity.commitment`, `identity.signMessage(message)`, `Identity.verifySignature(message, signature, publicKey)` and `Identity.generateCommitment(publicKey)`. The signature representation is `{R8:[x,y], S}`. No new elliptic-curve arithmetic or circuit is required.

## Public-key validation is part of this wrapper

The inspected EdDSA-Poseidon verifier checks curve membership and a cofactored signature equation. That alone is insufficient for this enrollment use: a neutral or torsion public point must not count as possession of a Semaphore secret. Enrollment must enforce canonical field encodings, nonneutral public keys, curve membership and prime-subgroup membership using existing `@zk-kit/baby-jubjub` primitives. Signature point/scalar encodings also need strict bounds.

The neutral-point equation concern is source-derived and encoded as a regression. It is not a claim of a tested deployed vulnerability or a defect in every use of the upstream API. The underlying library and circuit remain responsible for their own documented cryptographic behavior; this wrapper must enforce the assumptions of its enrollment use.

Replay and expiry must be checked at atomic insertion, with independent SQLite connections unable to replace the committed mapping. Failed signatures must not reserve the binding. A valid fresh request for the existing binding is idempotent; a consumed challenge is not reusable. Current tests specify these behaviors, restoration and community separation, copied keys, replacement attempts, duplicate commitments, neutral/torsion points and malformed encodings.

The prepared service uses opaque consumed-challenge hashes and a per-community clock floor in addition to the immutable bindings. These are replay/validity controls, not member activity histories. The floor prevents a restarted process with a rolled-back clock from reviving pruned challenges. Expired hashes can be removed while the floor persists. A process-local challenge-authentication key is replaced on restart, invalidating unfinished challenges.

Signed eligibility publication is a separate [checkpoint contract](SNAPSHOTS.md). Enrollment by itself does not assert that a credential remains eligible forever.
