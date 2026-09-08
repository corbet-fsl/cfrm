# Authenticated complete eligibility checkpoints

This is a design contract, not an implemented transparency system. The current proof experiment receives its complete eligibility snapshot through a trusted host argument. A signature can authenticate a checkpoint; it cannot prove that the checkpoint issuer told the truth or showed everyone the same checkpoint.

## Inputs and lifecycle

An epoch publisher reads cfrm's complete registered account state at the epoch boundary:

- The immutable enrollment ledger containing each community member's Semaphore commitment.
- Minimal qualification state derived from successfully verified cvld admissions: the community, member ID, policy digest and eligibility expiry. Renewing qualification requires the same authenticated member binding; it does not rotate the commitment. Raw grants, passkeys and provider factors do not need to remain in this registry.

The published members are all enrolled accounts whose recorded cvld qualification remains valid for the current policy at the snapshot cut, sorted by canonical member ID. This means **registered qualification completeness**, not knowledge of every potentially eligible person or offline credential. cvld currently authenticates individual proofs and returns admissions; it has no global current-eligibility checkpoint API. This design does not require adding one.

An account that has not enrolled a Semaphore identity or refreshed its expired registered qualification cannot participate in anonymous acknowledgements in that epoch. The publisher's public request API must not accept a caller-selected member list, predicate or subset. The snapshot transaction fixes its cut using a trusted clock and reads the full enrollment/qualification state consistently with concurrent enrollment and renewal. A later request cannot backdate qualification into an already frozen checkpoint. Minimal expiry state reveals some eligibility freshness to the operator; it is distinct from a public profile or live-presence archive.

Membership is frozen for the checkpoint interval. New enrollments and gate changes affect the next interval. An admission that was valid at the cut may expire before that interval ends: anonymous acknowledgement rights remain frozen until interval expiry, while forum admission and messaging continue to enforce their own current eligibility. The epoch duration therefore bounds this deliberate delay. The existing experiment needs at least 17 members so each sender-excluded proof has at least 16 other commitments. A smaller community can still use its base allowance, but cannot obtain an anonymous acknowledgement through this experiment.

The publisher stores exactly one serialized checkpoint and digest per `(communityId, sequence)` in durable storage. Conflicting attempts at that sequence fail atomically, including across independent processes. Repeating the same request returns the exact committed checkpoint. This controls accidental or request-driven forks within the service; it does not constrain a malicious holder of the signing key outside that service.

## Signed portable envelope

The proposed envelope contains `version`, `issuerKeyId`, `policyDigest`, `sequence`, `previousDigest`, `snapshot`, and `signature`. `snapshot` is the existing canonical `freezeEligibility` result, including its complete ordered members, epoch label, interval, depth, minimum anonymity and digest. `sequence` is a positive safe integer. Sequence one uses `previousDigest=null`; later sequences refer to the previous signed checkpoint's digest.

The domain-separated Ed25519 signing bytes are UTF-8 JSON with this fixed order:

```text
["cfrm.eligibility.checkpoint.v1", issuerKeyId, policyDigest, sequence,
 previousDigest, snapshot.communityId, snapshot.epoch,
 snapshot.notBefore, snapshot.expiresAt, snapshot.minAnonymity,
 snapshot.depth, snapshot.members.map(m => [m.memberId, m.commitment]),
 snapshot.digest]
```

`issuerKeyId` is SHA256 of the raw 32-byte trusted signing public key; hashes and signatures use the established unpadded base64url encoding. The checkpoint digest is SHA256 of these canonical signing bytes. The signer is pinned by community configuration; a key supplied by the fetched envelope is never a trust anchor. A cfrm checkpoint key is a separate purpose from a member's chat key. Key rollover requires an explicit authenticated trust update and preserved sequence history.

## Client acceptance and limitations

A client verifies the pinned signature, community, policy, exact field encodings, canonical ordering, duplicate-free members, snapshot digest, current interval and local checkpoint continuity before using the list. It stores the highest accepted sequence and digest in its encrypted local wallet. The same sequence with different bytes, a lower sequence or a broken prior link is rejected. A reconnecting client that missed epochs needs the intervening signed checkpoint chain. A newly provisioned client needs a trusted starting checkpoint; a chain supplied solely by a malicious issuer does not provide independent truth.

The client derives every sender's proof group from this entire accepted snapshot and removes exactly that sender's enrolled commitment. It rejects a sender-proposed subset, changed interval, different policy or different membership digest. These local checks require a trusted complete starting view. The current acknowledgement wrapper implements the exact-whole-input check but does not yet authenticate network-fetched checkpoints.

Independent checkpoint witnessing or exchange between clients is needed to expose issuer equivocation. It can reveal conflicting signed digests without submitting allegations or conversation content, but cannot guarantee detection for isolated clients. This design does not invent a transparency protocol, custom circuit, blockchain or claim that signatures solve completeness. Reusing an existing append-only transparency implementation is the next step if this threat must be covered operationally.

The current snapshot exposes the stable IDs and commitments of qualified accounts, including offline accounts. It contains no profiles, endpoints, current-presence flags or contact edges, but durable eligibility membership itself is disclosed to its readers. A commitment-only list can reduce that disclosure: the complete list would be sorted by commitment, and a separately signed enrollment certificate would bind only the particular credited sender's stable ID to the commitment that must be excluded. The client would verify that certificate and remove exactly its commitment from the whole list. Its stable acknowledgement scope would still use the sender ID, preserving lifetime pair uniqueness.

That certificate must come from the trusted immutable enrollment registry, not from a sender's unsupported assertion; otherwise a sender could substitute a different commitment and endorse themselves. Enrollment PoP remains required before issuance. Existing cvld admissions certify the member's chat key but do not contain the Semaphore commitment, so they alone cannot provide this binding. The commitment-only format would change the present proof context contract and needs its own adversarial tests before replacing it. The operator still knows its enrollment mapping, and a recipient learns the sender's commitment; other participants' public IDs need not be revealed. Neither format proves that the other commitments belong to independent honest people.
