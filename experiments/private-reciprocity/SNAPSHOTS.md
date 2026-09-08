# Authenticated complete eligibility checkpoints

Thirteen tests failed against the explicit checkpoint stubs at source `09c12d3a9c8f460e8eaf33763c897dc1a6e92c64` in internal CI. The corresponding implementation now awaits its first execution. This is not a transparency system: a signature can authenticate a checkpoint, but cannot prove that the checkpoint issuer told the truth or showed everyone the same checkpoint.

## Inputs and lifecycle

An epoch publisher reads cfrm's complete registered account state at the epoch boundary:

- The immutable enrollment ledger containing each community member's Semaphore commitment.
- Minimal qualification state derived from successfully verified cvld admissions: the community, member ID, policy digest and eligibility expiry. Renewing qualification requires the same authenticated member binding; it does not rotate the commitment. Raw grants, passkeys and provider factors do not need to remain in this registry.

The published values are all enrolled commitments whose recorded cvld qualification remains valid for the current policy throughout the entire proposed checkpoint interval, sorted numerically. This means **registered qualification completeness**, not knowledge of every potentially eligible person or offline credential. cvld currently authenticates individual proofs and returns admissions; it has no global current-eligibility checkpoint API. This design does not require adding one.

An account that has not enrolled a Semaphore identity or refreshed its expired registered qualification cannot participate in anonymous acknowledgements in that epoch. The publisher's public request API must not accept a caller-selected member list, predicate or subset. The snapshot transaction fixes its cut using a trusted clock and reads the full enrollment/qualification state consistently with concurrent enrollment and renewal. A later request cannot backdate qualification into an already frozen checkpoint. Minimal expiry state reveals some eligibility freshness to the operator; it is distinct from a public profile or live-presence archive.

Epochs use an explicit fixed duration. At a successful publication cut `now`, `epoch=floor(now/epochSeconds)`, `notBefore=now` and `expiresAt=(epoch+1)*epochSeconds`. Inclusion requires a previously verified admission with `validUntil >= expiresAt`; one second short is insufficient. Near-expiry accounts must refresh before entering a later checkpoint. No member's qualification lifetime is extended, and a single short-lived account cannot shorten the interval for everyone else. New registrations and renewals cannot rewrite an already frozen epoch.

An empty or small complete checkpoint is valid, but the proof experiment still requires at least 17 included commitments so every sender-excluded group contains at least 16 others. Base allowance remains separate. A registry larger than the bounded depth-7 experiment supports must fail publication rather than silently truncate its list.

The publisher retains only the current full checkpoint, plus compact signed epoch links. Conflicting attempts at an already published epoch fail atomically, including across independent processes. Repeating the current configuration returns the exact committed checkpoint even if the registry changed afterwards. A durable clock/epoch floor prevents rollback after restart; the configured signing key and epoch duration cannot silently change. This controls accidental or request-driven forks within the service; it does not constrain a malicious holder of the signing key outside that service.

## Signed portable envelope

The envelope contains `version`, `issuerKeyId`, `communityId`, `policyDigest`, `epochSeconds`, `epoch`, `notBefore`, `expiresAt`, `minAnonymity`, `depth`, `previousDigest`, `commitments`, `digest`, and `signature`. It contains no member IDs. The first published checkpoint uses `previousDigest=null`; subsequent checkpoints refer to the previous published digest, even when quiet epochs were skipped.

The domain-separated Ed25519 signing bytes are UTF-8 JSON with this fixed order:

```text
["cfrm.eligibility.checkpoint.v1", issuerKeyId, communityId, policyDigest,
 epochSeconds, epoch, notBefore, expiresAt, minAnonymity, depth,
 previousDigest, commitments]
```

`issuerKeyId` is SHA256 of the raw 32-byte trusted signing public key; hashes and signatures use the established unpadded base64url encoding. The checkpoint digest is SHA256 of these canonical signing bytes. The signer is pinned by community configuration; a key supplied by the fetched envelope is never a trust anchor. A cfrm checkpoint key is a separate purpose from a member's chat key. Key rollover requires an explicit authenticated trust update and preserved sequence history.

Each compact link contains `version`, `issuerKeyId`, `communityId`, `epoch`, `previousDigest`, `digest`, and `signature`. It signs the UTF-8 JSON array `["cfrm.eligibility.link.v1",issuerKeyId,communityId,epoch,previousDigest,digest]`. It contains no commitments or member IDs. The explicit `maxRetainedLinks` setting is required and bounded from 1 to 4096; storage grows by one link per published epoch up to that ceiling, including the current epoch's link. The durable epoch floor survives pruning. Historical full rosters are not retained by this publisher.

## Client acceptance and limitations

A client verifies the pinned signature, community, policy, exact field encodings, canonical numeric ordering, duplicate-free commitments, digest, current interval and local checkpoint continuity before using the list. It retains the highest accepted epoch and digest in its encrypted local wallet. The same epoch with different bytes, a lower epoch or a broken prior link is rejected. A reconnecting client that missed published checkpoints needs the intervening signed compact links; `links(afterEpoch,beforeEpoch)` returns the retained links strictly between those epochs. Every signature and digest edge must verify. A gap caused by the retention ceiling fails continuity verification; it cannot silently become a successful catch-up. Starting a new trust checkpoint after such a gap is a separate client trust decision, not continuity with the old one.

A newly provisioned client needs a trusted starting checkpoint; a chain supplied solely by a malicious issuer does not provide independent truth. The pure verifier receives previous trusted checkpoint state explicitly; wallet persistence is a caller integration responsibility.

The client derives every sender's proof group from this entire accepted snapshot and removes exactly that sender's enrolled commitment. It rejects a sender-proposed subset, changed interval, different policy or different membership digest. These local checks require a trusted complete starting view. The current acknowledgement wrapper implements the exact-whole-input check but does not yet authenticate network-fetched checkpoints.

Independent checkpoint witnessing or exchange between clients is needed to expose issuer equivocation. It can reveal conflicting signed digests without submitting allegations or conversation content, but cannot guarantee detection for isolated clients. This design does not invent a transparency protocol, custom circuit, blockchain or claim that signatures solve completeness. Reusing an existing append-only transparency implementation is the next step if this threat must be covered operationally.

The earlier synthetic `freezeEligibility` format exposes stable IDs and commitments of qualified accounts, including offline accounts. The new format publishes commitments only. A separately signed enrollment certificate binds only the particular credited sender's stable ID to the commitment that must be excluded. The client verifies that certificate and removes exactly its commitment from the whole list. Its stable acknowledgement scope still uses the sender ID, preserving lifetime pair uniqueness.

That certificate comes from the trusted immutable enrollment registry, not from a sender's unsupported assertion; otherwise a sender could substitute a different commitment and endorse themselves. Enrollment PoP remains required before issuance. Its signed bytes are `JSON.stringify(["cfrm.semaphore.binding.v1",issuerKeyId,communityId,memberId,commitment])`, encoded as UTF-8. The object additionally contains `version:1` and the signature. The certificate is an immutable identity binding; membership in a currently valid checkpoint supplies acknowledgement eligibility. Existing cvld admissions certify the member's chat key but do not contain the Semaphore commitment, so they alone cannot provide this binding.

The publisher's `binding(memberId)` is a trusted internal operation. A network wrapper must deliver a member's own certificate only through authenticated enrollment/session handling, rather than expose an unauthenticated member-ID lookup directory. The operator still knows its enrollment mapping, and a recipient learns the sender's commitment; other participants' public IDs need not be revealed. Neither format proves that the other commitments belong to independent honest people.
