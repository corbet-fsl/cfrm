# Counter-backed release attestations: acceptance boundaries

**Counter-backed statements and bounded native release composition are tested; no policy selection.** The current
[22-case experiment](README.md) establishes the two raw directional counter
operations. The [cmsg release proposal](https://github.com/corbet-libs/cmsg/blob/main/studies/first-contact-release-gate.md)
adds a conditional sender-side gate. Actual counter commits must connect to that
gate's signed statements; synthetic signatures alone do not establish this
connection. The initial
[16 executable cases](attestations.test.js) cover groups 1–7 below with actual
cryptographic fixtures. All 16 reached the intended stub failures at
`907616cde9224d1be8b2f49ac2c68f269f555fc3`, alongside 22 passing raw cases. The
implementation shares the original atomic ledger and passes all 38 cases at
`fdf739e3fdc40aedbc61a552d41b9fc83623f8b4`: the unchanged 22 raw cases plus the
16 release cases. This includes independent Node verification of the exact cmsg
canonical arrays. The additional [three composition cases](composition.test.js)
now establish the core same-member MLS release, substitution/retry and local
encrypted-restore portion of group 8. They reached three intended stub failures
in Crow 9/18, then passed with all 38 baseline and four process cases in Crow
9/21 at cfrm `82f824c1d26e37d89f946728dab98b36a76612b1` and native cmsg
`7c6740369cf17779c2b749547adfbca92b899f34`: 45 passes, 0 failures. See the
[complete source pins and scope](README.md). Groups 9–10 and durable crash/
rollback recovery remain separate composition work.

The boolean redemption API remains the tested raw baseline. The isolated
release-receipt service exposes the same two operation names with the structured
success results below. It changes no shipping API and selects no participation
policy. The new cases reached assertions against rejecting stubs after actual
prerequisite crypto execution before the implementation was written.

## Counter and release contract

| Operation | Required durable changes | Success result |
|---|---|---|
| `authorizeAndAcknowledge` | Existing sender nonce, whole-request digest, lifetime nullifier and `authorizedSend`, plus the exact cached response | `{ blindSignature, senderCommit }` |
| `redeemAcknowledgedReceipt` | Receipt serial, `acknowledgedReceive`, recipient/release-nonce marker and the exact cached attestation | `{ recipientRedemption }` |

The sender result establishes its own authorized counter commit. The recipient
result establishes its own receive counter commit for a fresh release challenge.
Together they still do not prove that this recipient token came from this
sender's particular blind signing interaction, that a text was delivered, or
that the participants sincerely conversed. A policy controller must keep the
existing counter names and their precise meanings.

The cmsg [canonical structures](https://github.com/corbet-libs/cmsg/blob/main/experiments/first-contact-release/src/lib.rs)
at source `760948f` define these JSON shapes:

```text
Context = { communityId, policyDigest, cohortId, notBefore, expiresAt }
Peer = { memberId, chatPublicKey }
SenderCommit = {
  context: Context, sender: Peer,
  authorizationNonce, blindedRequestHash, signature
}
RecipientRedemption = {
  context: Context, recipient: Peer, releaseNonce, signature
}
```

Their Ed25519 signing bytes are UTF-8 JSON arrays in exactly this order:

```text
[
  "cfrm.directional.commit.v1",
  communityId, policyDigest, cohortId,
  senderId, senderChatPublicKey, authorizationNonce, blindedRequestHash,
  notBefore, expiresAt
]
[
  "cfrm.directional.redemption.v1",
  communityId, policyDigest, cohortId,
  recipientId, recipientChatPublicKey, releaseNonce,
  notBefore, expiresAt
]
```

Community/cohort identifiers follow the existing canonical ASCII scope syntax
and are at most 128 bytes, within the cmsg context bounds. Policy
digests, member IDs, keys, nonces and hashes use exact base64url without padding;
those binary values are 32 bytes and signatures 64 bytes. Times are positive safe
integers in the Node adapter. Reject unknown fields, alternate encodings and
wrong purposes. Use maintained Ed25519 signing through Node crypto and the
existing cmsg verifier; no generic signing oracle or new cryptographic circuit
is introduced.

The context is common to the cohort: `notBefore` is its common start and
`expiresAt` is its common `redeemUntil`. Do not copy per-request authorization
times or generate an expiry personalized to one account. Two independently
generated operator attestation keys serve the distinct sender/recipient purposes
and are pinned in the cohort configuration. Their public keys and purpose
assignments cannot silently change for an already registered cohort. Blind RSA,
admission and checkpoint keys retain their separate existing purposes.

## Hidden receipt and consent

Use a new receipt purpose/domain and a newly generated shared 3072-bit RSA key.
Do not issue the old and new formats under one key: hidden message labels cannot
stop a client asking one issuer to sign another valid purpose's payload.

The proposed randomized receipt is 160 bytes:

| Bytes | Meaning |
|---|---|
| 0–31 | RFC 9474 randomized prefix |
| 32–63 | Domain digest of the complete common release-receipt context and RSA key |
| 64–95 | Recipient's stable community member ID |
| 96–127 | Fresh receipt serial |
| 128–159 | Fresh private release nonce generated by the honest sender |

The recipient chooses and blinds its own receipt after receiving authenticated,
consented private preflight. It must not unblind a request supplied by a sender.
The current proof circuit can bind the blinded-request hash but cannot prove
that the hidden recipient is the prover; the tested pooling limitation remains.

The release nonce must not occur in the named sender's operator request,
authorization, proof public message, cached response or database records, either
directly or as a shared hash. Only the RSA-blinded request carries it during
issuance. The sender authorization nonce is independently generated. Its nonce
and request hash must not occur in receiver redemption or its signed result.
No preflight signature, invitation digest or conversation ID enters either
operator payload. The recipient can see those private preflight details; the
operator should not receive them.

The attested chat key comes from the admission verified at the first successful
commit. Recovery returns that exact cached attestation, including its original
key, context and expiry. It must never mint a new attestation for a rotated key
without the corresponding new release process. An attestation claims a counter
commit under the then-verified key; the client composition must still verify
current cvld admission and private preflight ownership before content release.

## Acceptance groups

The first seven acceptance groups have real stub-failure evidence followed by
passing implementation tests. Group 8 has the bounded actual-member evidence
described above; the remaining consent/fairness and first-contact/group
composition in groups 9–10 is unverified:

1. **Real counter-backed outputs.** Use actual enrolled sender-excluded
   Semaphore proofs, real cvld admission verification and maintained blind RSA.
   Before authorization, no valid sender statement exists. After the durable
   sender commit, verify its exact canonical Ed25519 statement, independently
   finalize the receipt, redeem with the named recipient's own authorization,
   and verify its exact recipient statement. Both counters increase once.
2. **No signatures on rejected or partial operations.** Missing own signatures,
   invalid proofs, wrong admission, wrong configured keys, exhausted caps,
   expiry and precommit interruptions produce no usable success result and no
   counter update. The attestation and accounting changes share their respective
   transaction. Signing before commit is allowed only if the candidate result
   cannot escape before successful commit.
3. **Lost response and cross-connection recovery.** Two SQLite connections racing
   the same issuance or redemption receive the exact same cached result. Inject
   loss immediately after commit, reopen, and recover without another debit.
   Issuance recovery works after its checkpoint and short authorization expire
   while the common cohort remains open. Receive recovery uses a fresh current
   admission and freshly signed receipt-specific authorization when necessary.
   It returns the old signed context/key/expiry rather than extending validity.
4. **Release nonce ownership and uniqueness.** No receive debit or attestation
   exists without the recipient's own receipt-specific permission. Another
   account, changed release nonce, serial or receipt message cannot use that
   permission. A different valid serial for the same recipient/release nonce
   cannot create a second debit or a replacement attestation; reject it. Exact
   retries of the first valid receipt remain recoverable. This is a
   recipient-side marker, never a sender-recipient join.
5. **Key, purpose and cohort isolation.** Old 128-byte receipts, wrong-purpose
   RSA signatures, swapped sender/recipient attestation keys, wrong common
   contexts and a same-algorithm wrong private key fail. Persistent cohort
   configuration rejects key reuse, silent key reassignment and cap changes.
   Pruning and rollback cannot reactivate old receipts or cached statements.
6. **No shared join field.** Inspect both requests, both returned statements and
   retained rows. The named sender side has no recipient ID, chat key, release
   nonce or directly shared derivative; the named recipient side has no sender
   ID, sender nonce, request hash or proof nullifier. The anonymous proof still
   uses the full qualified group with at least 16 alternatives. The inspection
   demonstrates explicit-field separation, not traffic-analysis resistance.
7. **Preserved malicious limits.** A qualified prover can still designate another
   hidden recipient and pool receipts. The raw counter example must continue to
   succeed. An attestation naming that other recipient must fail the honest
   sender's expected-recipient release check. A matching receive result obtained
   from a different authorized issuance can satisfy that check; no same-token
   provenance claim is added. The sender separately needs its own commit.
8. **Conditional release with actual MLS.** Exchange safe synthetic fixtures with
   cmsg: actual certified member IDs and chat keys, a fresh challenge from its
   pending release, Node-produced statements from committed ledgers and the
   corresponding withheld MLS material. The intended modified receiver cannot
   obtain that material from the honest sender before both valid attestations;
   it can decrypt after release. Changed identity/key/nonce/purpose/cohort and a
   prior challenge's attestation fail. Test lost release responses against
   encrypted pending state. A generic signature fixture with unrelated MLS
   participants does not establish this composition.
9. **Consent and fairness boundaries.** Rejected/blocked preflight creates no
   receive debit. Once a recipient authorizes redemption, a malicious sender may
   disappear or provide invalid material despite the debit. Demonstrate this
   limitation explicitly: there is no delivery proof, automatic refund,
   accusation, report or adjudication. A dishonest sender can also release
   content without this gate; the conditional claim concerns honest senders.
10. **First-contact and group separation.** A new introduction retains its
    independent first-contact permit. An honest reversed directional action
    requires no ordinary-reply permit. One recipient attestation cannot unlock
    independent recipient/challenge pairs in a group, and joining does not
    debit every group member or each later message. The bounded test may use
    several independently challenged recipients; a 100-member claim requires
    separate actual scale evidence.

## Dependencies before integration

Groups 1–7 use actual counter crypto and exact canonical outputs. The bounded
group-8 composition followed the cmsg gate's passing tests and its narrow
certified-key signers for enrollment, private preflight and account authorizations.
It uses the same certified counterparts in cfrm and MLS, without generic
private-key export or replacement Node chat keys. Its Node driver spans synthetic
holder/operator roles and the native child owns both peers for the test; neither
arrangement establishes deployed peer or operator isolation.

Groups 9–10 need the consent, local block and first-contact state boundaries to
be joined with the real client paths. Until those paths run, document them as
unverified composition work. Existing Tor routing and no-direct-fallback rules
still apply; an in-process crypto test cannot establish network anonymity.

Client-owned encrypted blind preparation, durable pending recovery and concurrent
writer/old-snapshot handling remain necessary. The tested encrypted pending
restore happens within one child; a fresh nonce alone is not a
durable rollback solution. No participation controller, compulsory read counter
or final policy decision follows from passing this attestation increment.
