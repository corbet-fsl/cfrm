# Actual-member release composition: reviewed harness outline

**Reviewed design, now implemented and tested within the stated harness scope.**
This outline is retained as the accepted protocol plan for the
[three executable composition cases](composition.test.js). They reached the
intended native stub in Crow 9/18 after actual enrollment/proof verification, then
passed in the full 45-case run at cfrm
`82f824c1d26e37d89f946728dab98b36a76612b1`, native cmsg
`7c6740369cf17779c2b749547adfbca92b899f34` (Crow 9/21). See the
[evidence and exact dependency pins](README.md). The bounded portion of
[acceptance group 8](ATTESTATION-ACCEPTANCE.md) uses actual cfrm counter statements
to unlock MLS material for the **same two certified members** whose chat keys
authorized enrollment and accounting. It adds no production API or final policy.

## Processes and trust boundaries

A native cmsg child owns two actual `Member` instances, their signing keys, MLS
state, withheld Welcome/first ciphertext and encrypted pending-release state.
It exposes narrow typed operations and coarse results. No member private key,
MLS payload, plaintext, wrapping key or snapshot leaves this child.

A Node test driver owns a synthetic cvld issuer, the trusted checkpoint and
operator keys, two synthetic **holder-wallet** Semaphore identities and 15 filler
members. It also invokes the actual enrollment, checkpoint and receipt services.
The two real chat keys come only from the native child. The filler chat keys
remain ordinary Node fixtures. Together these make exactly 17 enrolled identities
and 16 qualified alternatives to the named sender.

The driver is a test orchestrator spanning holder and operator roles. It sees
private preflight while acting as the recipient's holder, then supplies only the
specified service envelopes to the operator modules. Do not describe this Node
process as an unaware production operator or copy the arrangement into an
operator relay. Assertions inspect the actual service inputs, outputs and rows;
they cannot establish separation between processes sharing this harness.

Similarly, one native child holding both peers is deliberate test scaffolding.
It establishes cryptographic interoperability and identity continuity, not peer
isolation, network anonymity or two independently deployed clients.

## Reusable entry points

| Existing component | Required use |
|---|---|
| Pinned cvld `admissionBytes`, `verifyAdmission` | Sign synthetic admission grants using each exact native public key, then verify those grants through the real service path. Load the same pinned source through `CVLD_ADMISSION_MODULE`. |
| `private-reciprocity/enrollment.js`: `deriveSemaphoreIdentity`, `openEnrollmentLedger`, `createEnrollmentService`, `enrollmentMessage` | Derive synthetic holder identities, issue enrollment challenges and verify both actual native chat-key signatures and Semaphore possession signatures. `enrollmentBytes` signs only the 15 filler members in Node. |
| `private-reciprocity/checkpoints.js`: `createCheckpointPublisher`, `registeredAcknowledgementContext` | Publish the entire enrolled/qualified roster; get the independent sender binding and authenticated sender-excluded proof context. Never supply a caller-selected subset. |
| Maintained Semaphore `Group`, `generateProof`, identity `signMessage` | Generate the recipient holder's actual proof and enrollment possession signature. Reuse the existing verified depth-7 artifact manifest and pinned packages; no new circuit. |
| `directional-receipts/fixtures.js`: `proofMessage` and canonical byte helpers | Bind the proof to the actual native sender authorization and signed checkpoint. Do not call the whole `fixture()` constructor: it substitutes Node chat keys for all 17 members. |
| `directional-receipts/attestation-fixtures.js`: `releaseDomain`, `commonContext` | Reuse the exact release domain/common context encoding when preparing the recipient's 160-byte receipt. Do not call the whole `releaseFixture()` constructor. |
| Maintained RFC 9474 blind-RSA suite | Holder-owned prepare/blind/finalize using the release-purpose 3072-bit key. Unblinding state stays in the driver's holder role and never enters service requests. |
| `openDirectionalLedger`, `createReleaseReceiptService` | Obtain actual sender/recipient signed results from their corresponding committed transactions. No synthetic replacement attestation in the successful path. |
| cmsg `Member` admission, enrollment and release methods | Use the same two member signing keys for admission binding, narrow enrollment signatures, authenticated private preflight and both directional account authorizations. No generic signing or private-key export. |
| cmsg experimental `PendingRelease`, `OperatorTrust`, MLS `Member` methods | Retain actual material, bind the request hash/independent sender nonce, verify real statements, join and authenticate/decrypt inside the child. |

Existing dependency pins are sufficient for the Node side. Any helper extraction
must remain small and preserve all 38 existing cases. The native executable is
an unpublished experiment consuming the actual cmsg crate and its separate
release-gate experiment. The CI workflow must pin its exact reviewed source and
provide the built executable by a trusted `CMSG_RELEASE_HARNESS` path. The driver
must not download, install or select a substitute binary itself.

Artifact paths remain `private-reciprocity/.artifacts/semaphore.wasm` and
`semaphore.zkey`; verify their lengths and SHA-256 hashes against
`private-reciprocity/artifacts.json` before generating proofs. The current check
is private inside `fixtures.js`'s `common()` initializer. Extract only that
verification/curve-lifecycle helper if sharing it, rather than invoking the
initializer that manufactures 17 chat keys. Reuse the existing `ffjavascript`
curve setup/termination pattern so a proof worker cannot keep the child test
process alive after completion.

Composition followed separate passing evidence for cmsg's typed release
authorizations/private preflight and narrow enrollment signer. Their presence
in source alone was insufficient. The already-tested experimental
`PendingRelease` gate does not supply those `Member` signatures itself.

## Proposed JSON-lines exchange

Every request has `{ id, op, args }`; every response has either
`{ id, ok: true, result }` or `{ id, ok: false, error }`. Errors use fixed coarse
codes. One request is outstanding at a time. Actor handles are the fixed strings
`sender` and `recipient`; each maps to the same native instance for the whole run.

| Verb | Request data | Result and local behavior |
|---|---|---|
| `init` | Fixed synthetic time; community/policy; public admission issuer and distinct operator purpose keys; independently derived expected wallet commitment for each actor | Create two actual `Member`s with a trusted synthetic clock; pin configuration and return their exact public chat keys. Retain expected commitments separately from all future server challenges. |
| `bindAdmissions` | The two exact Node-issued admission grants | Bind each grant to its matching native key; return both member IDs and public keys for equality assertions. Subsequent methods derive their own IDs from stored grants. |
| `signEnrollment` | Actor and typed enrollment challenge | Call `sign_semaphore_enrollment` with the actor's independently retained expected commitment; return only its fixed-purpose signature. Do not accept a replacement expected commitment in this call. |
| `prepareRelease` | Common release context and bounded private-preflight expiry | Create the real group/invitation and synthetic first text inside the child; wrap the withheld bytes in `PendingRelease`. Sign preflight with S and verify it with R against the exact current peer grants. Return that private preflight and coarse assertions that R has no Welcome and cannot decrypt the first ciphertext alone. |
| `authorizeSend` | Actual base64url 384-byte blinded request and short authorization expiry | Hash actual bytes inside the child; bind through `PendingRelease.bind_request`; use its independently generated authorization nonce with S's `authorize_release_send`. Return the account authorization, without private preflight or release nonce. |
| `authorizeReceive` | Exact `{ message, signature }` receipt and short authorization expiry | Use R's retained verified private release nonce, current grant and a fresh independent receive-authorization nonce with `authorize_release_receive`. Return only the named R account authorization. |
| `finishRelease` | Actual `senderCommit` and `recipientRedemption` from the ledgers | Check pinned operator keys and exact pending context/peers/nonces/hash; release retained material, join and decrypt using R. Return coarse gate/decryption/authenticated-sender/expected-text results, never text or MLS bytes. |
| `restorePending` | Empty object | The reviewed eighth verb seals/restores the bound pending state inside the child before its first join. Return only restored/not-joined outcomes; wrapping material and encrypted snapshots stay inside the child. |

The receipt's message and signature retain their exact base64url encoding; the
native receiver adapter computes the canonical envelope hash itself. The sender
adapter likewise computes its own blinded-request hash. Contexts and statement
arrays remain exactly those in [the acceptance contract](ATTESTATION-ACCEPTANCE.md).
The common statement deadline comes from `redeemUntil`, never a short account
authorization's personalized expiry. Public keys and binary IDs remain exact
canonical base64url values; typed Rust trust structures are mapped explicitly
instead of accidentally depending on their internal snake-case field names.

The private preflight is returned only to the driver's holder role. Neither it,
its signature nor its release nonce may be added to the named sender's operator
authorization, proof public message, request or cached output. A test can compare
the assembled service envelope to the exact permitted schema before calling it.
That is an explicit-field check, not a traffic-analysis claim.

Use a small fixed line limit (32 KiB suffices without proofs or MLS bytes in the
child protocol), deny unknown fields and require matching monotonically increasing
request IDs. Bound every exchange with a timeout. Unexpected EOF, non-JSON output,
wrong IDs or child failure fail the test. Protocol stdout is a captured pipe;
diagnostics and final CI output contain only coarse assertions, never raw
envelopes. On cleanup, stop only the exact child process created by the test.
Do not mask a failure by switching to fixture keys or a simulated child.

## Successful run

1. Generate two independent synthetic wallet identities in the driver's holder
   role and 15 filler identities. Supply only the two expected commitments to
   native `init`; retain the Semaphore secrets in the holder role. Receive the
   actual two chat keys and issue synthetic grants for those exact keys and
   stable community IDs. Bind them in the child.
2. For S and R, call actual enrollment `begin`, obtain the native fixed-purpose
   chat signature, and produce the holder's actual Semaphore possession signature
   over `enrollmentMessage(challenge)`. Submit both to `enroll`. Enroll the 15
   fillers through the same service, then publish the full 17-member checkpoint.
   Compare grants, challenges and published bindings with the native identities.
3. Prepare the native pending release and authenticate its private preflight at
   R. The harness explicitly chooses acceptance for this run; signature
   verification alone is not a consent decision. Assert that the unjoined R
   cannot decrypt the first ciphertext without the withheld Welcome.
4. The recipient holder prepares/blinds its own receipt containing its exact
   certified ID and the independently received private release nonce. Obtain S's
   native authorization over those actual blinded bytes. Generate R's actual
   sender-excluded Semaphore proof using the authenticated full checkpoint,
   independent S binding, existing lifetime scope and `proofMessage`.
5. Call `authorizeAndAcknowledge` with only S authorization/admission, checkpoint,
   binding, blinded request and proof. Check S's counter increased once and R's
   did not. Give the child the real sender statement and an unusable recipient
   statement: it must still withhold material and R must remain unjoined.
6. Finalize the blind signature in the recipient holder role. Obtain the actual
   native receipt-specific R authorization, then call
   `redeemAcknowledgedReceipt`. Check the receive counter increased exactly once.
   Sender nonce/request hash/proof nullifier do not enter that call or its result.
7. Give both actual operator statements to `finishRelease`. R now joins and
   decrypts the retained text. Inside the child, compare MLS's authenticated
   sender member ID to the exact S admitted/enrolled/accounted identity, and
   compare the plaintext to the fixed synthetic text. Return only the results.

This run proves the connection between the actual accounting keys and MLS peers.
It does not prove that R's receipt originated from this particular S issuance:
the explicitly permitted pooling/provenance limitation remains unchanged.

## Fail-first cases and deferred scope

The small executable suite reached a rejecting harness operation after all real
prerequisites ran, before native release implementation. The passing combined
run preserves the existing 38 cases and the four process contracts. Its three
independent composition cases are:

- The complete run above, with withholding before either required statement and
  actual authenticated decryption only after both real counter commits.
- A changed certified peer/key, request binding or private release challenge
  fails the native gate despite an otherwise well-formed statement. An unchanged
  valid retry still succeeds; negative attempts do not consume the pending text.
- Exact issuance/redemption retries return the same actual statements and leave
  counters at one. Seal/restore the pending release inside the child, then release
  the same retained material. Compare returned material internally before one
  actual join/decrypt, without exporting snapshots or wrapping material.

Recovery after short account-authorization expiry may be added with one explicit
monotonic fixture-clock operation after reviewing the simpler wire. Current
grants/private preflight/common cohort must still be valid. Use fresh ledgers and
pending challenges where a case needs a new directed event; do not reset the
lifetime-nullifier rule to make repeated attempts pass.

An in-process encrypted restore is not process-crash recovery, durable old-snapshot
protection or a production encrypted wallet. Holder blind preparation recovery,
independent clients, first-contact permits, first reversed accounting, local
block/decline integration and group fanout remain separate. In particular, an
ordinary continuation-text check must not be described as proving correct
first-reply accounting. No live phone/payment provider, passkey bootstrap, mobile
runtime, network transport, delivery/read proof or participation policy is
selected by this harness.
