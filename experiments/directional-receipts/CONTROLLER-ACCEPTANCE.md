# First controller slice: shared accounting store

**Outline only; no implementation, tests or policy selection.** This would cover
a bounded part of the [controller study](../../studies/directional-accounting-controller.md):
a sealed cohort catalog shares one origin rule epoch, aggregate caps, initial funding,
one-epoch rollover and settlement. Ratio-based maturity, rolling imbalance,
first-reply exceptions and the final controller remain later increments.

## Store and internal API

Existing ledgers hide separate `DatabaseSync`/`BEGIN IMMEDIATE` closures. Sharing
a filename, wrapping public methods or adding callbacks cannot combine them.

Propose one owned `openAccountingStore(path, trustedClock)`. Each instance owns
one connection and synchronous `write(tx => ...)`. Internal adapters cannot open
connections, nest transactions or outlive the callback. Reject asynchronous
callbacks; revoke ports after commit/rollback. Independent instances serialize
through SQLite's write lock.

| Proposed trusted API | Boundary |
|---|---|
| `defineOrigin(config)` | Seal a bounded cohort/key/deadline catalog, community, rule epoch, policy snapshot, A/B caps, permit context, `n`, base grant `g`, and carry cap `C`. Tests use two cohorts; the store does not hardcode two. |
| `receiptPort(cohortId)` | Provide the existing ledger interface through shared transactions; preserve real cvld/signature/Semaphore/blind-RSA verification. |
| `permitPort(contextId)` | Implement the real permit issuer's ledger interface; reservation and exact cached blind response commit together. |
| `fundInitial(proof, origin)` / `rollover(proof, nextOrigin)` | Verify account permission, then atomically consume its authorization, fix an allocation and advance the funding frontier. |
| `settleAndPrune(origin)` | Freeze final origin totals and funding summaries before deleting any dependent source rows. |

The cvld eligibility `policyDigest` remains distinct from the digest of the
complete immutable numerical-rule snapshot. Quota changes never reset identity.

Ports call `tx.receipts`/`tx.permits` inside a store transaction. Funding uses
`tx.permits.allocate`, avoiding nested issuer calls. Extract storage operations;
preserve real crypto.

Add a narrow experimental `verifyAllocationProof`: use pinned cvld
`verifyAdmission` and maintained Node Ed25519 `verify` against the grant's chat
key. Require a separate `cfrm.allocation.authorize.v1` signature binding operation,
community, eligibility policy, rule snapshot, origin, own member ID, nonce and
bounded issue/expiry times. Atomically commit its nonce/request fingerprint,
allocation and frontier after rechecking time/context. Exact retries recover
unchanged; changed proofs cannot reuse a nonce for another operation or origin.
A copied admission or account string is insufficient; test real signed proofs,
not a fabricated verified-subject brand. Issuer `allocate` stays internal to
trusted rules. Existing receipt-specific cvld/own-account verification is unchanged.

## Transaction and epoch rules

Within receipt commit: check trusted time, find an exact committed retry, then
check aggregate origin caps before mutations. Initially derive A/B totals by
joining existing cohort counters to the immutable mapping; do not maintain a
second mutable counter copy. Counter increments, nullifier/serial consumption,
cached result and cap enforcement share one transaction. Repeat validity and
allowance checks under the lock after asynchronous crypto. Preserve the corrected
permit allocation/issuance lock-time expiry contract.

Phases remain separate. Exact recovery preserves response/deadline: sender
recovery may outlive its checkpoint; receiver recovery requires current own-account
authorization. Add no shared nonce, provenance field or sender/recipient join.

Initial `n` is granted once per stable account despite policy changes,
reconnection or key rotation. Rollover waits for the previous permit issuance
window to close. Under the lock, read its immutable quota `Q` and final issuance
count `I`, create `Qnext = min(C, Q - I + g)`, and advance the frontier idempotently.
Base grants here select no maturity policy. Issued permits expire, never carry;
silence, decline and claimed loss earn no refund. Missed epochs cannot bypass `C`.

Late redemption updates its origin, never an opened successor allocation. Seal
the catalog initially; settle after every cohort's redemption deadline, with
grace shorter than one epoch. Before cascading deletion, persist final A/B totals
and quota/issued summaries needed by an unfunded successor. Retain funding and
settlement frontiers, clock/retirement floors and lifetime nullifiers. Settlement
awards no maturity yet; pruning must preserve its future inputs.

## Future fail-first cases

Use maintained Node crypto and actual cvld/enrollment fixtures; native identity
continuity already has [45-case evidence](README.md). Proposed cases:

1. **Fixed shared origin.** Register two independently keyed cohorts; reject
   remapping, changed policy/caps/deadlines or a third late cohort. Their counters
   consume one aggregate cap, including across restart.
2. **Last-unit races.** Competing real operations through separate connections
   reach the combined A or B cap once. Exact retries still recover at exhaustion;
   a changed proof/request consumes neither another counter nor nullifier.
3. **Atomic recovery.** Inject before/after-commit interruption for issuance and
   redemption. Reopening shows either no mutation or the exact cached result,
   never a counter/replay/cap split or duplicate debit.
4. **One initial allocation.** Concurrent verified funding and exact retry grant
   `n` once; rotation/reconnection/policy changes cannot reset it. Rejected account
   signatures, copied grants and wrong-origin proofs create no allocation through
   the actual cvld/Ed25519 verifier.
5. **Rollover versus issuance.** Race final permit issuance with rollover/retirement;
   count committed issuance once, reject expired work under the lock, and bound
   unissued carryover by `C`. Reopen/retry without a second grant or refund.
6. **Late settlement and pruning.** Redeem during the longer cohort's grace after
   successor funding. Preserve origin attribution and the fixed successor quota;
   reject premature settlement/pruning and clock rollback. Final summaries survive
   pruning and remain sufficient for later funding.
7. **Consent and privacy limits.** An exhausted receiver can refuse redemption
   after a sender debit without refund. Inspect actual service inputs/rows for
   new cross-phase joins. Permits and maliciously designated receipts remain
   poolable; a quota is not a strict outreach limit under one visible identity.
   No asserted `reply=true` bypass or free first-reply integration is claimed.
8. **Transaction capability lifetime.** Returning a promise after tentative writes
   rolls everything back. Retained transaction ports reject after commit and
   rollback; delayed continuation cannot mutate a later transaction.
