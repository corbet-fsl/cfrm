# Stateless allocation authorization

The experimental [`verifyAllocationProof`](allocation-authorization.js) verifies
permission from a currently admitted account to request initial funding or a
rollover. It returns validated claims or `null`. It does not fund an allocation,
consume a nonce or prove that a request has not already been used.

## Fixed contract

```js
await verifyAllocationProof({
  proof: { grant, authorization },
  expected: {
    operation, communityId, policyDigest, ruleConfigDigest, origin,
    authorizationSeconds,
  },
  trustedPublicKey, clock, verifyAdmission,
});
```

`grant` is the existing signed cvld admission. `authorization` has exactly
`operation`, `communityId`, `policyDigest`, `ruleConfigDigest`, `origin`,
`memberId`, `nonce`, `issuedAt`, `expiresAt` and `signature`. The admitted chat
key signs the UTF-8 bytes of this JSON array, with no trailing placeholder:

```text
["cfrm.allocation.authorize.v1", operation, communityId, policyDigest,
 ruleConfigDigest, origin, memberId, nonce, issuedAt, expiresAt]
```

Operation is `initial` or `rollover`. Community and origin use
`[A-Za-z0-9._:/-]`, with 1–128 characters. Digests, member ID and nonce are
canonical unpadded base64url encodings of 32 bytes; the Ed25519 signature encodes
64 bytes. Times are positive safe integers. Authorization must be current,
contained in the admission interval and no longer than the explicitly configured
`authorizationSeconds`, which must be in 1–300.

The trusted expected context fixes the operation and origin. `policyDigest`
means cvld eligibility policy; `ruleConfigDigest` separately identifies the
immutable numerical-rule configuration. The controller must compute and pin that
digest from the complete canonical public configuration, rather than accepting
a requester-supplied digest as authoritative.

Proof, expected context and issuer pin are copied before asynchronous work.
Maintained Node Ed25519 verification checks possession of the certified chat key;
the pinned cvld verifier checks the admission. After awaiting verification,
trusted time and both validity intervals are checked again. Returned fields come
only from the snapshot: authorization claims without the signature, plus
`chatPublicKey`, `grantIssuedAt` and `grantExpiresAt`.

The future [controller store](CONTROLLER-ACCEPTANCE.md) owns atomic authorization
fingerprints, nonce consumption, allocation funding and epoch frontiers. It must
repeat time/context checks under its write lock. This stateless function can
accept authentic repeated-nonce proofs; successful verification alone is never
permission to grant another allowance.

## Executed evidence

[Crow 9/24](https://crow.corbet.ch/repos/9/pipeline/24), source
`a48eb60a136a61de7eab892b61996c465222e62d`, executed ten tests: zero passed and
ten failed at valid-fixture acceptance because the explicit stub returned
`null`. Fixtures used real-format signed admissions and authorizations; the
rejecting stub did not invoke cvld verification.

[Crow 9/25](https://crow.corbet.ch/repos/9/pipeline/25), source
`d0a38fa9fdfd0a1adcffb6da33a7dfe12bcd8459`, passes all ten unchanged tests with
zero failures. They exercise actual cvld verification and Node Ed25519, copied
grants and other keys, issuer/context/purpose substitutions, strict field and
time bounds, expiry across asynchronous verification, immutable snapshots and
explicitly stateless nonce reuse. They use synthetic identities and issuer keys;
no RSA, Semaphore, live factor provider or controller transaction is tested here.
The existing 38/45-case suites remain separate.

Run on an authorized Node 24 test runner, from the repository root, using the
independently verified cvld checkout:

```sh
CVLD_ADMISSION_MODULE="/absolute/path/to/pinned/cvld/src/admission.js" node --test --test-concurrency=1 experiments/directional-receipts/allocation-authorization.test.js
```
