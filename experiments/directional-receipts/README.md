# Directional receipt composition experiment

**Tested experimental implementation; unselected as a participation policy.** This
experiment composes real Semaphore proofs and RFC 9474 blind RSA into the two
operations proposed in [the directional accounting study](../../studies/directional-blind-receipts.md).
It does not implement a participation controller or change cfrm's shipping APIs.

The separate [stateless allocation-authorization verifier](ALLOCATION-AUTHORIZATION.md)
passes all ten tests at `d0a38fa9fdfd0a1adcffb6da33a7dfe12bcd8459`
([Crow 9/25](https://crow.corbet.ch/repos/9/pipeline/25)). It checks actual cvld
admission and certified-key permission for an initial or rollover request, binding
eligibility policy and immutable rule configuration separately. This result does
not consume a nonce or fund an allocation; those effects belong to the future
controller transaction. The linked contract records the exact fail-first run,
wire format and scope independently of the receipt/MLS suites below.

The new [release-attestation tests](attestations.test.js) reached 16 intended
failures at `907616cde9224d1be8b2f49ac2c68f269f555fc3`, while all 22 raw cases
passed. The implementation now passes all 38 cases at
`fdf739e3fdc40aedbc61a552d41b9fc83623f8b4`: 22 raw cases plus 16 release-attestation
cases using the same internal verification and ledger transactions. `npm test` runs both suites;
`npm run test:receipts` runs the raw baseline and `npm run test:attestations` runs
the release-attestation cases.

The combined run now passes **45 cases** at cfrm
`82f824c1d26e37d89f946728dab98b36a76612b1`, using native cmsg
`7c6740369cf17779c2b749547adfbca92b899f34` and cvld
`c416d9edd6f7f7259d84b88838b8e607b2166671` (Crow 9/21): the same 38 baseline
cases, four bridge-process cases and three actual counter/MLS composition cases.
The native source checks, locked build and formatting check also passed. The
composition uses the same two actual native member keys throughout enrollment,
account authorization and authenticated MLS release; its scope is detailed below.

`authorizeAndAcknowledge` accepts a purpose-bound, certified-key authorization
from the named sender and a proof by another enrolled qualified identity. One
SQLite transaction must consume the sender nonce and lifetime directed nullifier,
increment `authorizedSend`, and retain the exact blinded response for recovery.
`redeemAcknowledgedReceipt` requires a current admission and that receipt owner's
own purpose-bound signature; its transaction increments `acknowledgedReceive`
and consumes the receipt exactly once. Successful identical redemption retries
return `true`, including after restart, without another counter increment.

Neither counter proves text delivery, reading or sincere conversation. This
boundary alone allows a recipient to omit redemption. The separately tested
[sender-side content release gate](https://github.com/corbet-labs/cmsg/blob/main/studies/first-contact-release-gate.md)
withholds the honest sender's first MLS content until both actual counter
statements verify. This conditional result neither proves reading nor enforces a
dishonest sender. The boolean raw redemption result is an experimental
API, not a frozen public contract. The separate release service returns signed
counter statements; the bounded cmsg composition below does not select a final
participation policy or integrate every first-contact rule.

## Reproduce

Use an existing Node 24 CI worker. The independent fixture imports the pinned
cvld admission module through `CVLD_ADMISSION_MODULE`; use the same verified cvld
source archive as the private-reciprocity experiment. No live factors, payment
providers or user secrets are involved.

```sh
npm ci --prefix experiments/private-reciprocity --ignore-scripts --no-audit --no-fund
npm run artifacts --prefix experiments/private-reciprocity
npm ci --prefix experiments/directional-receipts --ignore-scripts --no-audit --no-fund
CVLD_ADMISSION_MODULE="$PWD/.dependencies/cvld/src/admission.js" npm test --prefix experiments/directional-receipts
```

Dependencies: `@cloudflare/blindrsa-ts` 0.4.6, Semaphore group/identity/proof
4.14.3 and `ffjavascript` 0.3.1. The fixture verifies the existing pinned depth-7
Semaphore 4.13.0 artifact sizes and hashes before executing them. It enrolls 17
synthetic members through actual signed cvld admissions and the existing
certified-chat-key plus Semaphore-identity possession protocol. Every membership
proof uses all 16 qualified identities other than the named sender. Signed cvld
admission fixtures do not establish a live independent factor provider.

The lockfile combines previously pinned package entries from the two primitive
experiments and installs successfully with remote `npm ci`. No local dependency
installation, build or test has been performed.

The SQLite schema is disposable experiment state. The release service adds
cached responses and a recipient/release-nonce index to the spend table; existing
databases from the earlier schema are not migrated. Start this version with a
fresh experiment database. No existing database is automatically deleted.

## Test boundary

The original 21 cases reached their intended stub failures on Crow at source
`b53c9095f84e2a5056bd8adcb1403ef6e7e16c39`. At
`3f3f75c5e29741f4260f4b36b94c19fe4634e1d2`, all 21 original cases passed and the
new twenty-second case failed with a missing expected rejection: a configured
same-algorithm private key did not match the advertised cohort modulus. The
binding check compares the private key's public parameters through maintained
SubtleCrypto before proof/signing work or a sender debit. All 22 tests pass at
`207a8df6e767bda9523da531682425d4b879470c` on the existing Node 24 CI worker.
This verifies the two raw counter operations, not the proposed signed release
attestations, a participation controller or network composition.

The cases cover actual distinct-membership proofs, own-account authorization,
cross-connection replay, transactional fault injection, lost response recovery
after checkpoint expiry, lifetime scopes across cohort keys, honest reverse
actions, delayed/omitted receive recording, expiry and durable pruning floors,
separate-purpose RSA keys, named sender quotas and explicit wire/state joins.
Pre/post-commit fault hooks inject application interruption; they do not simulate
power loss or certify filesystem crash durability.

Malicious preparation of a receipt for the sender is expected to **succeed**.
Three colluders can concentrate all `k(k−1) = 6` receipts on one account, despite
each member having only `k−1 = 2` direct outbound events within that group.
Separately authorized outside senders can enlarge that pool. Replaying a directed
pair across new checkpoints or cohort keys must still fail. These are affirmative
attack demonstrations, not rejection tests that pretend hidden recipient/prover
equality is proven.

The 99-redemption-attempt test uses repeated attempts by the 17 admitted fixture
members; it is not a 100-member capacity benchmark. The wire/SQLite inspection
only checks explicit joins. One issuance followed by one redemption still leaves
one timing candidate, regardless of a 16-member membership anonymity set. No
anonymity transport, batching, policy optimum or mobile behavior is tested here.

## Exact experimental contract

The cohort is trusted operator configuration shared by everyone: community,
policy, cohort ID, validity times and a 3072-bit RSA public key. Issuance accepts
new actions in `[notBefore, issueUntil)`; receipt redemption and recovery remain
open until `redeemUntil`. An old cohort never becomes a new cohort's balancing
credit. Separate purposes and separate cohorts require independently generated
signing keys; a hidden label under a shared signing key is insufficient isolation.

The randomized RSA message is 128 bytes: RFC 9474 randomized prefix (32), fixed
cohort domain digest (32), account ID (32), random serial (32). The domain digest
commits to the complete shared context and RSA modulus. `fixtures.js` constructs
these wire values independently of the service under test; it is not a production
client or encrypted recovery adapter.

The sender authorization signs a canonical array of purpose-domain, community,
policy, cohort, sender ID, hash of the blinded request, random nonce and bounded
issue/expiry times. The Semaphore message commits to that authorization including
its signature and the complete signed checkpoint digest. Its scope reuses
`cfrm.ack.scope.v1` plus community and named sender only. No epoch or action role
appears in this lifetime scope. The whole current signed checkpoint and certified
sender commitment binding are required; caller subsets are forbidden.

The receive authorization signs its own distinct purpose-domain, community,
policy, cohort, member ID, receipt hash, random nonce and bounded issue/expiry
times. This is explicit permission for the one receipt debit. There is no sender
ID, issuance nonce, request hash or proof nullifier in the redemption payload.

Exact issuance request replays recover the committed response without requiring
the old checkpoint to be current. A different proof under the same authorization
is not an exact retry and cannot consume its nullifier. New acceptance requires
current sender admission and checkpoint, valid proof and own signature; final
transaction checks repeat time and quota checks after asynchronous verification.
The trusted ledger retains nonce/request/response recovery data until cohort
retirement, serial spends until expiry, and per-account cohort counters until
cohort retirement. It also retains a durable time/retirement floor, lifetime
directed nullifiers, and signing-key/configuration fingerprints. Pruning does not
erase those lifetime markers or make old cohorts acceptable after rollback. Key
reuse detection covers contexts registered in this ledger; independent systems
must separately configure different purpose keys.

Exact recovery compares the complete structurally canonicalized request: object
key ordering is immaterial, but changing the proof is not an identical retry.
Receive retries still require a current admission and a current receipt-specific
owner signature. If that short authorization expired, the owner may freshly sign
for the same receipt while its shared cohort remains open; no second counter
increment follows. This bool result does not provide a cached signed release
attestation. Pending operation limits apply per service instance, so a future
network adapter must also bound total workers and ingress bytes before parsing.

`fault` is a trusted test-only synchronous hook at `issue-before-commit`,
`issue-after-commit`, `receive-before-commit` and `receive-after-commit`. Before
commit means after tentative writes but within the transaction; after commit
means before returning a result. No hook is supplied by network clients.

The [counter-backed release increment](ATTESTATION-ACCEPTANCE.md) uses a distinct
160-byte receipt format and a new RSA key shared across that release cohort, with an independently generated
operator signing key for each statement purpose. The service caches each exact
signed result in its corresponding debit transaction and limits one debit per
recipient/release nonce. It preserves the first attested chat key and common
expiry during recovery. The 16 new cases use real enrollment, proof and blind-RSA
fixtures and pass alongside all 22 raw cases. Their independent Node verifier
checks the exact cmsg canonical arrays. The additional composition below provides
the Rust/MLS round trip; first-contact permit integration remains separate.

The reviewed [actual-member composition harness](COMPOSITION-OUTLINE.md) implements
the bounded check using two native cmsg member keys throughout enrollment,
account authorization and actual MLS release. Its [three executable contracts](composition.test.js)
and [Node driver](composition-driver.js) reached all three intended rejecting
native `prepareRelease` failures at cfrm
`2f60fb8aabd87399d5c444569531babf909ac898`, using native cmsg
`7395344a12a54711e84581edecd2340908db1e87` (Crow 9/18: 38 baseline passes,
3 intended composition failures). All three then passed in the 45-case run at
`82f824c1d26e37d89f946728dab98b36a76612b1` with native
`7c6740369cf17779c2b749547adfbca92b899f34` (Crow 9/21: 45 passes, 0 failures).
Each case first enrolls the two actual native chat keys plus
15 synthetic filler members, publishes the complete qualified checkpoint, and
generates/verifies an actual sender-excluded qualification proof with 16 eligible
alternatives. The native sender signs private preflight, the recipient verifies
it, and each native key signs its own actual account authorization. Maintained
blind RSA and the real SQLite transactions
produce both counter attestations before the native gate releases its retained
MLS material. The real recipient joins, decrypts and checks the authenticated
sender's unchanged member ID. No native member private key or MLS payload leaves
the child.

The three passing cases cover counter-backed MLS release, rejection of
re-signed negative substitution witnesses followed by a valid retry, and local
encrypted pending restore with exact ledger-response recovery. Altered negative
statements are explicitly synthetic test witnesses; every successful release and
retry must use the untouched statements produced by committed ledger operations.
The native process owns both members only for this harness. The Node driver spans
synthetic holder/operator roles; it does not model an unaware production operator.
Encrypted restore occurs inside the existing child, with retained wrapping
material; it is not a process-crash or durable rollback test. This run includes
no live factor provider, passkey bootstrap, mobile runtime, Tor transport,
complete policy controller, first reversed accounting or first-contact permit
integration. Blind unblinding-state recovery and network anonymity remain separate.

Use the reviewed native `counter_bridge` executable from cmsg source
`7c6740369cf17779c2b749547adfbca92b899f34` to reproduce the passing run, with the
existing pinned Node dependencies/artifacts and cvld admission module. Supply its
absolute path explicitly; a missing executable fails rather than skipping or
substituting fixture signing keys:

```sh
CVLD_ADMISSION_MODULE="$PWD/.dependencies/cvld/src/admission.js" npm test --prefix experiments/directional-receipts
CVLD_ADMISSION_MODULE="$PWD/.dependencies/cvld/src/admission.js" CMSG_RELEASE_HARNESS="/absolute/path/to/counter_bridge" npm run test:composition --prefix experiments/directional-receipts
```

`npm test` keeps the 38-case baseline independent of the native executable.
`npm run test:all` runs those same 38 cases, the three composition contracts and
four focused bridge-process contracts when both environment variables are set.
JSON-lines exchanges are sequential,
bounded to 32 KiB and 30 seconds each, and raw native diagnostics are discarded.
Each composition case has a 240-second limit. CI reports only fixed diagnostics
and assertion outcomes. No local build, test or dependency installation was run.

The [bridge-process contracts](bridge.test.js) exercise the current shutdown
behavior with fully owned, temporary synthetic Node children. A clean final
response/exit is the control. A nonzero exit, signal or malformed trailing output
after that same successful response must still make shutdown fail. These four
new cases produced the expected fail-first result at
`0ca6601d9a82b8b1de70b8899f234b3c43943eca`: the clean control passed and all three
terminal-failure cases failed with a missing expected rejection (Crow 9/19:
1 pass, 3 failures). All four cases pass at
`51e2df53e475cd57c5c481a9cac237421ac8e890` (Crow 9/20: 4 passes, 0 failures).
The fix retains the actual exit status and any late protocol failure, awaits the
owned child's closure, and shares the same result with repeated shutdown calls.
After a one-second graceful shutdown deadline it force-terminates the exact
owned child and still waits for closure before cleanup. This focused result
establishes the process boundary; the separate three-case result above establishes
the bounded native MLS composition. The process contracts run without RSA/proof
generation or a native executable, using the
same installed packages and pinned admission-module import:

```sh
CVLD_ADMISSION_MODULE="$PWD/.dependencies/cvld/src/admission.js" npm run test:bridge --prefix experiments/directional-receipts
```
