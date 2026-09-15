# Durable accounting storage experiment

**Experimental storage boundary; synthetic genesis; production admission unchanged.**

`verify.mjs` verifies the actual browser proofs and independently pins their
community, named owner, scheme, circuit/key, checkpoint and time before calling
`ledger-contract.mjs`. The ledger receives immutable public statements and
digests of the exact proof bytes and canonical public inputs. It receives no
private witness. Its constructors are trusted verifier helpers, not proof
verification or public authorization APIs.

`ledger.mjs` uses Node's built-in SQLite module with WAL and `synchronous=FULL`.
One `BEGIN IMMEDIATE` transaction compares the previous commitment and version,
consumes an owner-specific marker, stores the successor and caches the exact
acceptance response. Each request has an independently random identifier and a
digest binding its complete statement, expected version and proof digest.
Re-randomizing a proof changes that request. Exact retries return the stored
response bytes; mutations under the same ID and replay under a new ID fail.
The cached response is an unsigned experimental storage result, not a production
operator certificate or a private peer reservation proof.

The focused contract uses both actually verified statements. Independent worker
processes race two requests for the same verified successor. It also checks
reopening, a worker exiting after commit but before replying, and a SQL write
fault between marker insertion and account update. Mutated scope, version,
marker and digest inputs are explicitly storage-boundary fault tests, not claims
that those mutations passed cryptographic verification. The race does not
produce two distinct cryptographically valid successor proofs.

Startup and each mutation check a durable clock high-water value and bounded
versions. The clock is the existing synthetic receipt time supplied by the
verifier; no product timeout or clock policy is added. An already accepted exact
request remains retrievable later. The current proof ABI has no ledger version;
the version comparison is a storage guard alongside its proved old commitment.

Each account starts once from its **synthetic pre-reserved commitment**. There is
no proved genesis, reservation, balance issuance, dual-party release, refill,
reward or policy migration. The owner/community/scheme/circuit/checkpoint scope
is immutable in this fixture; real checkpoint, key and policy evolution needs
continuity rather than another seed. Production `resolve_private` remains
unsupported.

Crow **9/42**, source `0ef6fb410ad356ff483be49b7da45da3be9ed623`,
passed all 37 storage checks alongside actual browser proofs and independent
verification. This demonstrates the tested local transaction and process-restart
behavior. It does not establish distributed consensus, power-loss durability,
honest storage administrators or protection against restoring an entire old
database. The temporary ledger is deleted after the contract; only its labeled
public test results enter the report. Browser memory samples exclude these
Node storage tests, which run after browser proving has completed.
