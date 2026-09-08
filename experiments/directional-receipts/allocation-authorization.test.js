import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyAllocationProof } from './allocation-authorization.js';
import { allocationFixture, verifiedClaims, NOW, nonce, keys, raw, b64, hash } from './allocation-fixtures.js';

async function accepted(f, proof = f.proof(), changes = {}) {
  assert.deepEqual(await verifyAllocationProof(f.options(proof, changes)), verifiedClaims(proof));
  return proof;
}

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

async function duringAdmission(options, change) {
  const entered = deferred();
  const release = deferred();
  const actual = options.verifyAdmission;
  const pending = verifyAllocationProof({ ...options, verifyAdmission: async args => {
    const result = await actual(args);
    entered.resolve();
    await release.promise;
    return result;
  } });
  try {
    await Promise.race([entered.promise, pending.then(() => {
      throw new Error('Verifier returned without awaiting actual admission verification');
    })]);
    change();
    release.resolve();
    return await pending;
  } finally {
    release.resolve();
    await pending.catch(() => {});
  }
}

test('actual cvld and certified-key proofs authorize precisely initial or rollover claims', async () => {
  const f = allocationFixture();
  await accepted(f);
  const proof = { grant: f.grant(), authorization: f.authorization({ operation: 'rollover', origin: 'rule-epoch-2' }) };
  await accepted(f, proof, { expected: { ...f.expected, operation: 'rollover', origin: 'rule-epoch-2' } });
});

test('a copied admission, absent signature or other account key cannot authorize funding', async () => {
  const f = allocationFixture();
  await accepted(f);
  const proof = f.proof();
  for (const candidate of [
    { grant: proof.grant },
    { ...proof, authorization: { ...proof.authorization, signature: '' } },
    { ...proof, authorization: f.authorization({}, keys().privateKey) },
    { ...proof, authorization: f.authorization({ memberId: nonce() }) },
    { ...proof, grant: f.grant({ memberId: nonce() }) },
    { ...proof, grant: f.grant({ chatPublicKey: b64(raw(keys().publicKey)) }) },
  ]) assert.equal(await verifyAllocationProof(f.options(candidate)), null);
});

test('the signature binds operation, community, eligibility, rule configuration and origin separately', async () => {
  const f = allocationFixture();
  await accepted(f);
  for (const change of [{ operation: 'rollover' }, { communityId: 'another.example' },
    { policyDigest: hash('other-eligibility') }, { ruleConfigDigest: hash('other-rules') },
    { origin: 'rule-epoch-2' }]) {
    // These are genuine signatures, but not permission for the trusted context.
    const proof = { grant: f.grant(), authorization: f.authorization(change) };
    assert.equal(await verifyAllocationProof(f.options(proof)), null);
  }
  const swapped = { grant: f.grant(), authorization: f.authorization({
    policyDigest: f.expected.ruleConfigDigest, ruleConfigDigest: f.expected.policyDigest }) };
  assert.equal(await verifyAllocationProof(f.options(swapped)), null);
});

test('another signing purpose or tampered signed nonce/time is rejected', async () => {
  const f = allocationFixture();
  await accepted(f);
  const wrongPurpose = { grant: f.grant(),
    authorization: f.authorization({}, f.member.chat.privateKey, 'cfrm.directional.authorize.v1') };
  assert.equal(await verifyAllocationProof(f.options(wrongPurpose)), null);
  for (const change of [{ nonce: nonce() }, { expiresAt: NOW + 59 }, { issuedAt: NOW - 1 }]) {
    const proof = f.proof();
    Object.assign(proof.authorization, change);
    assert.equal(await verifyAllocationProof(f.options(proof)), null);
  }
});

test('admission issuer pins, admission signatures and current admission context are required', async () => {
  const f = allocationFixture();
  await accepted(f);
  const proof = f.proof();
  assert.equal(await verifyAllocationProof(f.options(proof, { trustedPublicKey: Uint8Array.from(raw(keys().publicKey)) })), null);
  for (const grant of [f.grant({}, keys().privateKey),
    f.grant({ issuerKeyId: nonce() }), f.grant({ communityId: 'another.example' }),
    f.grant({ policyDigest: hash('other-eligibility') }),
    f.grant({ issuedAt: NOW - 60, expiresAt: NOW }),
    f.grant({ issuedAt: NOW + 1, expiresAt: NOW + 600 })]) {
    assert.equal(await verifyAllocationProof(f.options({ ...proof, grant })), null);
  }
});

test('only bounded canonical fields and an explicit trusted verifier configuration are accepted', async () => {
  const f = allocationFixture();
  const proof = await accepted(f);
  for (const candidate of [null, [], { ...proof, account: 'untrusted' },
    { ...proof, grant: { ...proof.grant, extra: 'forbidden' } },
    { ...proof, authorization: { ...proof.authorization, extra: 'forbidden' } },
    { ...proof, authorization: { ...proof.authorization, signature: proof.authorization.signature + '=' } },
    ...[{ nonce: 'AA' }, { nonce: proof.authorization.nonce + '=' }, { memberId: 'AA' },
      { origin: '' }, { origin: 'x'.repeat(129) }, { origin: 'époch' }, { operation: 'refund' },
      { ruleConfigDigest: 'AA' }, { issuedAt: NOW + 0.5 }, { expiresAt: Infinity }]
      .map(change => ({ ...proof, authorization: f.authorization(change) })),
  ]) assert.equal(await verifyAllocationProof(f.options(candidate)), null);
  for (const expected of [{ ...f.expected, authorizationSeconds: 0 },
    { ...f.expected, authorizationSeconds: undefined },
    { ...f.expected, authorizationSeconds: 301 }, { ...f.expected, origin: '' },
    { ...f.expected, ruleConfigDigest: 'AA' }]) {
    assert.equal(await verifyAllocationProof(f.options(proof, { expected })), null);
  }
  for (const changes of [{ verifyAdmission: undefined }, { clock: undefined },
    { trustedPublicKey: new Uint8Array(31) }, { expected: undefined }]) {
    assert.equal(await verifyAllocationProof(f.options(proof, changes)), null);
  }
  assert.equal(await verifyAllocationProof(null), null);
  assert.equal(await verifyAllocationProof({}), null);
});

test('authorization times are positive, current, bounded and contained in admission validity', async () => {
  const f = allocationFixture();
  await accepted(f);
  for (const changes of [{ issuedAt: 0 }, { issuedAt: NOW + 1 },
    { issuedAt: NOW - 60, expiresAt: NOW }, { expiresAt: NOW },
    { expiresAt: NOW + 91 }, { issuedAt: NOW - 1, expiresAt: NOW + 60 }]) {
    const proof = { grant: f.grant(), authorization: f.authorization(changes) };
    assert.equal(await verifyAllocationProof(f.options(proof)), null);
  }
  const beyondGrant = { grant: f.grant({ expiresAt: NOW + 30 }), authorization: f.authorization() };
  assert.equal(await verifyAllocationProof(f.options(beyondGrant)), null);
  assert.equal(await verifyAllocationProof(f.options(f.proof(), { clock: () => NaN })), null);
});

test('authorization and grant validity are rechecked after asynchronous admission verification', { timeout: 10_000 }, async () => {
  const f = allocationFixture();
  await accepted(f);
  const proof = f.proof();
  assert.equal(await duringAdmission(f.options(proof), () => f.advance(NOW + 60)), null);
  f.advance(NOW);
  const shortGrant = { grant: f.grant({ expiresAt: NOW + 30 }),
    authorization: f.authorization({ expiresAt: NOW + 30 }) };
  assert.equal(await duringAdmission(f.options(shortGrant), () => f.advance(NOW + 30)), null);
});

test('async verification uses immutable proof, expected-context and issuer-pin snapshots', { timeout: 10_000 }, async () => {
  const f = allocationFixture();
  await accepted(f);
  const options = f.options();
  const expectedResult = verifiedClaims(structuredClone(options.proof));
  const result = await duringAdmission(options, () => {
    options.proof.authorization.operation = 'rollover';
    options.proof.authorization.origin = 'changed-origin';
    options.proof.authorization.memberId = nonce();
    options.proof.grant.chatPublicKey = b64(raw(keys().publicKey));
    options.proof.grant.expiresAt = NOW;
    options.expected.origin = 'changed-origin';
    options.expected.ruleConfigDigest = hash('changed-rules');
    options.expected.authorizationSeconds = 1;
    options.trustedPublicKey.fill(0);
  });
  assert.deepEqual(result, expectedResult);
});

test('stateless verification does not consume a nonce, assign quota or change the funding frontier', async () => {
  const f = allocationFixture();
  const proof = await accepted(f);
  await accepted(f, proof);
  const sameNonceNewIntent = { grant: f.grant(),
    authorization: f.authorization({ nonce: proof.authorization.nonce, operation: 'rollover', origin: 'rule-epoch-2' }) };
  // Both proofs can be authentic. Only the controller can atomically reject a
  // consumed nonce or already-funded account; this verifier has no such state.
  await accepted(f, sameNonceNewIntent, { expected: { ...f.expected, operation: 'rollover', origin: 'rule-epoch-2' } });
});
