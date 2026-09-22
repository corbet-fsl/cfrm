import { proveAccountCandidate, createAccountProver } from '../../../runtime/accounting/runtime.mjs';
import { Noir } from '@noir-lang/noir_js';
import { UltraHonkBackend, UltraHonkVerifierBackend } from '@aztec/bb.js';
import { OPTIONS, hex, unhex, random, sha, canonicalSignature, be, memberBytes } from '../common.mjs';
import { fieldBytes, FR_MODULUS } from '../hashes.mjs';
import { ACCOUNT_MODE, accountHashes, checkpointFromVerified, noirInput, receiptBytes, receiptDigest, ackBytes, SparseTree, policyDigest } from './hashes.mjs';
import { AccountWitness, statementBytes, publicInputValues, PUBLIC_INPUT_COUNT, validityHorizon } from './witness.mjs';
import { runPeerReservationContract } from '../peer-reservation/browser.mjs';

const ECDSA_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const highS = signature => {
  const result = signature.slice();
  result.set(be(ECDSA_ORDER - BigInt('0x' + hex(result.slice(32))), 32), 32); return result;
};
const uint = bytes => BigInt('0x' + hex(bytes));
const equal = (a, b) => hex(a) === hex(b);

export async function runAccountState({ api, circuit, manifest, verificationKey, post, bytes, metrics, assert, stage, releaseBackend }) {
  metrics.accountingMode = ACCOUNT_MODE;
  const configuration = await (await fetch('/test-config.json')).json();
  if (!['answer','close'].includes(configuration.accountScenario)) throw new Error('Explicit synthetic scenario required');
  metrics.accountScenario = configuration.accountScenario;
  const hashes = accountHashes(api); let policy = manifest.accountPolicy;
  if (!policy) throw new Error('No independently pinned account policy');
  if (policy.newcomerAdmissions > 16) throw new Error('Synthetic counter contract exceeds bounded execution; this is not a product limit');
  // Fixture scope and times, not product parameters. The native response must
  // agree and is retained separately by the trusted driver for verification.
  const community = await sha(new TextEncoder().encode('synthetic-community'));
  const holders = [];
  for (let i = 0; i < 2; i++) {
    const key = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign','verify']);
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key.publicKey));
    const secret = random(); holders.push({ key, raw: raw.slice(1), secret, secretHash: await hashes.secretHash(community, secret) });
  }
  stage('actual-cmsg-enrollment');
  const response = await post({ command: 'enroll', keys: holders.map(h => ({ accountKey: hex(h.raw), secretHash: hex(h.secretHash) })),
    peerExpires: configuration.accountScenario === 'answer' ? 200 : 10000 });
  assert(response.ok, 'actual cmsg root/device delegations accepted');
  const enrolled = response.value;
  assert(enrolled.community === hex(community) && enrolled.context.communityId === 'synthetic-community', 'actual cmsg fixture community is pinned');
  assert(enrolled.entries.length === 2 && enrolled.acceptedTimes.join(',') === '100,300,600', 'independent fixture roster and times');
  for (let i = 0; i < 2; i++) assert(enrolled.entries[i].accountKey === hex(holders[i].raw)
    && enrolled.entries[i].secretHash === hex(holders[i].secretHash), 'actual delegation binds browser key and secret ' + i);
  const verified = await post({ command: 'verify', delegations: enrolled.entries.map(e => e.originalDelegation) });
  assert(verified.ok && verified.value.entries.every((e, i) => e.delegationDigest === enrolled.entries[i].delegationDigest), 'Rust re-verifies original delegation digests');
  const alteredDelegations = structuredClone(enrolled.entries.map(e => e.originalDelegation));
  alteredDelegations[1].stateSecretCommitment = enrolled.entries[0].secretHash;
  assert(!(await post({ command: 'verify', delegations: alteredDelegations })).ok, 'Rust rejects changed registered secret');
  const checkpoint = await checkpointFromVerified(community, enrolled.entries, hashes);
  assert(enrolled.context.contact.initiatorId === enrolled.entries[0].memberId
    && enrolled.context.responderId === enrolled.entries[1].memberId, 'actual original sender and recipient are bound');
  const context = { nonce: Uint8Array.from(enrolled.context.introductionId), group: unhex(enrolled.groupBinding),
    contactPolicy: unhex(enrolled.contactPolicyDigest), openedAt: 100n };
  const gate = await post({ command: 'prepareGate' });
  assert(gate.ok, 'native cmsg prepares its own authenticated contexts and fresh peer challenges');
  context.expiresAt = BigInt(gate.value.outgoing.expected.expiresAt);
  const ledgerPost = async input => {
    const response = await fetch('/account-ledger', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input) });
    if (!response.ok) throw new Error('Real account ledger bridge request failed'); return response.json();
  };
  const acceptedStates = new Map(); metrics.peerReservations = [];
  const noir = new Noir(circuit);
  const rejected = async (input, label) => {
    let failed = false; try { await noir.execute(noirInput(input)); } catch { failed = true; }
    assert(failed, label);
  };
  const mutate = async (candidate, label, change) => { const input = structuredClone(candidate.input); await change(input); await rejected(input, label); };
  // Constraint-only counterexamples below use explicit synthetic checkpoints;
  // they never enter the native enrollment verifier, operator or proof report.
  async function constraintCheckpoint(changedIndex, changes, retainedIndices) {
    const entries = checkpoint.entries.map(entry => ({ ...entry }));
    Object.assign(entries[changedIndex], changes);
    const retained = entries.filter((_, index) => retainedIndices === undefined || retainedIndices.includes(index));
    const tree = await SparseTree.create(hashes.enrollmentNode);
    for (let index = 0; index < retained.length; index++) {
      const entry = retained[index]; entry.index = BigInt(index);
      entry.leaf = await hashes.enrollment(community, entry.member, entry);
      await tree.set(entry.index, entry.leaf);
    }
    return { root: tree.root, entries: retained.map(entry => ({ ...entry, path: tree.path(entry.index) })) };
  }
  const enrollmentInput = e => ({ key: e.key, secret_hash: e.secretHash, start: e.start, end: e.end,
    delegation_digest: e.delegationDigest, path: e.path, index: e.index });
  const setup = {};
  for (const record of manifest.setup) {
    const data = await bytes('/setup/' + record.name);
    assert(data.length === record.bytes && hex(await sha(data)) === record.sha256, 'pinned account setup ' + record.name);
    setup[record.name] = data;
  }
  await api.srsInitSrs({ pointsBuf: setup['g1.dat'], numPoints: manifest.numPoints, g2Point: setup['g2.dat'] });
  const backend = new UltraHonkBackend(circuit.bytecode, api), verifier = new UltraHonkVerifierBackend(api);
  async function prove(candidate, ownerIndex, label) {
    stage(label);
    const generated = await proveAccountCandidate({ noir, backend, verifier, verificationKey, candidate,
      scope: { circuitDigest: Array.from(unhex(manifest.circuitSha256)), verifyingKeyDigest: Array.from(unhex(manifest.vkSha256)) },
      maxProofBytes: 1024 * 1024 });
    const proof = { proof: unhex(generated.record.proof), publicInputs: generated.publicInputs };
    const { witnessMs, provingMs, verificationMs } = generated;
    assert(generated.record.proof.length > 0, label); // Shared production prover verified the generated proof.
    const expected = publicInputValues(candidate.statement);
    assert(proof.publicInputs.length === PUBLIC_INPUT_COUNT && expected.length === PUBLIC_INPUT_COUNT
      && proof.publicInputs.every((value, index) => BigInt(value) === expected[index]), 'exact v2 public encoding without private action/role/outcome');
    const original = enrolled.entries[ownerIndex].originalDelegation;
    const requestId = random(), issuedAt = candidate.statement.now;
    const expiresAt = Math.min(issuedAt + 100, candidate.statement.validUntil, original.admission.expiresAt, original.authorization.expiresAt);
    const authorized = await post({ command: 'authorize', owner: ownerIndex, requestId: hex(requestId),
      circuitDigest: manifest.circuitSha256, verifyingKeyDigest: manifest.vkSha256,
      statementDigest: hex(await sha(statementBytes(candidate.statement))), proofDigest: hex(await sha(proof.proof)),
      issuedAt, expiresAt });
    assert(authorized.ok, 'actual current cmsg device authorizes exact proof request ' + label);
    const alternate = await post({ command: 'authorize', owner: ownerIndex, requestId: hex(random()),
      circuitDigest: manifest.circuitSha256, verifyingKeyDigest: manifest.vkSha256,
      statementDigest: hex(await sha(statementBytes(candidate.statement))), proofDigest: hex(await sha(proof.proof)),
      issuedAt, expiresAt });
    assert(alternate.ok, 'independent request ID receives actual owner signature ' + label);
    const acceptance = await ledgerPost({ action: 'apply', record: { statement: candidate.statement,
      proof: hex(proof.proof), requestAuthorization: authorized.value.authorization } });
    assert(acceptance.ok, 'actual Rust ledger durably accepts the public proof while opening stays in browser: ' + label);
    acceptedStates.set(hex(candidate.statement.nextState), acceptance.value);
    metrics.proofs.push({ statement: candidate.statement, ownerIndex, proof: hex(proof.proof), publicInputs: proof.publicInputs,
      requestAuthorization: authorized.value.authorization,
      alternateRequestAuthorization: alternate.value.authorization,
      proofBytes: proof.proof.length, witnessMs, provingMs, verificationMs,
      verificationIncludesKeyGeneration: false });
    return candidate.next;
  }
  async function present(state, event, nativeContext, label) {
    const pin = manifest.peerReservation;
    if (pin?.mode !== 'peer-reservation-v3' || pin.publicInputs !== 389 || !pin.sharesAccountSetup
        || Number(pin.stats.numGatesDyadic) + 1 > manifest.numPoints) throw new Error('Pinned peer circuit/setup contract');
    const accountAcceptance = acceptedStates.get(hex(fieldBytes(state.commitment)));
    if (!accountAcceptance) throw new Error('No real acceptance for private opening');
    const ownEntry = checkpoint.entries.find(entry => equal(entry.member, state.owner.member));
    const device = enrolled.entries.find(entry => equal(memberBytes(entry.memberId), state.owner.member));
    if (!ownEntry || !device || !equal(memberBytes(device.originalDelegation.authorization.devicePublicKey), Uint8Array.from(nativeContext.devicePublicKey))) throw new Error('Native expected device differs from retained enrollment');
    const expected = { ...nativeContext.expected, ownerAuthority: Array.from(fieldBytes(ownEntry.leaf)), statePolicyDigest: Array.from(state.statePolicyHash),
      stateVersion: Number(state.version), stateCommitment: Array.from(fieldBytes(state.commitment)) };
    const result = await runPeerReservationContract({ api, state, event, accountAcceptance,
      circuitBytes: await bytes('/peer-reservation/circuit.json'), verificationKey: await bytes('/peer-reservation/vk.bin'),
      peerProofScope: { circuitDigest: Array.from(unhex(pin.circuitSha256)), verifyingKeyDigest: Array.from(unhex(pin.vkSha256)) },
      accountProofScope: { circuitDigest: Array.from(unhex(manifest.circuitSha256)), verifyingKeyDigest: Array.from(unhex(manifest.vkSha256)) },
      context: { now: nativeContext.now, expected, accountPolicy: policy, enrollmentRoot: Array.from(fieldBytes(checkpoint.root)) },
      verifyAccountAcceptance: async acceptance => {
        const checked = await ledgerPost({ action: 'verifyAcceptance', acceptance });
        return checked.ok && checked.value?.verified === true;
      }, assert, stage });
    assert(result.presentation.statement.phase === 2, 'only actual Active evidence enters the cmsg gate: ' + label);
    metrics.peerReservations.push(result); return result.presentation;
  }
  const genesis = [];
  for (let i = 0; i < 2; i++) genesis.push(await AccountWitness.genesis({ hashes, community, policy,
    checkpoint, ownerIndex: i, ownerSecret: holders[i].secret, now: 100 }));
  await mutate(genesis[0], 'genesis rejects unproved initial credit', async input => {
    const opening = structuredClone(genesis[0].next.opening); opening.available += 1n;
    input.next_state = fieldBytes(await genesis[0].next.commit(opening, 0n));
  });
  await mutate(genesis[0], 'genesis rejects a populated obligation map', async input => {
    const opening = structuredClone(genesis[0].next.opening);
    const inserted = await genesis[0].next.outgoing.insert(7n, 11n);
    opening.outgoingRoot = inserted.next.root; opening.outgoingCount = inserted.next.count;
    input.next_state = fieldBytes(await genesis[0].next.commit(opening, 0n));
  });
  await mutate(genesis[0], 'genesis rejects an existing-state shape', input => { input.previous_state = fieldBytes(genesis[0].next.commitment); });
  await mutate(genesis[0], 'proof cannot choose a contact-specific validity horizon', input => { input.valid_until += 1n; });
  await mutate(genesis[0], 'genesis cannot backdate maturity or the first refill before its accepted horizon', async input => {
    const opening = structuredClone(genesis[0].next.opening); opening.createdAt = 100n; opening.frontier = 100n;
    input.next_state = fieldBytes(await genesis[0].next.commit(opening, 0n));
  });
  await mutate(genesis[0], 'ACVM rejects coherent synthetic current enrollment expiring inside the proof horizon', async input => {
    const truncated = await constraintCheckpoint(0, { end: input.valid_until - 1n });
    input.enrollment_root = fieldBytes(truncated.root); input.owner_enrollment = enrollmentInput(truncated.entries[0]);
  });
  let sender = await prove(genesis[0], 0, 'proved sender lifetime genesis');
  let recipient = await prove(genesis[1], 1, 'proved recipient lifetime genesis');
  const outgoing = await sender.reserve({ peerIndex: 1, role: 0, ...context, now: 100 });
  await mutate(outgoing, 'reservation cannot inflate its configured amount', input => { input.slot.amount += 1n; });
  await mutate(outgoing, 'coherent outgoing reservation cannot backdate its fixed waiting period', async input => {
    input.slot.admitted_at = 99n; input.slot.expires_at = 599n;
    const changedSlot = structuredClone(outgoing.next.slots.get(outgoing.event.toString()));
    changedSlot.admittedAt = 99n; changedSlot.expiresAt = 599n;
    const changed = await outgoing.next.outgoing.update(outgoing.event, await hashes.obligation(outgoing.event, changedSlot, 1));
    const opening = structuredClone(outgoing.next.opening); opening.outgoingRoot = changed.next.root;
    input.next_state = fieldBytes(await outgoing.next.commit(opening, outgoing.next.version));
  });
  await mutate(outgoing, 'reservation cannot hide negative available credit', input => { input.old.available = 0n; });
  await mutate(outgoing, 'reservation rejects changed registered owner secret', input => { input.owner_secret = holders[1].secret; });
  await mutate(outgoing, 'insertion rejects append path from before predecessor update', input => {
    input.own_map.append_path = sender.outgoing.tree.path(sender.outgoing.count);
  });
  await mutate(outgoing, 'insertion rejects a truncated next pointer', input => { input.own_map.leaf[2] += 1n << 32n; });
  await mutate(outgoing, 'insertion rejects an exhausted append counter', input => { input.old.outgoing_count = 1n << 32n; });
  await mutate(outgoing, 'insertion rejects zero-key sentinel reuse', input => { input.own_map.leaf[0] = 1n; });
  await mutate(outgoing, 'enrollment rejects a noncanonical secret encoding', input => { input.owner_enrollment.secret_hash = be(FR_MODULUS, 32); });
  sender = await prove(outgoing, 0, 'proved outgoing reservation');
  sender = await sender.withEnrollment({ enrollment: checkpoint, expectedRoot: fieldBytes(checkpoint.root) });
  const checkpointLimits = { maxBytes: 65536, maxMapEntries: 64, maxSlots: 32 };
  const walletCheckpoint = sender.exportCheckpoint(checkpointLimits);
  sender = await AccountWitness.restoreCheckpoint({ checkpointBytes: walletCheckpoint, hashes: accountHashes(api),
    enrollment: checkpoint, ownerSecret: holders[0].secret, expectedStatement: outgoing.statement, limits: checkpointLimits });
  assert(equal(fieldBytes(sender.commitment), outgoing.statement.nextState),
    'private wallet checkpoint restores the exact real ledger-accepted reservation with production hashes');
  metrics.checkpointRecovery = { version: 1, storedBytes: walletCheckpoint.length,
    acceptedNextVersion: outgoing.statement.nextVersion, followingActivationProved: false, privateCheckpointExported: false };
  const activeSender = await sender.activate(outgoing.event, 100);
  await mutate(activeSender, 'activation cannot replace an obligation peer', input => { input.slot.peer = input.owner; });
  await mutate(activeSender, 'activation cannot change its original group', input => { input.slot.group[0] ^= 1; });
  await mutate(activeSender, 'payload update cannot alter linked pointers', input => { input.own_map.leaf[3] = 1n; });
  await mutate(activeSender, 'unknown action cannot refund a sender reservation', input => { input.action = 7; });
  sender = await prove(activeSender, 0, 'proved sender activation');
  metrics.checkpointRecovery.followingActivationProved = true;
  const outgoingPresentation = await present(sender, outgoing.event, gate.value.outgoing, 'original initiator');
  assert((await post({ command: 'authorizeIncoming', outgoingPresentation })).ok,
    'native cmsg independently verifies real Active outgoing proof before explicit incoming consent');
  const incoming = await recipient.reserve({ peerIndex: 0, role: 1, ...context, now: 100 });
  recipient = await prove(incoming, 1, 'proved incoming reservation');
  // A second pending obligation in the other role exercises one shared balance
  // and preservation of unrelated paths. No payload is released for this slot.
  const secondary = await recipient.reserve({ peerIndex: 0, role: 0,
    nonce: random(), group: random(), contactPolicy: context.contactPolicy, now: 100 });
  await mutate(secondary, 'both roles cannot use separate available balances', input => { input.old.available = BigInt(policy.initialCredit); });
  recipient = await prove(secondary, 1, 'proved second role shares available capacity');
  assert(recipient.opening.reserved === BigInt(policy.incomingReservation) + BigInt(policy.outgoingReservation), 'both role amounts remain reserved together');
  const activeRecipient = await recipient.activate(incoming.event, 100);
  recipient = await prove(activeRecipient, 1, 'proved recipient activation preserves other role');
  if (configuration.accountScenario === 'close') {
    recipient = await prove(await recipient.activate(secondary.event, 100), 1, 'proved independent outgoing slot activation for later abandonment');
  }
  const incomingPresentation = await present(recipient, incoming.event, gate.value.incoming, 'original recipient');
  const tuned = await ledgerPost({ action: 'tuneWaitingPeriod' });
  assert(tuned.ok && tuned.value.policy.abandonAfter === 900, 'actual operator tuning changes only future reservation waiting periods');
  const senderBeforeTune = sender.commitment, recipientBeforeTune = recipient.commitment;
  sender = await sender.withPolicy(tuned.value.policy); recipient = await recipient.withPolicy(tuned.value.policy);
  policy = tuned.value.policy;
  const adopted = await (await genesis[1].next.withPolicy(policy)).reserve({ peerIndex: 0, role: 1, ...context, now: 100 });
  await noir.execute(noirInput(adopted.input));
  assert(adopted.next.slots.get(adopted.event.toString()).expiresAt === 600n,
    'ACVM incoming reservation adopts the authenticated older lease after current waiting-period tuning');
  assert(sender.commitment === senderBeforeTune && recipient.commitment === recipientBeforeTune
    && sender.slots.get(outgoing.event.toString()).expiresAt === 600n
    && recipient.slots.get(incoming.event.toString()).expiresAt === 600n, 'live tuning preserves accepted openings and original shared expiry');
  let immutableRejected = false;
  try { await sender.withPolicy({ ...policy, policyRevision: policy.policyRevision + 1 }); } catch { immutableRejected = true; }
  assert(immutableRejected, 'waiting-period reload cannot reinterpret immutable economic policy or revision');
  assert((await post({ command: 'bindGate', outgoingPresentation, incomingPresentation })).ok,
    'native cmsg verifies original Active proofs after tuning and preserves their original release deadline');
  const secondaryRoot = recipient.outgoing.root;
  stage('actual-cmsg-' + configuration.accountScenario);
  // Answer retains the expired-sender acknowledgment case. In Close, the sender
  // has a longer genuine fixture authority so its deadline refund can be proved.
  const prepared = await post(configuration.accountScenario === 'answer' ? { command: 'answer' } : { command: 'close', now: 100 });
  assert(prepared.ok, 'actual durable cmsg recipient decision exists');
  const message = unhex(prepared.value.signingBytes);
  assert(message.length === 357, 'real cmsg receipt has exact versioned357 encoding');
  const resolution = { kind: message[347], issuedAt: uint(message.slice(349)), historyDigest: message.slice(283, 315),
    ed25519ReceiptDigest: message.slice(315, 347), signature: new Uint8Array(64) };
  const slot = recipient.slots.get(incoming.event.toString());
  assert(equal(message, receiptBytes(community, checkpoint.entries[1].member, checkpoint.entries[0].member,
    slot, checkpoint.entries[1].delegationDigest, resolution)), 'browser encoding matches real cmsg receipt authority and context');
  resolution.signature = canonicalSignature(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, holders[1].key.privateKey, message));
  const completeReceipt = { ...prepared.value.receipt, signature: Array.from(resolution.signature) };
  assert((await post({ command: 'verifyReceipt', receipt: completeReceipt, now: Number(resolution.issuedAt) })).ok, 'Rust verifies browser-signed actual cmsg receipt');
  let acknowledgment, completeAck;
  if (configuration.accountScenario === 'answer') {
    const preparedAck = await post({ command: 'ack', answer: completeReceipt });
    assert(preparedAck.ok, 'actual cmsg original sender acknowledges delivered answer');
    const ackMessage = unhex(preparedAck.value.signingBytes);
    const issuedAt = uint(ackMessage.slice(247));
    assert(ackMessage.length === 255 && equal(ackMessage, ackBytes(community, checkpoint.entries[0].member,
      checkpoint.entries[1].member, slot, await receiptDigest(message, resolution.signature),
      checkpoint.entries[0].delegationDigest, issuedAt)), 'browser encoding matches exact nested-answer acknowledgment');
    acknowledgment = { issuedAt, signature: canonicalSignature(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, holders[0].key.privateKey, ackMessage)) };
    completeAck = { ...preparedAck.value.acknowledgment, signature: Array.from(acknowledgment.signature) };
    assert((await post({ command: 'verifyAcknowledgment', acknowledgment: completeAck, now: 100 })).ok, 'Rust verifies browser-signed sender acknowledgment');
  }
  const senderAmount = BigInt(policy.outgoingReservation);
  if (configuration.accountScenario === 'answer') {
  const settledSender = await sender.settle(outgoing.event, resolution, undefined, 100);
  assert(settledSender.next.opening.available === sender.opening.available + senderAmount
    && settledSender.next.opening.reserved === sender.opening.reserved - senderAmount,
  'confirmed Answer returns the exact sender bond early');
  await mutate(settledSender, 'sender cannot self-sign a recipient resolution', async input => {
    input.resolution.signature = canonicalSignature(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, holders[0].key.privateKey, message));
  });
  await mutate(settledSender, 'settlement rejects high-S receipt signatures', input => { input.resolution.signature = highS(input.resolution.signature); });
  await mutate(settledSender, 'coherent successor cannot burn the refundable sender bond', async input => {
    const opening = structuredClone(settledSender.next.opening);
    opening.available -= senderAmount;
    input.next_state = fieldBytes(await settledSender.next.commit(opening, settledSender.next.version));
  });
  await mutate(settledSender, 'settlement cannot retain the resolved reservation amount', async input => {
    const opening = structuredClone(settledSender.next.opening); opening.reserved += senderAmount;
    input.next_state = fieldBytes(await settledSender.next.commit(opening, settledSender.next.version));
  });
  sender = await prove(settledSender, 0, 'proved outgoing confirmed-Answer refund');
  let secondDecisionRejected = false;
  try { await sender.settle(outgoing.event, { ...resolution, kind: resolution.kind === 1 ? 2 : 1 }, undefined, 100); }
  catch { secondDecisionRejected = true; }
  assert(secondDecisionRejected, 'settled Answer/Close cannot be replaced by a later decision');
  await mutate(settledSender, 'proved settled state rejects a freshly recipient-signed later decision', async input => {
    const later = { ...resolution, kind: resolution.kind === 1 ? 2 : 1 };
    const senderSlot = sender.slots.get(outgoing.event.toString());
    later.signature = canonicalSignature(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, holders[1].key.privateKey,
      receiptBytes(community, checkpoint.entries[1].member, checkpoint.entries[0].member,
        senderSlot, checkpoint.entries[1].delegationDigest, later)));
    const current = sender.input(random(), 100);
    input.old = current.old; input.new_blind = current.new_blind;
    input.previous_state = current.previous_state; input.previous_version = current.previous_version;
    input.next_version = current.next_version; input.slot.phase = 3;
    input.own_map = sender.outgoing.witness(sender.outgoing.find(outgoing.event)[0]);
    input.resolution.kind = later.kind; input.resolution.signature = later.signature;
    const opening = structuredClone(sender.opening); opening.blind = current.new_blind;
    input.next_state = fieldBytes(await sender.commit(opening, current.next_version));
  });
  assert((await post({ command: 'advance', now: 300 })).ok, 'native fixture advances its trusted test clock');
  } else {
    let rejectedClose = false;
    try { await sender.settle(outgoing.event, resolution, undefined, 100); } catch { rejectedClose = true; }
    assert(rejectedClose, 'genuine recipient Close cannot change the sender fixed refund date');
    const attempt = await sender.settle(outgoing.event, { ...resolution, kind: 1 }, undefined, 100);
    await mutate(attempt, 'circuit rejects genuine Close as an early outgoing refund', input => { input.resolution.kind = 2; });
    await mutate(attempt, 'circuit rejects genuine Close as an early outgoing burn', async input => {
      input.resolution.kind = 2;
      const opening = structuredClone(attempt.next.opening); opening.available -= senderAmount;
      input.next_state = fieldBytes(await attempt.next.commit(opening, attempt.next.version));
    });
    assert(sender.slots.get(outgoing.event.toString()).phase === 2 && sender.opening.reserved === senderAmount,
      'sender remains Active and reserved after recipient Close');
  }
  if (completeAck) {
    assert((await post({ command: 'verifyHistoricalAcknowledgment', acknowledgment: completeAck, now: 300 })).ok, 'native historical acknowledgment retains exact expired sender authority');
    assert(!(await post({ command: 'verifyAcknowledgment', acknowledgment: completeAck, now: 300 })).ok, 'current verifier does not silently authorize expired sender');
  }
  const pendingRecipient = recipient;
  const recipientSettlementTime = configuration.accountScenario === 'answer' ? 300 : 100;
  const settledRecipient = await recipient.settle(incoming.event, resolution, acknowledgment, recipientSettlementTime);
  await mutate(settledRecipient, 'historical self receipt cannot replace its reserved owner authority', input => {
    input.receipt_owner_enrollment.delegation_digest[0] ^= 1;
  });
  {
    const renewedKey = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign','verify']);
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', renewedKey.publicKey)).slice(1);
    const renewal = { key: raw, start: 200n, delegationDigest: random() };
    for (const retained of [undefined, [1]]) {
      const synthetic = await constraintCheckpoint(1, renewal, retained);
      const renewed = await recipient.withEnrollment({ enrollment: synthetic, expectedRoot: fieldBytes(synthetic.root) });
      const historicalSelf = await renewed.settle(incoming.event, resolution, acknowledgment, 300);
      await noir.execute(noirInput(historicalSelf.input));
      assert(true, retained ? 'ACVM-only renewed owner settles using original receipt/ACK after the peer leaves the current roster'
        : 'ACVM-only supported enrollment refresh retains real original self receipt and exact nested ACK authority');
    }
    metrics.historicalSelfRenewal = 'constraint-only supported context refresh, including removed peer; real old receipt; no native renewal interoperability claim';
  }
  assert(settledRecipient.next.opening.available === recipient.opening.available + BigInt(policy.incomingReservation)
    && settledRecipient.next.opening.reserved === recipient.opening.reserved - BigInt(policy.incomingReservation),
  'recipient actual Answer/Close restores exactly its own reservation');
  await mutate(settledRecipient, 'recipient settlement cannot silently burn its refundable capacity', async input => {
    const opening = structuredClone(settledRecipient.next.opening); opening.available -= BigInt(policy.incomingReservation);
    input.next_state = fieldBytes(await settledRecipient.next.commit(opening, settledRecipient.next.version));
  });
  await mutate(settledRecipient, 'settlement cannot change a saved historical peer', input => { input.slot.peer_authority += 1n; });
  await mutate(settledRecipient, 'coherent successor cannot mint extra available credit', async input => {
    const opening = structuredClone(settledRecipient.next.opening); opening.available += 1n;
    input.next_state = fieldBytes(await settledRecipient.next.commit(opening, settledRecipient.next.version));
  });
  await mutate(settledRecipient, 'coherent successor cannot erase other reserved credit', async input => {
    const opening = structuredClone(settledRecipient.next.opening); opening.reserved -= 1n;
    input.next_state = fieldBytes(await settledRecipient.next.commit(opening, settledRecipient.next.version));
  });
  await mutate(settledRecipient, 'settlement cannot discard another pending role', async input => {
    const opening = structuredClone(settledRecipient.next.opening); opening.outgoingRoot = genesis[1].next.outgoing.root; opening.outgoingCount = 1n;
    input.next_state = fieldBytes(await settledRecipient.next.commit(opening, settledRecipient.next.version));
  });
  await mutate(settledRecipient, 'settlement cannot reset its event marker', input => { input.settlement_marker[0] ^= 1; });
  await mutate(settledRecipient, 're-signed or reopened group cannot reuse old obligation', input => { input.slot.group[0] ^= 1; });
  if (acknowledgment) {
    await mutate(settledRecipient, 'authentic historical Answer cannot refund at the common deadline', input => {
      input.now = 600n; input.valid_until = validityHorizon(600, policy);
    });
    await mutate(settledRecipient, 'incoming answer cannot omit sender acknowledgment', input => { input.acknowledgment.signature.fill(0); });
    await mutate(settledRecipient, 'incoming answer rejects high-S sender acknowledgment', input => { input.acknowledgment.signature = highS(input.acknowledgment.signature); });
    await mutate(settledRecipient, 'historical acknowledgment cannot replace the original delegated key', input => { input.peer_enrollment.key = holders[1].raw; });
    await mutate(settledRecipient, 'historical acknowledgment cannot invent renewed delegation validity', input => { input.peer_enrollment.end = 10000n; });
    await mutate(settledRecipient, 'genuinely signed different-group acknowledgment cannot settle this obligation', async input => {
      const wrong = ackMessageForWrongGroup();
      input.acknowledgment.signature = canonicalSignature(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, holders[0].key.privateKey, await wrong));
    });
    async function ackMessageForWrongGroup() {
      const wrongSlot = structuredClone(slot); wrongSlot.group[0] ^= 1;
      return ackBytes(community, checkpoint.entries[0].member, checkpoint.entries[1].member, wrongSlot,
        await receiptDigest(message, resolution.signature), checkpoint.entries[0].delegationDigest, acknowledgment.issuedAt);
    }
  } else {
    const lateClose = structuredClone(settledRecipient.input);
    lateClose.now = 600n; lateClose.valid_until = validityHorizon(600, policy);
    await noir.execute(noirInput(lateClose));
    assert(true, 'ACVM accepts authentic recipient Close after the common deadline');
  }
  await mutate(settledRecipient, 'coherent expiry cannot silently retire an unresolved incoming obligation', async input => {
    input.action = 5; input.now = 600n; input.valid_until = validityHorizon(600, policy);
    const changed = await pendingRecipient.incoming.update(incoming.event, await hashes.obligation(incoming.event,
      pendingRecipient.slots.get(incoming.event.toString()), 5));
    const opening = structuredClone(settledRecipient.next.opening);
    opening.incomingRoot = changed.next.root;
    input.next_state = fieldBytes(await settledRecipient.next.commit(opening, settledRecipient.next.version));
  });
  recipient = await prove(settledRecipient, 1, configuration.accountScenario === 'answer'
    ? 'proved incoming Answer settlement after peer expiry' : 'proved recipient Close refunds its bond immediately');
  assert(recipient.outgoing.root === secondaryRoot && recipient.opening.reserved === BigInt(policy.outgoingReservation), 'unrelated outgoing obligation survives recipient settlement');
  let duplicateRejected = false;
  try { await recipient.reserve({ peerIndex: 0, role: 0, ...context, now: 300 }); } catch { duplicateRejected = true; }
  assert(duplicateRejected, 'settled event cannot re-enter under opposite role');
  await mutate(settledRecipient, 'settled tombstone cannot be credited again', input => {
    input.previous_state = fieldBytes(recipient.commitment); input.previous_version = recipient.version;
    input.next_version = recipient.version + 1n;
  });
  // Additional real transitions cover all six private actions across the two
  // scenarios. Counter/refill attacks below execute ACVM only, without proofs.
  const execute = async (candidate, label) => { await noir.execute(noirInput(candidate.input)); assert(true, label); return candidate.next; };
  if (configuration.accountScenario === 'answer') {
    const canceled = await recipient.cancel(secondary.event, 300);
    assert(canceled.next.opening.admissions === recipient.opening.admissions
      && canceled.next.opening.admissionEpoch === recipient.opening.admissionEpoch, 'Prepared cancellation never restores admission throughput');
    await mutate(canceled, 'Prepared cancellation cannot reset the shared admission counter', async input => {
      const opening = structuredClone(canceled.next.opening); opening.admissions = 0n;
      input.next_state = fieldBytes(await canceled.next.commit(opening, canceled.next.version));
    });
    await mutate(canceled, 'only Prepared phase can receive a cancellation refund', input => { input.slot.phase = 2; });
    recipient = await prove(canceled, 1, 'proved Prepared cancellation refunds only reserved capacity');
    const mature = await recipient.refill(600);
    assert(mature.next.opening.available === recipient.opening.available + BigInt(policy.refillUnits), 'maturity creates headroom without automatically filling it');
    await execute(mature, 'ACVM accepts one due mature refill from the actual proved canceled state');
    await mutate(mature, 'maturity cannot reset the permanent genesis age', async input => {
      const opening = structuredClone(mature.next.opening); opening.createdAt = 600n;
      input.next_state = fieldBytes(await mature.next.commit(opening, mature.next.version));
    });
    await mutate(mature, 'maturity cannot mint the whole larger capacity', async input => {
      const opening = structuredClone(mature.next.opening); opening.available = BigInt(policy.maximumAvailable);
      input.next_state = fieldBytes(await mature.next.commit(opening, mature.next.version));
    });
  } else {
    assert((await post({ command: 'advance', now: 600 })).ok, 'native fixture advances to the pinned abandonment/refill time');
    const senderExpiry = await sender.expire(outgoing.event, 600);
    assert(senderExpiry.next.opening.available === sender.opening.available + senderAmount
      && senderExpiry.next.opening.reserved === sender.opening.reserved - senderAmount,
    'sender receives its exact bond at the original deadline despite the longer current wait');
    const withoutClose = structuredClone(senderExpiry.input);
    withoutClose.resolution.signature.fill(0);
    withoutClose.peer_enrollment.end = 100n; // No current peer authority or signature is required.
    await noir.execute(noirInput(withoutClose));
    const deliveredClose = structuredClone(withoutClose);
    Object.assign(deliveredClose.resolution, { kind: resolution.kind, issued_at: resolution.issuedAt,
      history_digest: resolution.historyDigest, ed25519_receipt_digest: resolution.ed25519ReceiptDigest, signature: resolution.signature });
    await noir.execute(noirInput(deliveredClose));
    assert(equal(withoutClose.next_state, deliveredClose.next_state), 'withholding or delivering genuine Close produces the same deadline refund without peer eligibility');
    await mutate(senderExpiry, 'sender expiry cannot run before the original deadline', input => { input.now = 599n; input.valid_until = validityHorizon(599, policy); });
    await mutate(senderExpiry, 'changed slot expiry cannot shorten the original fixed wait', input => { input.slot.expires_at = 599n; });
    await mutate(senderExpiry, 'changed slot expiry cannot extend the original fixed wait', input => { input.slot.expires_at = 700n; });
    const shorter = await sender.withPolicy({ ...policy, abandonAfter: 100 });
    const shortenedAttempt = await shorter.expire(outgoing.event, 600);
    await mutate(shortenedAttempt, 'a shorter current wait cannot refund an old slot early', input => { input.now = 300n; input.valid_until = validityHorizon(300, policy); });
    sender = await prove(senderExpiry, 0, 'proved sender fixed-deadline refund after recipient Close');
    await mutate(senderExpiry, 'coherent expired tombstone cannot refund twice', async input => {
      const current = sender.input(random(), 600);
      Object.assign(input, { old: current.old, new_blind: current.new_blind, previous_state: current.previous_state,
        previous_version: current.previous_version, next_version: current.next_version });
      input.slot.phase = 5; input.own_map = sender.outgoing.witness(sender.outgoing.find(outgoing.event)[0]);
      const opening = structuredClone(sender.opening); opening.available += senderAmount; opening.blind = current.new_blind;
      input.next_state = fieldBytes(await sender.commit(opening, current.next_version));
    });
    await mutate(senderExpiry, 'expired tombstone rejects a later recipient-signed Answer refund', async input => {
      const current = sender.input(random(), 600), later = { ...resolution, kind: 1, issuedAt: 600n };
      later.signature = canonicalSignature(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, holders[1].key.privateKey,
        receiptBytes(community, checkpoint.entries[1].member, checkpoint.entries[0].member,
          sender.slots.get(outgoing.event.toString()), checkpoint.entries[1].delegationDigest, later)));
      Object.assign(input, { action: 3, old: current.old, new_blind: current.new_blind, previous_state: current.previous_state,
        previous_version: current.previous_version, next_version: current.next_version });
      input.slot.phase = 5; input.own_map = sender.outgoing.witness(sender.outgoing.find(outgoing.event)[0]);
      Object.assign(input.resolution, { kind: 1, issued_at: later.issuedAt, history_digest: later.historyDigest,
        ed25519_receipt_digest: later.ed25519ReceiptDigest, signature: later.signature });
      const opening = structuredClone(sender.opening); opening.available += senderAmount; opening.blind = current.new_blind;
      input.next_state = fieldBytes(await sender.commit(opening, current.next_version));
    });
    const expired = await recipient.expire(secondary.event, 600);
    assert(expired.next.opening.available === recipient.opening.available + BigInt(policy.outgoingReservation)
      && expired.next.opening.reserved === recipient.opening.reserved - BigInt(policy.outgoingReservation), 'unanswered outgoing expiry refunds exactly once');
    await mutate(expired, 'outgoing expiry cannot run before the common deadline', input => { input.now = 599n; input.valid_until = validityHorizon(599, policy); });
    await mutate(expired, 'outgoing expiry cannot burn the refundable bond', async input => {
      const opening = structuredClone(expired.next.opening); opening.available -= BigInt(policy.outgoingReservation);
      input.next_state = fieldBytes(await expired.next.commit(opening, expired.next.version));
    });
    await mutate(expired, 'expiry cannot reset admission throughput', async input => {
      const opening = structuredClone(expired.next.opening); opening.admissions = 0n;
      input.next_state = fieldBytes(await expired.next.commit(opening, expired.next.version));
    });
    recipient = await prove(expired, 1, 'proved unanswered outgoing refund without a peer signature');
    const refill = await recipient.refill(600);
    assert(refill.next.opening.available === recipient.opening.available + BigInt(policy.refillUnits)
      && refill.next.opening.frontier === validityHorizon(600, policy), 'due refill grants once and advances to the common committed horizon');
    await mutate(refill, 'offline time cannot multiply the single refill grant', async input => {
      const opening = structuredClone(refill.next.opening); opening.available += BigInt(policy.refillUnits);
      input.next_state = fieldBytes(await refill.next.commit(opening, refill.next.version));
    });
    await mutate(refill, 'refill cannot retain an old frontier for replay', async input => {
      const opening = structuredClone(refill.next.opening); opening.frontier = recipient.opening.frontier;
      input.next_state = fieldBytes(await refill.next.commit(opening, refill.next.version));
    });
    recipient = await prove(refill, 1, 'proved one bounded mature refill after fixed-wait refunds');
    await mutate(refill, 'coherent backdated proofs cannot refill twice inside the same acceptance window', async input => {
      const current = recipient.input(random(), 601);
      input.now = current.now; input.valid_until = current.valid_until;
      input.old = current.old; input.new_blind = current.new_blind;
      input.previous_state = current.previous_state; input.previous_version = current.previous_version; input.next_version = current.next_version;
      const opening = structuredClone(recipient.opening); opening.available += BigInt(policy.refillUnits); opening.blind = current.new_blind;
      input.next_state = fieldBytes(await recipient.commit(opening, current.next_version));
    });
    let replay = false; try { await recipient.refill(600); } catch { replay = true; }
    assert(replay, 'same-time refill replay is rejected');
    let late = false; try { await recipient.settle(secondary.event, resolution, undefined, 600); } catch { late = true; }
    assert(late, 'terminal expiry cannot later receive an Answer or Close refund');
    const fresh = await recipient.reserve({ peerIndex: 0, role: 0, nonce: random(), group: random(), contactPolicy: context.contactPolicy, now: 600 });
    assert(fresh.next.slots.get(fresh.event.toString()).expiresAt === 1500n, 'new reservations alone adopt the tuned waiting period');
    await execute(fresh, 'ACVM accepts a fresh reservation under the actual tuned policy');
    let tailRejected = false;
    try { await recipient.reserve({ peerIndex: 0, role: 0, nonce: random(), group: random(), contactPolicy: context.contactPolicy, now: 9100 }); } catch { tailRejected = true; }
    assert(tailRejected, 'new reservation cannot promise a refund at or beyond immutable policy expiry');
    await mutate(fresh, 'coherent circuit reservation rejects refund exactly at immutable policy expiry', async input => {
      const atBoundary = { ...policy, abandonAfter: 9400 };
      input.abandon_after = 9400n; input.policy_digest = await policyDigest(community, atBoundary);
      input.slot.expires_at = 10000n;
      const changedSlot = structuredClone(fresh.next.slots.get(fresh.event.toString())); changedSlot.expiresAt = 10000n;
      const changed = await fresh.next.outgoing.update(fresh.event, await hashes.obligation(fresh.event, changedSlot, 1));
      const opening = structuredClone(fresh.next.opening); opening.outgoingRoot = changed.next.root;
      input.next_state = fieldBytes(await fresh.next.commit(opening, fresh.next.version));
    });
  }

  // Coherent private forks are deliberately ACVM-only, not ledger evidence.
  let churn = await execute(await secondary.next.cancel(secondary.event, 100), 'ACVM cancellation retains a counted admission');
  for (let count = Number(churn.opening.admissions); count < policy.newcomerAdmissions; count++) {
    const reservation = await churn.reserve({ peerIndex: 0, role: 0, nonce: random(), group: random(), contactPolicy: context.contactPolicy, now: 100 });
    churn = await execute(reservation, 'ACVM counts another newcomer reservation in either role');
    churn = await execute(await churn.cancel(reservation.event, 100), 'ACVM canceled reservation remains counted in the shared window');
  }
  const lowered = churn.clone(); lowered.opening.admissions -= 1n;
  const overRate = await lowered.reserve({ peerIndex: 0, role: 0, nonce: random(), group: random(), contactPolicy: context.contactPolicy, now: 100 });
  overRate.input.old = churn.input(overRate.input.new_blind, 100).old;
  await rejected(overRate.input, 'coherent successor cannot bypass newcomer throughput after repeated refunds');
  await mutate(incoming, 'incoming reservation cannot shift the shared introduction opened-at into the future', input => { input.slot.admitted_at = 101n; });
  await mutate(activeRecipient, 'a live-at-proving contact cannot outlast the common proof horizon', input => {
    input.now = 600n; input.valid_until = validityHorizon(600, policy);
  });
  // Real proofs form the only exported account chain; openings, map witnesses,
  // signing secrets and contact receipts stay in this browser test process.
  // Exercise the complete shipped browser factory after releasing the first
  // backend. Reprove a page-local genesis candidate, without submitting a second
  // genesis or transmitting its private witness. Keep this separate from the
  // chronological accepted account chain.
  await releaseBackend();
  stage('production-runtime-factory');
  const manifestBytes=await bytes('/manifest.json'), manifestSha256=hex(await sha(manifestBytes));
  const originalFetch=globalThis.fetch;
  let wasmNetworkFetches=0,wasmBlobFetches=0,runtime;
  globalThis.fetch=async function(input,init){
    const url=new URL(input instanceof Request?input.url:String(input),location.href);
    if(url.protocol==='blob:'&&url.hash.endsWith('/barretenberg-threads.wasm'))wasmBlobFetches++;
    if(url.protocol!=='blob:'&&url.pathname.endsWith('/barretenberg-threads.wasm')){
      wasmNetworkFetches++;
      // A TOCTOU regression must fail with a corrupted second download, not
      // accidentally pass because this fixture's asset server is immutable.
      if(wasmNetworkFetches>1)return new Response(new Uint8Array([255]),{status:200});
    }
    return originalFetch.call(globalThis,input,init);
  };
  try {
    runtime=await createAccountProver({manifestBytes,manifestSha256,
      readArtifact:async(name,maximum)=>{const data=await bytes('/'+name);if(data.length>maximum)throw new Error('Factory artifact bound');return data;},
      limits:{maxProofBytes:20000}});
  } finally {globalThis.fetch=originalFetch;}
  try {
    assert(wasmNetworkFetches===1&&wasmBlobFetches===1,'production factory compiles the verified immutable Wasm without a second network fetch');
    const started=performance.now(),record=await runtime.prove(genesis[0]);
    assert(record.statement.nextVersion===0 && record.proof.length>0,'production browser factory proves the retained private genesis witness');
    assert((await runtime.verify(record)).verified===true,'production browser factory verifies its generated public proof');
    metrics.runtimeFactory={record,manifestSha256,elapsedMs:performance.now()-started,wasmNetworkFetches,wasmBlobFetches,
      privateWitnessExported:false,ledgerSubmitted:false};
  } finally {await runtime.destroy();}
  metrics.endJsHeapBytes = performance.memory?.usedJSHeapSize ?? null;
  metrics.memoryMeasurement = 'Local JS heap at end; exact peak WASM unknown; harness process samples are separate';
  metrics.manifest = manifest;
  return { ok: true, ...metrics };
}
