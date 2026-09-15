// Real browser contract. The harness serves ./pkg/cfrm.js and its Wasm output,
// and injects a test-only bridge to examples/browser_fixture.rs on a CI runner.
// This module never submits private checkpoints, member pairs, or blinding state.
import init, { BrowserMeetingBoard, BrowserPreparedPermit, BrowserRecipientClaim } from './pkg/cfrm.js';

const b64 = bytes => btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
const unb64 = value => Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/').padEnd(Math.ceil(value.length / 4) * 4, '=')), c => c.charCodeAt(0));
const random32 = () => crypto.getRandomValues(new Uint8Array(32));
const equal = (a, b) => a.length === b.length && a.every((value, index) => value === b[index]);

export async function runBrowserContract(callFixture) {
  await init({ module_or_path: new URL('./pkg/cfrm_bg.wasm', import.meta.url) });
  const checks = [];
  const timingsMs = {};
  const allocated = new Set();
  const keep = object => { allocated.add(object); return object; };
  const free = object => { allocated.delete(object); object.free(); };
  function check(condition, name) {
    if (!condition) throw new Error(`cfrm browser contract failed: ${name}`);
    checks.push(name);
  }
  function rejects(action, name) {
    let rejected = false;
    try { action(); } catch (error) { rejected = String(error).startsWith('cfrm:'); }
    check(rejected, name);
  }
  function rejectsCode(action, code, name) {
    let rejected = false;
    try { action(); } catch (error) { rejected = String(error) === `cfrm:${code}`; }
    check(rejected, name);
  }
  async function fixture(request) {
    // Reject a harness mistake before it could send sensitive local state.
    const permitted = request.action === 'issue' ? ['action', 'blindedRequest', 'nonce']
      : request.action === 'redeem' ? ['action', 'request'] : ['action'];
    if (Object.keys(request).some(key => !permitted.includes(key))) throw new Error('unexpected fixture request field');
    const response = await callFixture(request);
    if (!response.ok) throw new Error(`synthetic fixture rejected: ${response.error}`);
    return response.value;
  }

  try {
    const config = await fixture({ action: 'config' });
    check(config.fixtureOnly === true, 'synthetic fixture is explicit');
    const boardFixture = config.board;
    const boardTrust = JSON.stringify(boardFixture.trust);
    const boardLimits = JSON.stringify(boardFixture.limits);
    const applyRow = (board, row, update = row.update) => board.apply(
      JSON.stringify(row.admission), JSON.stringify(row.authorization), JSON.stringify(update));
    rejects(() => new BrowserMeetingBoard(JSON.stringify({ ...boardFixture.trust, extra: true }), boardLimits), 'unknown board trust fields rejected');
    rejects(() => new BrowserMeetingBoard(boardTrust, JSON.stringify({ ...boardFixture.limits, extra: true })), 'unknown board limit fields rejected');
    rejects(() => new BrowserMeetingBoard(boardTrust, JSON.stringify({ ...boardFixture.limits, maxMembers: 0 })), 'empty board capacity rejected');
    const weakIssuer = new Uint8Array(32); weakIssuer[0] = 1;
    rejects(() => new BrowserMeetingBoard(JSON.stringify({ ...boardFixture.trust, issuerPublicKey: b64(weakIssuer) }), boardLimits), 'weak board issuer key rejected');
    const board = keep(new BrowserMeetingBoard(boardTrust, boardLimits));
    check(board.snapshot() === '[]', 'new browser board starts with no unverified rows');
    applyRow(board, boardFixture.primary);
    let rows = JSON.parse(board.snapshot());
    check(rows.length === 1 && rows[0].memberId === config.senderId && rows[0].devices.length === 1
      && rows[0].devices[0].admission.signature === boardFixture.primary.admission.signature
      && rows[0].devices[0].authorization.signature === boardFixture.primary.authorization.signature
      && rows[0].devices[0].update.signature === boardFixture.primary.update.signature,
      'browser verifies and retains original issuer root and presence signatures');
    const initialSnapshot = board.snapshot();
    applyRow(board, boardFixture.primary);
    check(board.snapshot() === initialSnapshot, 'identical signed presence retry is idempotent');
    for (const [field, value] of [
      ['issuerPublicKey', boardFixture.primary.authorization.devicePublicKey],
      ['policyDigest', b64(random32())], ['communityId', 'different-community'],
    ]) {
      const wrongBoard = keep(new BrowserMeetingBoard(JSON.stringify({ ...boardFixture.trust, [field]: value }), boardLimits));
      rejectsCode(() => applyRow(wrongBoard, boardFixture.primary), 'Admission', `roster cannot replace pinned ${field}`);
    }
    rejects(() => board.apply(' '.repeat(8193), JSON.stringify(boardFixture.primary.authorization), JSON.stringify(boardFixture.primary.update)), 'oversized board JSON rejected before parsing');
    rejects(() => board.apply(JSON.stringify({ ...boardFixture.primary.admission, extra: true }), JSON.stringify(boardFixture.primary.authorization), JSON.stringify(boardFixture.primary.update)), 'unknown admission fields rejected in browser');
    rejects(() => board.apply(JSON.stringify(boardFixture.primary.admission), JSON.stringify({ ...boardFixture.primary.authorization, extra: true }), JSON.stringify(boardFixture.primary.update)), 'unknown device authorization fields rejected in browser');
    rejects(() => applyRow(board, boardFixture.primary, { ...boardFixture.primary.update, extra: true }), 'unknown presence fields rejected in browser');
    rejectsCode(() => applyRow(board, boardFixture.primary, { ...boardFixture.primary.update,
      endpoint: boardFixture.otherMember.update.endpoint }), 'Signature', 'altered valid onion cannot replace the signed endpoint');
    rejectsCode(() => applyRow(board, boardFixture.primary, { ...boardFixture.primary.update,
      memberId: config.recipientId }), 'Admission', 'presence cannot substitute another permanent member');
    rejectsCode(() => applyRow(board, boardFixture.primary, { ...boardFixture.primary.update,
      expiresAt: boardFixture.primary.update.expiresAt + 1 }), 'Signature', 'altered lease cannot extend a signed presence');
    rejectsCode(() => applyRow(board, boardFixture.issuerOnly), 'Admission', 'eligibility issuer cannot add its own device under an existing member root');
    check(board.snapshot() === initialSnapshot, 'rejected roster mutations leave the accepted snapshot intact');
    applyRow(board, boardFixture.primary, boardFixture.laterUpdate);
    rejectsCode(() => applyRow(board, boardFixture.primary), 'Replay', 'older genuinely signed sequence cannot replace newer presence');
    applyRow(board, boardFixture.secondDevice);
    applyRow(board, boardFixture.otherMember);
    rows = JSON.parse(board.snapshot());
    const senderRow = rows.find(row => row.memberId === config.senderId);
    const recipientRow = rows.find(row => row.memberId === config.recipientId);
    check(rows.length === 2 && senderRow?.devices.length === 2 && recipientRow?.devices.length === 1
      && senderRow.devices.some(row => row.update.sequence === 2)
      && new Set(senderRow.devices.map(row => row.update.chatPublicKey)).size === 2,
      'independently certified devices remain grouped under permanent member identities');
    rejectsCode(() => applyRow(board, boardFixture.thirdDevice), 'Capacity', 'extra certified device cannot exceed the per-member limit');
    rejectsCode(() => applyRow(board, boardFixture.excessMember), 'Capacity', 'extra certified member cannot exceed the roster member limit');
    const boardRealNow = Date.now;
    try {
      Date.now = () => (boardFixture.primary.update.issuedAt - 1) * 1000;
      rejectsCode(() => board.snapshot(), 'ClockRollback', 'browser board rejects clock rollback');
      Date.now = () => boardFixture.primary.update.expiresAt * 1000;
      check(board.snapshot() === '[]', 'expired leases disappear from the browser snapshot');
      rejectsCode(() => applyRow(board, boardFixture.primary, boardFixture.laterUpdate), 'Expired', 'expired signed rows cannot be reintroduced');
      Date.now = () => NaN;
      rejects(() => board.snapshot(), 'invalid clock cannot produce a browser roster');
      rejects(() => new BrowserMeetingBoard(boardTrust, boardLimits), 'invalid clock cannot initialize a browser board');
    } finally { Date.now = boardRealNow; }
    const epoch = JSON.stringify(config.epoch);
    const pin = config.contextId;
    const key = random32();
    const storageContext = new TextEncoder().encode('synthetic browser checkpoint');
    const wrongContext = new TextEncoder().encode('different browser checkpoint');
    rejects(() => new BrowserPreparedPermit(epoch, b64(random32())), 'personalized epoch pin rejected');
    rejects(() => new BrowserPreparedPermit(JSON.stringify({ ...config.epoch, extra: true }), pin), 'unknown epoch fields rejected');

    let started = performance.now();
    const original = keep(new BrowserPreparedPermit(epoch, pin));
    timingsMs.prepare = performance.now() - started;
    const second = keep(new BrowserPreparedPermit(epoch, pin));
    const firstRequest = original.issuanceRequest();
    check(firstRequest.length === 416, 'Wasm emits the fixed issuance envelope');
    check(!equal(firstRequest, second.issuanceRequest()), 'independent preparation uses fresh randomness');
    const checkpoint = original.seal(key, storageContext);
    check(!equal(checkpoint, original.seal(key, storageContext)), 'private checkpoints use fresh nonces');
    free(original);
    rejects(() => BrowserPreparedPermit.restore(epoch, pin, checkpoint, random32(), storageContext), 'wrong checkpoint key rejected');
    rejects(() => BrowserPreparedPermit.restore(epoch, pin, checkpoint, key, wrongContext), 'wrong storage context rejected');
    const tampered = checkpoint.slice(); tampered[tampered.length - 1] ^= 1;
    rejects(() => BrowserPreparedPermit.restore(epoch, pin, tampered, key, storageContext), 'tampered checkpoint rejected');
    const prepared = keep(BrowserPreparedPermit.restore(epoch, pin, checkpoint, key, storageContext));
    check(equal(prepared.issuanceRequest(), firstRequest), 'encrypted restore preserves the exact issuance request');

    const issueRequest = { action: 'issue', blindedRequest: b64(firstRequest), nonce: b64(random32()) };
    const issued = await fixture(issueRequest);
    const retried = await fixture(issueRequest);
    check(issued.remainingCredits === 1 && JSON.stringify(issued) === JSON.stringify(retried), 'issuer retry returns one durable debit and the original blind signature');
    rejects(() => prepared.finalize(new Uint8Array(384)), 'malicious blind signature rejected by Wasm');
    started = performance.now();
    const permit = prepared.finalize(unb64(issued.blindSignature));
    timingsMs.finalize = performance.now() - started;
    check(permit === prepared.finalize(unb64(retried.blindSignature)), 'Wasm finalization verifies and recovers the same permit');

    const introduction = {
      senderId: config.senderId,
      recipientId: config.recipientId,
      introductionId: b64(random32()),
      challenge: b64(random32()),
    };
    const introJson = JSON.stringify(introduction);
    const forgedPermit = { ...JSON.parse(permit), serial: b64(random32()) };
    rejects(() => new BrowserRecipientClaim(epoch, pin, JSON.stringify(forgedPermit), introJson), 'forged public permit rejected');
    const initialClaim = keep(new BrowserRecipientClaim(epoch, pin, permit, introJson));
    const anonymous = initialClaim.anonymousRequest();
    const request = JSON.parse(anonymous);
    check(Object.keys(request).sort().join(',') === 'claim,commitment,permit', 'only anonymous redemption fields are exported');
    check(!anonymous.includes(config.senderId) && !anonymous.includes(config.recipientId)
      && !anonymous.includes(introduction.introductionId) && !anonymous.includes(introduction.challenge), 'operator request excludes the private pair and invitation opening');
    const claimCheckpoint = initialClaim.seal(key, storageContext);
    free(initialClaim);
    rejects(() => BrowserRecipientClaim.restore(epoch, pin, checkpoint, key, storageContext, introJson), 'checkpoint type substitution rejected');
    rejects(() => BrowserRecipientClaim.restore(epoch, pin, claimCheckpoint, random32(), storageContext, introJson), 'claim checkpoint wrong key rejected');
    rejects(() => BrowserRecipientClaim.restore(epoch, pin, claimCheckpoint, key, wrongContext, introJson), 'claim checkpoint wrong context rejected');
    for (const [field, replacement] of [
      ['senderId', config.otherRecipientId], ['recipientId', config.otherRecipientId],
      ['introductionId', b64(random32())], ['challenge', b64(random32())],
    ]) {
      rejects(() => BrowserRecipientClaim.restore(epoch, pin, claimCheckpoint, key, storageContext,
        JSON.stringify({ ...introduction, [field]: replacement })), `restored claim rejects changed ${field}`);
    }
    const claim = keep(BrowserRecipientClaim.restore(epoch, pin, claimCheckpoint, key, storageContext, introJson));
    check(claim.anonymousRequest() === anonymous, 'recipient retry restores the exact private claim');
    const stamp = await fixture({ action: 'redeem', request });
    started = performance.now();
    claim.verifyStamp(JSON.stringify(stamp));
    timingsMs.verifyStamp = performance.now() - started;
    check(true, 'Wasm verifies the native redemption stamp against its private opening');
    const retryStamp = await fixture({ action: 'redeem', request: JSON.parse(claim.anonymousRequest()) });
    check(JSON.stringify(stamp) === JSON.stringify(retryStamp), 'anonymous retry recovers the original stamp');
    rejects(() => claim.verifyStamp(JSON.stringify({ ...stamp, signature: b64(new Uint8Array(64)) })), 'forged stamp signature rejected');
    rejects(() => claim.verifyStamp(JSON.stringify({ ...stamp, claim: b64(random32()) })), 'another claim stamp rejected');
    rejects(() => claim.verifyStamp(JSON.stringify({ ...stamp, commitment: b64(random32()) })), 'substituted recipient commitment rejected');
    const otherClaim = keep(new BrowserRecipientClaim(epoch, pin, permit,
      JSON.stringify({ ...introduction, recipientId: config.otherRecipientId, challenge: b64(random32()) })));
    const doubleSpend = await callFixture({ action: 'redeem', request: JSON.parse(otherClaim.anonymousRequest()) });
    check(doubleSpend.ok === false && doubleSpend.error === 'Replay', 'copied permit cannot admit a second recipient');

    const secondIssued = await fixture({ action: 'issue', blindedRequest: b64(second.issuanceRequest()), nonce: b64(random32()) });
    check(secondIssued.remainingCredits === 0, 'second distinct issuance consumes the final fixture allowance');
    second.finalize(unb64(secondIssued.blindSignature));
    const third = keep(new BrowserPreparedPermit(epoch, pin));
    const exhausted = await callFixture({ action: 'issue', blindedRequest: b64(third.issuanceRequest()), nonce: b64(random32()) });
    check(exhausted.ok === false && exhausted.error === 'NoAllowance', 'client preparation cannot bypass the native allowance');
    const realNow = Date.now;
    try {
      Date.now = () => config.epoch.expiresAt * 1000;
      rejects(() => claim.verifyStamp(JSON.stringify(stamp)), 'expired stamp cannot authorize browser admission');
      rejects(() => claim.anonymousRequest(), 'expired permit cannot generate a browser redemption request');
      Date.now = () => NaN;
      rejects(() => new BrowserPreparedPermit(epoch, pin), 'invalid browser clock fails closed');
    } finally { Date.now = realNow; }
    key.fill(0);
    return { ok: true, checks, count: checks.length, timingsMs,
      scope: 'signed public roster entries and aggregate bearer permits; no roster completeness or private reciprocity proof' };
  } finally {
    for (const object of allocated) object.free();
  }
}
