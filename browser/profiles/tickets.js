import { authorityExpiry, decode, digest, encode, exact, fresh, json, monotonicClock, positive,
  random, reject, scope, signing, trustCopy, verifyAuthority, verifySignature } from './crypto.js';
import { identityCopy } from './access.js';

async function epochCopy(value) {
  exact(value, ['communityId', 'epochId', 'validFrom', 'issueUntil', 'expiresAt', 'publicKeyDer', 'redemptionPublicKey']);
  const epoch = structuredClone(value);
  scope(epoch.communityId); scope(epoch.epochId);
  if (!epoch.epochId.startsWith('cfrm.key-access.v1/') || epoch.epochId.length === 'cfrm.key-access.v1/'.length) reject();
  positive(epoch.validFrom); positive(epoch.issueUntil); positive(epoch.expiresAt);
  if (epoch.validFrom >= epoch.issueUntil || epoch.issueUntil > epoch.expiresAt) reject();
  decode(epoch.redemptionPublicKey, 32); decode(epoch.publicKeyDer, undefined, 800);
  const contextId = await digest(json(['cfrm.permit.epoch.v1', epoch.communityId, epoch.epochId,
    epoch.validFrom, epoch.issueUntil, epoch.expiresAt, epoch.publicKeyDer, epoch.redemptionPublicKey]));
  return { epoch, contextId };
}
function epochLive(epoch, now) { if (now < epoch.validFrom || now >= epoch.expiresAt) reject(); }
export async function profileTicketCommitment(contextId, challengeDigest, expiresAt) {
  decode(contextId, 32); decode(challengeDigest, 32); positive(expiresAt);
  return digest(json(['cfrm.profile-key-ticket.v1', contextId, challengeDigest, expiresAt]));
}
export async function keyAccessIssueBytes(value) {
  exact(value, ['communityId', 'memberId', 'chatPublicKey', 'contextId', 'requestId', 'blindedRequest', 'issuedAt', 'expiresAt', 'signature']);
  scope(value.communityId); positive(value.issuedAt); positive(value.expiresAt);
  if (value.expiresAt <= value.issuedAt) reject();
  for (const field of ['memberId', 'chatPublicKey', 'contextId', 'requestId']) decode(value[field], 32);
  if (decode(value.requestId, 32).every(byte => byte === 0)) reject();
  const blinded = decode(value.blindedRequest, 416);
  if (encode(blinded.subarray(0, 32)) !== value.contextId) reject();
  return json(['cfrm.key-access.issue.v1', value.communityId, value.memberId, value.chatPublicKey,
    value.contextId, value.requestId, await digest(blinded), value.issuedAt, value.expiresAt]);
}
/** Save the prepared Wasm permit's encrypted checkpoint and this exact request
 * before issuance. Reuse both on retry; a fresh requestId spends another quota
 * slot. Issuance names the admitted member but contains no profile target. */
export async function signProfileTicketIssue(options) {
  const { epoch, contextId } = await epochCopy(options.epoch), trust = trustCopy(options.trust),
    identity = identityCopy(options.identity), clock = monotonicClock(options.clock);
  const authority = await verifyAuthority(identity.authority, trust, clock());
  const issuedAt = clock(), expiresAt = positive(options.expiresAt);
  if (epoch.communityId !== trust.communityId || issuedAt < epoch.validFrom || issuedAt >= epoch.issueUntil ||
      expiresAt > Math.min(epoch.issueUntil, authorityExpiry(authority))) reject();
  if (!(options.blindedRequest instanceof Uint8Array) || options.blindedRequest.length !== 416) reject();
  const request = { communityId: trust.communityId, memberId: authority.admission.memberId,
    chatPublicKey: authority.admission.chatPublicKey, contextId, requestId: options.requestId,
    blindedRequest: encode(options.blindedRequest), issuedAt, expiresAt, signature: '' };
  request.signature = await signing(identity, await keyAccessIssueBytes(request));
  fresh(request, clock());
  return { ...authority, request };
}
function stampBytes(stamp) {
  exact(stamp, ['contextId', 'tokenId', 'commitment', 'claim', 'expiresAt', 'signature']);
  for (const field of ['contextId', 'tokenId', 'commitment', 'claim']) decode(stamp[field], 32);
  positive(stamp.expiresAt); decode(stamp.signature, 64);
  return json(['cfrm.permit.redeemed.v1', stamp.contextId, stamp.tokenId, stamp.commitment, stamp.claim, stamp.expiresAt]);
}
/** The epoch descriptor must come from the pinned common catalogue, with
 * dedicated RSA and redemption keys. Never accept a reader-selected epoch.
 * Global single-use enforcement lives at the anonymous redeemer; this verifier
 * is paired with the key service's one-use fresh challenge reservation. */
export async function createProfileTicketVerifier({ epoch: selected, clock }) {
  const { epoch, contextId } = await epochCopy(selected), now = monotonicClock(clock);
  return async ({ ticket, challengeDigest, expiresAt }) => {
    try {
      const stamp = structuredClone(ticket), bytes = stampBytes(stamp);
      epochLive(epoch, now()); positive(expiresAt);
      if (expiresAt <= now() || expiresAt > epoch.expiresAt || stamp.contextId !== contextId ||
          stamp.expiresAt !== epoch.expiresAt || stamp.commitment !== await profileTicketCommitment(contextId, challengeDigest, expiresAt)) return false;
      await verifySignature(epoch.redemptionPublicKey, stamp.signature, bytes);
      epochLive(epoch, now()); return now() < expiresAt;
    } catch { return false; }
  };
}
/** takePermit atomically reserves a real finalized BrowserPreparedPermit from
 * the member's encrypted wallet. This adapter does not replace RFC9474 with
 * WebCrypto RSA-PSS: blinding/finalization stay in the established Rust/Wasm
 * implementation. The redeemer validates the permit before signing a stamp. */
export async function createProfileTicketAcquirer(options) {
  const { epoch, contextId } = await epochCopy(options.epoch), now = monotonicClock(options.clock);
  for (const name of ['takePermit', 'savePending', 'redeem', 'complete', 'retire']) if (typeof options[name] !== 'function') reject();
  const takePermit = options.takePermit, save = options.savePending, redeem = options.redeem, complete = options.complete, retire = options.retire;
  const verify = await createProfileTicketVerifier({ epoch, clock: now });
  let pending = options.pending === undefined ? null : structuredClone(options.pending), busy = false;
  function validPending(value) {
    exact(value, ['challengeDigest', 'expiresAt', 'request']);
    decode(value.challengeDigest, 32); positive(value.expiresAt);
    exact(value.request, ['permit', 'commitment', 'claim']);
    const permit = value.request.permit;
    exact(permit, ['contextId', 'serial', 'randomizer', 'signature']);
    if (permit.contextId !== contextId) reject();
    decode(permit.serial, 32); decode(permit.randomizer, 32); decode(permit.signature, 384);
    decode(value.request.commitment, 32); decode(value.request.claim, 32);
  }
  if (pending) validPending(pending);
  async function finish() {
    validPending(pending); epochLive(epoch, now());
    if (pending.expiresAt <= now() || pending.expiresAt > epoch.expiresAt ||
        pending.request.commitment !== await profileTicketCommitment(contextId, pending.challengeDigest, pending.expiresAt)) reject();
    await save(structuredClone(pending));
    if (pending.expiresAt <= now()) reject();
    const ticket = await redeem({ permit: structuredClone(pending.request.permit), challengeDigest: pending.challengeDigest,
      expiresAt: pending.expiresAt, claim: pending.request.claim });
    if (await verify({ ticket, challengeDigest: pending.challengeDigest, expiresAt: pending.expiresAt }) !== true ||
        ticket.claim !== pending.request.claim ||
        ticket.tokenId !== await digest(json(['cfrm.permit.spend.v1', contextId, pending.request.permit.serial]))) reject();
    const result = { ticket: structuredClone(ticket), challengeDigest: pending.challengeDigest, expiresAt: pending.expiresAt };
    await complete(structuredClone(pending), structuredClone(ticket)); pending = null;
    if (result.expiresAt <= now()) reject();
    return result;
  }
  return Object.freeze({
    async acquireTicket({ challengeDigest, expiresAt }) {
      if (busy) reject(); busy = true;
      try {
        decode(challengeDigest, 32); positive(expiresAt); epochLive(epoch, now());
        if (expiresAt <= now() || expiresAt > epoch.expiresAt) reject();
        if (pending) {
          if (pending.challengeDigest !== challengeDigest || pending.expiresAt !== expiresAt) reject();
        } else {
          const permit = structuredClone(await takePermit({ contextId }));
          pending = { challengeDigest, expiresAt, request: { permit,
            commitment: await profileTicketCommitment(contextId, challengeDigest, expiresAt), claim: encode(random(32)) } };
        }
        return (await finish()).ticket;
      } finally { busy = false; }
    },
    async retryPending() {
      if (busy || !pending) reject(); busy = true;
      try { return await finish(); } finally { busy = false; }
    },
    async retireExpired() {
      if (busy) reject(); busy = true;
      try {
        if (!pending) return;
        validPending(pending);
        if (pending.expiresAt > now()) reject();
        // The redeemer may already have committed. Retirement marks the local
        // reservation spent, never returns it to the available permit pool.
        await retire(structuredClone(pending)); pending = null;
      } finally { busy = false; }
    },
  });
}
