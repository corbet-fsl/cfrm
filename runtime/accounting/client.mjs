import { be, cat, random, sha } from './encoding.mjs';
import { statementBytes } from './witness.mjs';
import { validateStatement } from './runtime.mjs';

const utf8 = value => new TextEncoder().encode(value);
const equal = (a,b) => a.length === b.length && a.every((v,i) => v === b[i]);
const bytes = (value, length) => {
  if (!(value instanceof Uint8Array) && !Array.isArray(value)) throw new Error('Expected bytes');
  if (value.length !== length || Array.from(value).some(v => !Number.isInteger(v) || v < 0 || v > 255)) throw new Error('Byte width');
  return Uint8Array.from(value);
};
const b64 = value => btoa(String.fromCharCode(...value)).replaceAll('+','-').replaceAll('/','_').replace(/=+$/, '');
const decode = (value, length) => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Canonical base64url');
  const data = Uint8Array.from(atob(value.replaceAll('-','+').replaceAll('_','/')), c => c.charCodeAt(0));
  if (data.length !== length || b64(data) !== value) throw new Error('Canonical base64url width'); return data;
};
const time = n => { if (!Number.isSafeInteger(n) || n <= 0) throw new Error('Time bound'); return n; };
const nonzero = value => { const data = bytes(value,32); if (!data.some(Boolean)) throw new Error('Zero identifier'); return data; };
const exact = (value,keys) => value && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(k=>Object.hasOwn(value,k));
function identity(grant,authorization) {
  if (!exact(grant,['version','issuerKeyId','communityId','memberId','chatPublicKey','policyDigest','issuedAt','expiresAt','signature'])
      || !exact(authorization,['version','communityId','memberId','rootPublicKey','devicePublicKey','issuedAt','expiresAt','signature'])) throw new Error('Exact public identity required');
  for(const value of [grant,authorization]) {
    if(value.version!==1 || typeof value.communityId!=='string' || value.communityId.length>256
      || !/^[A-Za-z0-9._:/-]+$/.test(value.communityId) || time(value.expiresAt)<=time(value.issuedAt)) throw new Error('Public identity encoding');
    decode(value.signature,64);
  }
  for(const key of ['issuerKeyId','memberId','chatPublicKey','policyDigest'])decode(grant[key],32);
  for(const key of ['memberId','rootPublicKey','devicePublicKey'])decode(authorization[key],32);
  return {grant:structuredClone(grant),authorization:structuredClone(authorization)};
}
function proofScope(value) {
  if(!exact(value,['circuitDigest','verifyingKeyDigest']))throw new Error('Exact public proof scope required');
  nonzero(value.circuitDigest);nonzero(value.verifyingKeyDigest);
}

export async function accountRequestBytes(r) {
  await validateStatement(r.statement);
  proofScope(r.proofScope);
  if (r.issuedAt !== r.statement.now || time(r.expiresAt) <= time(r.issuedAt)
      || r.expiresAt > r.statement.validUntil || !Array.isArray(r.proof) || !r.proof.length
      || r.proof.length > 1024 * 1024) throw new Error('Account request validity');
  return cat(utf8('cfrm.account.request.v1\0'), nonzero(r.requestId),
    bytes(r.proofScope.circuitDigest,32), bytes(r.proofScope.verifyingKeyDigest,32), decode(r.chatPublicKey,32),
    be(r.issuedAt,8), be(r.expiresAt,8), await sha(statementBytes(r.statement)), await sha(bytes(r.proof,r.proof.length)));
}

export async function accountAcceptanceBytes(a) {
  if(!exact(a,['statement','requestId','requestDigest','proofScope','acceptedAt','signature']))throw new Error('Exact acceptance required');
  await validateStatement(a.statement);
  proofScope(a.proofScope);
  if (time(a.acceptedAt) < a.statement.now || a.acceptedAt >= a.statement.validUntil) throw new Error('Acceptance time');
  return cat(utf8('cfrm.account.acceptance.v1\0'), nonzero(a.requestId), bytes(a.requestDigest,32),
    bytes(a.proofScope.circuitDigest,32), bytes(a.proofScope.verifyingKeyDigest,32), be(a.acceptedAt,8), await sha(statementBytes(a.statement)));
}

async function verifySignature(key, signature, message) {
  const publicKey = await crypto.subtle.importKey('raw', bytes(key,32), 'Ed25519', false, ['verify']);
  if (!await crypto.subtle.verify('Ed25519', publicKey, decode(signature,64), message)) throw new Error('Operator signature');
}
export async function verifyAccountAcceptance(acceptance, operatorPublicKey, request) {
  await verifySignature(operatorPublicKey, acceptance.signature, await accountAcceptanceBytes(acceptance));
  if (request) {
    const digest = await sha(cat(await accountRequestBytes(request), decode(request.signature,64)));
    if (!equal(digest, acceptance.requestDigest) || !equal(request.requestId, acceptance.requestId)
        || !equal(statementBytes(request.statement), statementBytes(acceptance.statement))
        || !equal(request.proofScope.circuitDigest, acceptance.proofScope.circuitDigest)
        || !equal(request.proofScope.verifyingKeyDigest, acceptance.proofScope.verifyingKeyDigest)) throw new Error('Acceptance does not match request');
  }
  return acceptance;
}

export function accountStatusBytes(r) {
  if (time(r.expiresAt) <= time(r.issuedAt)) throw new Error('Status validity');
  return cat(utf8('cfrm.account.status.v1\0'), bytes(r.community,32), bytes(r.owner,32),
    new Uint8Array([r.requestId === null ? 0 : 1]), r.requestId === null ? new Uint8Array(32) : nonzero(r.requestId),
    nonzero(r.challenge), decode(r.chatPublicKey,32), be(r.issuedAt,8), be(r.expiresAt,8));
}
export async function verifyAccountStatusResponse(response, request, operatorPublicKey) {
  if(!exact(response,['statusRequestDigest','observedAt','acceptance','signature']))throw new Error('Exact status response required');
  const digest = await sha(cat(accountStatusBytes(request), decode(request.signature,64)));
  if (!equal(digest, bytes(response.statusRequestDigest,32)) || time(response.observedAt) < request.issuedAt
      || response.observedAt >= request.expiresAt) throw new Error('Stale status response');
  let accepted = new Uint8Array(32);
  if (response.acceptance !== null) {
    const a = await verifyAccountAcceptance(response.acceptance, operatorPublicKey);
    if (a.acceptedAt > response.observedAt || !equal(a.statement.owner,request.owner)
        || !equal(a.statement.community,request.community)
        || (request.requestId !== null && !equal(a.requestId,request.requestId))) throw new Error('Status account mismatch');
    accepted = await sha(cat(await accountAcceptanceBytes(a), decode(a.signature,64)));
  }
  await verifySignature(operatorPublicKey, response.signature, cat(utf8('cfrm.account.status-response.v1\0'), digest,
    be(response.observedAt,8), new Uint8Array([response.acceptance === null ? 0 : 1]), accepted));
  return response;
}

/** Transport-neutral client. sign receives exact Ed25519 signing bytes; transport
 * receives public envelopes only. Persist the signed request AND private successor
 * before apply; install the successor only after verified acceptance is durable. */
export class AccountClient {
  constructor({ transport, sign, operatorPublicKey }) {
    if (typeof transport !== 'function' || typeof sign !== 'function') throw new Error('Account client callbacks');
    this.transport = transport; this.sign = sign; this.operatorPublicKey = bytes(operatorPublicKey,32);
  }
  async signature(message) {
    const result = await this.sign(message);
    return typeof result === 'string' ? b64(decode(result,64)) : b64(bytes(result,64));
  }
  async prepareApply({ record, chatPublicKey, expiresAt, requestId = random() }) {
    if (!record || Object.keys(record).length !== 3 || !['statement','proof','proofScope'].every(k => Object.hasOwn(record,k))
        || typeof record.proof !== 'string' || !/^(?:[0-9a-f]{2})+$/.test(record.proof) || record.proof.length > 2 * 1024 * 1024) throw new Error('Public proof record only');
    const request = { statement: structuredClone(record.statement), requestId: Array.from(nonzero(requestId)),
      proofScope: structuredClone(record.proofScope), chatPublicKey, issuedAt: record.statement.now, expiresAt,
      proof: Array.from(record.proof.match(/../g), pair => parseInt(pair,16)), signature: '' };
    request.signature = await this.signature(await accountRequestBytes(request)); return request;
  }
  async apply({ grant, authorization, request }) {
    // Reject accidental private fields before transport (including fields nested in proof request).
    const keys = ['statement','requestId','proofScope','chatPublicKey','issuedAt','expiresAt','proof','signature'];
    if (!request || Object.keys(request).length !== keys.length || !keys.every(k => Object.hasOwn(request,k))) throw new Error('Exact signed request required');
    request=structuredClone(request);
    const publicIdentity=identity(grant,authorization);
    await accountRequestBytes(request);
    const response = await this.transport({ action: 'apply', ...publicIdentity, request:structuredClone(request) });
    if (response?.action !== 'apply') throw new Error('Unexpected account response');
    return verifyAccountAcceptance(response.value, this.operatorPublicKey, request);
  }
  async prepareStatus({ community, owner, chatPublicKey, issuedAt, expiresAt, requestId = null, challenge = random() }) {
    const request = { community: Array.from(bytes(community,32)), owner: Array.from(bytes(owner,32)),
      chatPublicKey, issuedAt, expiresAt, requestId: requestId === null ? null : Array.from(nonzero(requestId)),
      challenge: Array.from(nonzero(challenge)), signature: '' };
    request.signature = await this.signature(accountStatusBytes(request)); return request;
  }
  async status({ grant, authorization, request }) {
    const keys = ['community','owner','requestId','challenge','chatPublicKey','issuedAt','expiresAt','signature'];
    if (!request || Object.keys(request).length !== keys.length || !keys.every(k => Object.hasOwn(request,k))) throw new Error('Exact status request required');
    request=structuredClone(request);
    const publicIdentity=identity(grant,authorization);
    accountStatusBytes(request);
    const response = await this.transport({ action: 'status', ...publicIdentity, request:structuredClone(request) });
    if (response?.action !== 'status') throw new Error('Unexpected account response');
    return verifyAccountStatusResponse(response.value, request, this.operatorPublicKey);
  }
}
