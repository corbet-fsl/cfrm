// Adapt AccountClient's fixed transcripts to cmsg's typed signing methods.
// No caller of the actor receives a raw signing callback or private device key.
const utf8 = new TextEncoder();
const equal = (a, b) => a.length === b.length && a.every((value, index) => value === b[index]);
const b64 = value => btoa(String.fromCharCode(...value)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
function decode(value, length) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Account signer encoding');
  const bytes = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), char => char.charCodeAt(0));
  if (bytes.length !== length || b64(bytes) !== value) throw new Error('Account signer width');
  return bytes;
}
export function scopedAccountSigner({ authorizeRequest, authorizeStatus, authority }) {
  return async message => {
    const bytes = new Uint8Array(message), identity = structuredClone(authority());
    const domains = ['cfrm.account.request.v1\0', 'cfrm.account.status.v1\0'];
    const domain = domains.find(value => equal(bytes.slice(0, utf8.encode(value).length), utf8.encode(value)));
    if (!domain) throw new Error('Unsupported account signing domain');
    let offset = utf8.encode(domain).length;
    const take = count => {
      if (offset + count > bytes.length) throw new Error('Account signing transcript width');
      const value = bytes.slice(offset, offset + count); offset += count; return value;
    };
    const time = () => {
      const value = new DataView(take(8).buffer).getBigUint64(0);
      if (value === 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('Account signing time');
      return Number(value);
    };
    let fields, callback;
    if (domain === domains[0]) {
      const requestId = take(32), circuitDigest = take(32), verifyingKeyDigest = take(32), device = take(32);
      const issuedAt = time(), expiresAt = time(), statementDigest = take(32), proofDigest = take(32);
      fields = { requestId: Array.from(requestId), circuitDigest: Array.from(circuitDigest),
        verifyingKeyDigest: Array.from(verifyingKeyDigest), statementDigest: Array.from(statementDigest),
        proofDigest: Array.from(proofDigest), chatPublicKey: b64(device), issuedAt, expiresAt };
      callback = authorizeRequest;
    } else {
      const community = take(32), owner = take(32), hasRequest = take(1)[0], request = take(32), challenge = take(32), device = take(32);
      if (hasRequest > 1 || (hasRequest === 0 && request.some(Boolean))) throw new Error('Account status lookup encoding');
      fields = { community: Array.from(community), owner: Array.from(owner), requestId: hasRequest ? Array.from(request) : null,
        challenge: Array.from(challenge), chatPublicKey: b64(device), issuedAt: time(), expiresAt: time() };
      callback = authorizeStatus;
    }
    if (offset !== bytes.length || fields.chatPublicKey !== identity.authorization.devicePublicKey
        || fields.chatPublicKey !== identity.grant.chatPublicKey || fields.issuedAt >= fields.expiresAt) {
      throw new Error('Account signer authority or transcript mismatch');
    }
    if (domain === domains[1]) {
      const expectedCommunity = new Uint8Array(await crypto.subtle.digest(
        'SHA-256', new TextEncoder().encode(identity.grant.communityId)));
      const expectedOwner = decode(identity.grant.memberId, 32);
      if (!equal(fields.community, expectedCommunity) || !equal(fields.owner, expectedOwner)
          || !fields.challenge.some(Boolean)) throw new Error('Account status scope mismatch');
    } else if (!fields.requestId.some(Boolean)) {
      throw new Error('Account request identifier');
    }
    const provided = await callback(structuredClone(fields));
    if (typeof provided === 'string' && provided.length > 8192) throw new Error('Account signer response bound');
    const result = typeof provided === 'string' ? JSON.parse(provided) : structuredClone(provided);
    if (JSON.stringify(result).length > 8192) throw new Error('Account signer response bound');
    const keys = [...Object.keys(fields), 'signature'];
    if (!result || Array.isArray(result) || Object.keys(result).length !== keys.length
        || !keys.every(key => Object.hasOwn(result, key))
        || !Object.keys(fields).every(key => Array.isArray(fields[key])
          ? Array.isArray(result[key]) && equal(fields[key], result[key]) : fields[key] === result[key])) {
      throw new Error('Typed account signer changed request fields');
    }
    const key = await crypto.subtle.importKey('raw', decode(fields.chatPublicKey, 32), 'Ed25519', false, ['verify']);
    if (!await crypto.subtle.verify('Ed25519', key, decode(result.signature, 64), bytes)) throw new Error('Account device signature');
    return result.signature;
  };
}
