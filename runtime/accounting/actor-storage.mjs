// Local encrypted wallet journal. The host owns authenticated encryption, durable
// compare-and-swap and rollback protection; this module never stores plaintext.
export function accountActorStorage({ storage, maxJournalBytes, maxCiphertextBytes }) {
  if (!storage || !['load', 'seal', 'open', 'compareAndSwap'].every(key => typeof storage[key] === 'function')
      || !Number.isSafeInteger(maxJournalBytes) || maxJournalBytes <= 0 || maxJournalBytes > 16 * 1024 * 1024
      || !Number.isSafeInteger(maxCiphertextBytes) || maxCiphertextBytes < maxJournalBytes
      || maxCiphertextBytes > 32 * 1024 * 1024) throw new Error('Explicit account wallet storage and bounds required');
  let revision = 0, uncertain = false;
  function bounded(value, maximum) {
    if (!(value instanceof Uint8Array) || !value.length || value.length > maximum) throw new Error('Account wallet byte bound');
    return new Uint8Array(value);
  }
  return {
    get uncertain() { return uncertain; },
    async load() {
      uncertain = true;
      const record = await storage.load();
      if (record === null) { revision = 0; uncertain = false; return null; }
      if (!record || Object.keys(record).length !== 2 || !Object.hasOwn(record, 'ciphertext')
          || !Number.isSafeInteger(record.revision) || record.revision <= 0) throw new Error('Account wallet revision');
      const observedRevision = record.revision, ciphertext = bounded(record.ciphertext, maxCiphertextBytes);
      const plaintext = bounded(await storage.open(ciphertext), maxJournalBytes);
      let journal;
      try { journal = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext)); }
      finally { plaintext.fill(0); }
      if (journal?.revision !== observedRevision) throw new Error('Account wallet revision binding');
      revision = observedRevision; uncertain = false; return journal;
    },
    async save(value) {
      if (uncertain || revision >= Number.MAX_SAFE_INTEGER) throw new Error('Account wallet reload required');
      const nextRevision = revision + 1;
      const journal = structuredClone({ ...value, revision: nextRevision });
      const plaintext = bounded(new TextEncoder().encode(JSON.stringify(journal)), maxJournalBytes);
      let ciphertext;
      try { ciphertext = bounded(await storage.seal(plaintext), maxCiphertextBytes); }
      finally { plaintext.fill(0); }
      // A thrown/ambiguous write may already be durable. No further mutation is
      // permitted until an authenticated reload observes the actual revision.
      uncertain = true;
      if (await storage.compareAndSwap(revision, { revision: nextRevision, ciphertext }) !== true) {
        throw new Error('Account wallet compare-and-swap failed');
      }
      revision = nextRevision; uncertain = false; return journal;
    },
  };
}
