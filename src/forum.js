/**
 * Omniscient, synthetic rule model. Not an operator database or network service.
 * Identifiers, relationship records and local choices exist only for experiments.
 */
export class ForumExperiment {
  #policy;
  #eligible;
  #members = new Map();
  #presence = new Map();
  #contacts = new Map();
  #votes = new Map();
  #rejections = {};
  #epoch = 0;
  #now = 0;

  constructor(policy, syntheticEligibilityOracle) {
    const nonnegative = ['initialTokens', 'epochGrant', 'maxEpochGrant',
      'tokenCap', 'growthPerActiveEpoch', 'imbalanceEpochs'];
    const positive = ['maxImbalance', 'pendingCap', 'requestTtl', 'presenceTtl'];
    for (const key of [...nonnegative, ...positive]) {
      if (!Number.isSafeInteger(policy[key]) || policy[key] < (positive.includes(key) ? 1 : 0)) {
        throw new TypeError(`Invalid policy field: ${key}`);
      }
    }
    if (policy.initialTokens > policy.tokenCap || policy.epochGrant > policy.maxEpochGrant ||
      typeof policy.voting !== 'boolean' || typeof syntheticEligibilityOracle !== 'function') {
      throw new TypeError('Invalid policy or synthetic eligibility oracle');
    }
    this.#policy = { ...policy };
    this.#eligible = syntheticEligibilityOracle;
  }

  get policy() { return { ...this.#policy }; }

  #tick(now) {
    if (!Number.isSafeInteger(now) || now < this.#now) throw new RangeError('Time must be monotonic');
    this.#now = now;
    for (const [id, deadline] of this.#presence) {
      if (deadline <= now || this.#eligible(id) !== true) this.#presence.delete(id);
    }
    for (const contact of this.#contacts.values()) {
      if (contact.status === 'pending' && contact.deadline <= now) contact.status = 'expired';
    }
  }

  connect(id, now) {
    this.#tick(now);
    if (typeof id !== 'string' || !id.length || this.#eligible(id) !== true) return false;
    if (!this.#members.has(id)) {
      this.#members.set(id, {
        tokens: this.#policy.initialTokens, sent: 0, received: 0, approaches: 0,
        activeEpochs: 0, activity: false, grantTotal: this.#policy.initialTokens,
        open: true, blocks: new Set(), windows: new Map(), maxPending: 0,
      });
    }
    this.#presence.set(id, now + this.#policy.presenceTtl);
    return true;
  }

  disconnect(id) { this.#presence.delete(id); }
  roster(now) { this.#tick(now); return [...this.#presence.keys()].sort(); }

  #member(id) {
    const member = this.#members.get(id);
    if (!member) throw new RangeError('Unknown synthetic member');
    return member;
  }

  /** Synthetic diagnostic only. Never expose this as an operator API. */
  state(id) {
    const { tokens, sent, received, approaches, activeEpochs, grantTotal } = this.#member(id);
    return { tokens, sent, received, approaches, activeEpochs, grantTotal };
  }

  /** Member-client queues are centrally visible only inside the synthetic model. */
  requestsFor(id) {
    this.#member(id);
    return [...this.#contacts.values()]
      .filter(contact => contact.to === id && contact.status === 'pending')
      .map(contact => ({ from: contact.from }));
  }

  /** Omniscient experiment outcomes; neither identities nor edges are serialized. */
  outcomes(id) {
    const contacts = [...this.#contacts.values()];
    return {
      reciprocatedApproaches: contacts.filter(contact => contact.from === id && contact.status === 'replied').length,
      unsolicitedReceived: contacts.filter(contact => contact.to === id).length,
      maxPending: this.#member(id).maxPending,
    };
  }

  #count(member, direction) {
    member[direction]++;
    const window = member.windows.get(this.#epoch) ?? { sent: 0, received: 0 };
    window[direction]++;
    member.windows.set(this.#epoch, window);
  }

  #imbalance(member) {
    if (this.#policy.imbalanceEpochs === 0) return member.sent - member.received;
    return [...member.windows.values()].reduce((sum, window) => sum + window.sent - window.received, 0);
  }

  setOpen(id, open) {
    if (typeof open !== 'boolean') throw new TypeError('Expected boolean local choice');
    this.#member(id).open = open;
  }

  block(owner, other) { this.#member(owner).blocks.add(other); }
  unblock(owner, other) { this.#member(owner).blocks.delete(other); }

  #pair(a, b) { return JSON.stringify([a, b].sort()); }

  #gate(a, b, now) {
    this.#tick(now);
    if (this.#eligible(a) !== true || this.#eligible(b) !== true) return 'ineligible';
    if (a === b) return 'self';
    if (!this.#presence.has(a) || !this.#presence.has(b)) return 'offline';
    if (this.#member(a).blocks.has(b) || this.#member(b).blocks.has(a)) return 'blocked';
    return null;
  }

  #reject(reason) {
    this.#rejections[reason] = (this.#rejections[reason] ?? 0) + 1;
    return reason;
  }

  introduce(from, to, now) {
    const gate = this.#gate(from, to, now);
    if (gate) return this.#reject(gate);
    const old = this.#contacts.get(this.#pair(from, to));
    if (old) return old.status === 'replied' ? 'established' :
      ['pending', 'accepted'].includes(old.status) ? 'pending' : this.#reject('already-contacted');
    const sender = this.#member(from);
    const recipient = this.#member(to);
    if (!recipient.open) return this.#reject('closed');
    const pending = [...this.#contacts.values()].filter(c => c.to === to && c.status === 'pending').length;
    if (pending >= this.#policy.pendingCap) return this.#reject('inbox-full');
    if (this.#imbalance(sender) >= this.#policy.maxImbalance) return this.#reject('outbound-imbalance');
    if (sender.tokens < 1) return this.#reject('no-tokens');
    sender.tokens--;
    this.#count(sender, 'sent');
    sender.approaches++;
    recipient.maxPending = Math.max(recipient.maxPending, pending + 1);
    this.#contacts.set(this.#pair(from, to), {
      from, to, deadline: now + this.#policy.requestTtl, status: 'pending',
    });
    return 'delivered';
  }

  #request(recipient, sender) {
    const contact = this.#contacts.get(this.#pair(recipient, sender));
    return contact?.from === sender && contact.to === recipient ? contact : undefined;
  }

  accept(recipient, sender, now) {
    const gate = this.#gate(recipient, sender, now);
    if (gate) return this.#reject(gate);
    const contact = this.#request(recipient, sender);
    if (!contact) return 'missing';
    if (['accepted', 'replied'].includes(contact.status)) return 'duplicate';
    if (contact.status !== 'pending') return contact.status;
    const member = this.#member(recipient);
    if (-this.#imbalance(member) >= this.#policy.maxImbalance) return this.#reject('inbound-imbalance');
    this.#count(member, 'received');
    contact.status = 'accepted';
    return 'accepted';
  }

  reply(recipient, sender, now) {
    const gate = this.#gate(recipient, sender, now);
    if (gate) return this.#reject(gate);
    const contact = this.#request(recipient, sender);
    if (!contact) return 'missing';
    if (contact.status === 'replied') return 'duplicate';
    if (contact.status !== 'accepted') return 'unaccepted';
    const a = this.#member(sender);
    const b = this.#member(recipient);
    // A first reply is a recovery path and must not require introduction tokens.
    this.#count(b, 'sent');
    this.#count(a, 'received');
    a.activity = true;
    b.activity = true;
    contact.status = 'replied';
    return 'replied';
  }

  decline(recipient, sender, now) {
    const gate = this.#gate(recipient, sender, now);
    if (gate) return this.#reject(gate);
    const contact = this.#request(recipient, sender);
    if (!contact) return 'missing';
    if (contact.status !== 'pending') return contact.status;
    contact.status = 'declined';
    return 'declined';
  }

  vote(id, direction, now) {
    this.#tick(now);
    if (!this.#policy.voting) return 'disabled';
    if (direction !== 1 && direction !== -1) return 'invalid-vote';
    if (this.#eligible(id) !== true) return 'ineligible';
    if (!this.#presence.has(id)) return 'offline';
    if (this.#votes.has(id)) return 'already-voted';
    this.#votes.set(id, direction);
    return 'recorded';
  }

  advanceEpoch() {
    if (this.#policy.voting) {
      const total = [...this.#votes.values()].reduce((sum, vote) => sum + vote, 0);
      this.#policy.epochGrant = Math.max(0, Math.min(this.#policy.maxEpochGrant,
        this.#policy.epochGrant + Math.sign(total)));
    }
    this.#votes.clear();
    this.#epoch++;
    for (const member of this.#members.values()) {
      const oldest = this.#epoch - this.#policy.imbalanceEpochs + 1;
      for (const epoch of member.windows.keys()) {
        if (epoch < oldest) member.windows.delete(epoch);
      }
      if (member.activity) member.activeEpochs++;
      member.activity = false;
      const grant = Math.min(this.#policy.maxEpochGrant,
        this.#policy.epochGrant + member.activeEpochs * this.#policy.growthPerActiveEpoch);
      member.grantTotal += grant;
      member.tokens = Math.min(this.#policy.tokenCap, member.tokens + grant);
    }
  }

  /** Aggregate synthetic diagnostics, not a privacy-reviewed telemetry scheme. */
  metrics() {
    const members = [...this.#members.values()];
    const contacts = [...this.#contacts.values()];
    return {
      epoch: this.#epoch, registeredMembers: members.length, activeMembers: this.#presence.size,
      approaches: members.reduce((sum, member) => sum + member.approaches, 0),
      reciprocated: contacts.filter(contact => contact.status === 'replied').length,
      declines: contacts.filter(contact => contact.status === 'declined').length,
      matureMembers: members.filter(member => member.activeEpochs > 0).length,
      totalGranted: members.reduce((sum, member) => sum + member.grantTotal, 0),
      maxBalance: Math.max(0, ...members.map(member => member.tokens)),
      rejections: { ...this.#rejections },
    };
  }
}
