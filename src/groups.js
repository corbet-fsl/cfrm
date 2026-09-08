/** Synthetic consent/fanout model. No group ID or roster belongs in an operator log. */
export class GroupExperiment {
  #forum;
  #limit;
  #groups = new Map();

  constructor(forum, maxMembers) {
    if (!Number.isSafeInteger(maxMembers) || maxMembers < 2 || maxMembers > 100) {
      throw new RangeError('Experimental group size must be 2–100');
    }
    this.#forum = forum;
    this.#limit = maxMembers;
  }

  #online(id, now) { return this.#forum.roster(now).includes(id); }

  create(owner, groupId, now) {
    if (!this.#online(owner, now)) return 'offline';
    if (typeof groupId !== 'string' || !groupId.length) return 'invalid-group';
    if (this.#groups.has(groupId)) return 'exists';
    this.#groups.set(groupId, { members: new Set([owner]), invitations: new Map() });
    return 'created';
  }

  invite(inviter, groupId, recipient, now) {
    const group = this.#groups.get(groupId);
    if (!group?.members.has(inviter)) return 'not-member';
    if (group.members.has(recipient)) return 'already-member';
    if (group.members.size >= this.#limit) return 'full';
    if (group.invitations.has(recipient)) return 'already-invited';
    const result = this.#forum.introduce(inviter, recipient, now);
    // Pending introductions cannot become an unbounded alternate invite channel.
    if (result !== 'delivered' && result !== 'established') return result;
    group.invitations.set(recipient, { inviter, established: result === 'established' });
    return 'invited';
  }

  join(recipient, groupId, now) {
    const group = this.#groups.get(groupId);
    if (group?.members.has(recipient)) return 'already-member';
    const invitation = group?.invitations.get(recipient);
    if (!invitation) return 'not-invited';
    if (group.members.size >= this.#limit) return 'full';
    if (!this.#online(recipient, now)) return 'offline';
    if (invitation.established) {
      // Recheck current blocks, eligibility and inviter presence before consent.
      const current = this.#forum.introduce(invitation.inviter, recipient, now);
      if (current !== 'established') return current;
    } else {
      const accepted = this.#forum.accept(recipient, invitation.inviter, now);
      if (accepted !== 'accepted' && accepted !== 'duplicate') return accepted;
      const replied = this.#forum.reply(recipient, invitation.inviter, now);
      if (replied !== 'replied' && replied !== 'duplicate') return replied;
    }
    group.members.add(recipient);
    group.invitations.delete(recipient);
    return 'joined';
  }

  send(sender, groupId, now) {
    if (!this.#groups.get(groupId)?.members.has(sender)) return 'not-member';
    if (!this.#online(sender, now)) return 'offline';
    return 'allowed';
  }

  size(groupId) { return this.#groups.get(groupId)?.members.size ?? 0; }
}
