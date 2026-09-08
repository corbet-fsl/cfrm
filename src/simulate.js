import { ForumExperiment } from './forum.js';

export const defaultExperiment = Object.freeze({
  seed: 42, epochs: 8, rounds: 12,
  population: Object.freeze({ cooperative: 64, flooder: 10, nonreciprocator: 10,
    'colluding-pair': 2, 'colluding-ring': 8, resetter: 6 }),
  policy: Object.freeze({ initialTokens: 3, epochGrant: 2, maxEpochGrant: 6, tokenCap: 8,
    growthPerActiveEpoch: 1, maxImbalance: 3, pendingCap: 3,
    requestTtl: 5, presenceTtl: 20, voting: false, imbalanceEpochs: 0 }),
});

function randomSource(seed) {
  // xorshift32 for repeatable experiments; never a cryptographic generator.
  let state = seed || 0x9e3779b9;
  return () => {
    state ^= state << 13; state ^= state >>> 17; state ^= state << 5;
    return (state >>> 0) / 4294967296;
  };
}

function shuffled(items, random) {
  const result = [...items];
  for (let i = result.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
}

const known = new Set(['cooperative', 'flooder', 'nonreciprocator',
  'colluding-pair', 'colluding-ring', 'resetter']);

export function simulate(config) {
  const { seed, epochs, rounds, population, policy } = config;
  if (!Number.isSafeInteger(seed) || seed < 0 || seed > 0xffffffff ||
      !Number.isSafeInteger(epochs) || epochs < 1 || epochs > 120 ||
      !Number.isSafeInteger(rounds) || rounds < 1 || rounds > 64 ||
      !population || typeof population !== 'object') throw new TypeError('Invalid experiment bounds');
  for (const [kind, count] of Object.entries(population)) {
    if (!known.has(kind) || !Number.isSafeInteger(count) || count < 0) throw new TypeError('Invalid population');
  }
  const count = Object.values(population).reduce((sum, n) => sum + n, 0);
  if (count < 2 || count > 500 || (population['colluding-pair'] ?? 0) % 2 !== 0) {
    throw new RangeError('Use 2–500 participants and an even colluding-pair population');
  }
  const random = randomSource(seed);
  const members = [];
  const cohorts = {};
  for (const [kind, count] of Object.entries(population)) {
    cohorts[kind] = [];
    for (let i = 0; i < count; i++) {
      const member = { id: `m${members.length.toString().padStart(3, '0')}`, kind, index: i };
      members.push(member); cohorts[kind].push(member);
    }
  }
  const byId = new Map(members.map(member => [member.id, member]));
  // Synthetic identity issuance is intentionally distinct from cvld verification.
  const forum = new ForumExperiment(policy, id => byId.has(id));
  const timeline = [];
  let now = 0;
  let withinTokenCap = true;
  let nonnegativeTokens = true;
  const lateStarts = new Map();
  const randomPeer = member => {
    const index = members.indexOf(member);
    const pick = Math.floor(random() * (members.length - 1));
    return members[pick >= index ? pick + 1 : pick];
  };
  const strategies = {
    cooperative(member) {
      if (random() < 0.25) forum.introduce(member.id, randomPeer(member).id, now);
    },
    flooder(member) {
      for (let i = 0; i < 20; i++) forum.introduce(member.id, randomPeer(member).id, now);
    },
    nonreciprocator() {},
    'colluding-pair'(member) {
      const peer = cohorts[member.kind][member.index ^ 1];
      forum.introduce(member.id, peer.id, now);
    },
    'colluding-ring'(member, epoch) {
      const peers = cohorts[member.kind];
      const peer = peers[(member.index + epoch + 1) % peers.length];
      if (peer !== member) forum.introduce(member.id, peer.id, now);
    },
    resetter(member) {
      forum.disconnect(member.id);
      forum.connect(member.id, now);
      strategies.flooder(member);
    },
  };

  for (let epoch = 0; epoch < epochs; epoch++) {
    if (epoch > 0) forum.advanceEpoch();
    for (let round = 0; round < rounds; round++) {
      now++;
      for (const member of members) forum.connect(member.id, now);
      if (epoch === Math.floor(epochs * 0.75) && round === 0) {
        for (const member of members) lateStarts.set(member.id, forum.state(member.id).approaches);
      }
      for (const member of shuffled(members, random)) strategies[member.kind](member, epoch);
      for (const member of shuffled(members, random)) {
        for (const request of forum.requestsFor(member.id)) {
          const sender = byId.get(request.from);
          const colluder = member.kind.startsWith('colluding-');
          const samePair = member.kind !== 'colluding-pair' ||
            Math.floor(member.index / 2) === Math.floor(sender.index / 2);
          const responds = member.kind === 'cooperative' ||
            (colluder && sender.kind === member.kind && samePair);
          if (responds || member.kind === 'nonreciprocator') {
            const accepted = forum.accept(member.id, sender.id, now);
            if (responds && accepted === 'accepted') forum.reply(member.id, sender.id, now);
          } else {
            forum.decline(member.id, sender.id, now);
          }
        }
        if (policy.voting && round === 0) forum.vote(member.id, random() < 0.5 ? -1 : 1, now);
        const state = forum.state(member.id);
        withinTokenCap &&= state.tokens <= policy.tokenCap;
        nonnegativeTokens &&= state.tokens >= 0;
      }
    }
    timeline.push({ epoch, ...forum.metrics() });
  }
  // Abrupt loss is modelled by lease expiry without explicit disconnect calls.
  forum.roster(now + policy.presenceTtl);
  const byBehavior = {};
  for (const [kind, cohort] of Object.entries(cohorts)) {
    if (!cohort.length) continue;
    const states = cohort.map(member => forum.state(member.id));
    byBehavior[kind] = {
      participants: states.length,
      approaches: states.reduce((sum, state) => sum + state.approaches, 0),
      maxActiveEpochs: Math.max(...states.map(state => state.activeEpochs)),
      maxInboundImbalance: Math.max(...states.map(state => state.received - state.sent)),
      maxOutboundImbalance: Math.max(...states.map(state => state.sent - state.received)),
      totalGranted: states.reduce((sum, state) => sum + state.grantTotal, 0),
      reciprocatedApproaches: cohort.reduce((sum, member) => sum + forum.outcomes(member.id).reciprocatedApproaches, 0),
      lateApproaches: cohort.reduce((sum, member) => sum + forum.state(member.id).approaches - lateStarts.get(member.id), 0),
    };
  }
  const perMemberBound = policy.initialTokens + (epochs - 1) * policy.maxEpochGrant;
  const withinGrantBound = members.every(member => {
    const state = forum.state(member.id);
    return state.approaches <= state.grantTotal && state.grantTotal <= perMemberBound;
  });
  return {
    config: { seed, epochs, rounds, participants: members.length, population: { ...population }, policy: { ...policy } },
    bound: members.length * perMemberBound,
    invariants: { withinGrantBound, withinTokenCap, nonnegativeTokens },
    final: forum.metrics(), byBehavior, timeline,
    exposure: {
      maxUnsolicitedPerTarget: Math.max(...members.map(member => forum.outcomes(member.id).unsolicitedReceived)),
      maxPending: Math.max(...members.map(member => forum.outcomes(member.id).maxPending)),
    },
  };
}

export function sweep(config, seeds = [1, 42, 101], imbalances = [1, 3, 6]) {
  return seeds.flatMap(seed => imbalances.map(maxImbalance => {
    const result = simulate({ ...config, seed, policy: { ...config.policy, maxImbalance } });
    return { seed, maxImbalance, approaches: result.final.approaches,
      reciprocated: result.final.reciprocated,
      unreciprocated: result.final.approaches - result.final.reciprocated,
      matureMembers: result.final.matureMembers,
      withinGrantBound: result.invariants.withinGrantBound };
  }));
}

export function comparePolicies(config, seeds = [1, 42, 101], horizons = [0, 1, 2, 4]) {
  const populations = {
    balanced: { cooperative: 80, flooder: 10, nonreciprocator: 10 },
    mixed: defaultExperiment.population,
    hostile: { cooperative: 40, flooder: 30, nonreciprocator: 20, resetter: 10 },
  };
  return Object.entries(populations).flatMap(([population, members]) => seeds.flatMap(seed =>
    horizons.map(imbalanceEpochs => {
      const result = simulate({ ...config, seed, population: members,
        policy: { ...config.policy, imbalanceEpochs } });
      const cooperative = result.byBehavior.cooperative;
      const hostile = ['flooder', 'resetter'].map(kind => result.byBehavior[kind]).filter(Boolean);
      return { population, seed, imbalanceEpochs,
        cooperativeReciprocated: cooperative.reciprocatedApproaches,
        cooperativeLateApproaches: cooperative.lateApproaches,
        hostileApproaches: hostile.reduce((sum, state) => sum + state.approaches, 0),
        hostileUnreciprocated: hostile.reduce((sum, state) => sum + state.approaches - state.reciprocatedApproaches, 0),
        maxUnsolicitedPerTarget: result.exposure.maxUnsolicitedPerTarget,
        maxPending: result.exposure.maxPending,
        withinGrantBound: result.invariants.withinGrantBound };
    })));
}
