import { writeFileSync } from 'node:fs';
import { defaultExperiment, simulate, sweep, comparePolicies } from '../src/simulate.js';

const args = process.argv.slice(2);
let config = { ...defaultExperiment };
let sweepMode = false;
let comparison = false;
let json = false;
let output;
for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === '--sweep') sweepMode = true;
  else if (arg === '--compare') comparison = true;
  else if (arg === '--json') json = true;
  else if (['--seed', '--epochs', '--rounds'].includes(arg)) config[arg.slice(2)] = Number(args[++i]);
  else if (arg === '--population') config.population = JSON.parse(args[++i]);
  else if (arg === '--policy') config.policy = { ...config.policy, ...JSON.parse(args[++i]) };
  else if (arg === '--output') output = args[++i];
  else throw new Error(`Unknown option: ${arg}`);
}
if (sweepMode && comparison) throw new Error('Choose either --sweep or --compare');
const result = comparison ? comparePolicies(config) : sweepMode ? sweep(config) : simulate(config);
if (output) writeFileSync(output, JSON.stringify(result, null, 2) + '\n');
if (json) console.log(JSON.stringify(result, null, 2));
else if (sweepMode || comparison) console.table(result);
else {
  console.log(`Synthetic participants: ${result.config.participants}; seed: ${result.config.seed}; epochs: ${result.config.epochs}`);
  console.table(result.byBehavior);
  console.log(JSON.stringify({ final: result.final, bound: result.bound, invariants: result.invariants }, null, 2));
}
