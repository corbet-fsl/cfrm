import test from 'node:test';
import { profileContractCases } from '../browser/profiles/contract.mjs';

for (const [name, run] of profileContractCases) test(`profile client: ${name}`, run);
