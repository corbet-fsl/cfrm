import { profileDiscoveryInteropFixture } from '../browser/profiles/contract.mjs';
process.stdout.write(JSON.stringify(await profileDiscoveryInteropFixture()) + '\n');
