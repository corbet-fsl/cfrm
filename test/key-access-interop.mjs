// Invoked by the native integration test with real issued/redeemed public evidence.
import { createProfileTicketVerifier,keyAccessIssueBytes } from '../browser/profiles/tickets.js';
const chunks=[];for await(const chunk of process.stdin)chunks.push(chunk);
const value=JSON.parse(Buffer.concat(chunks));
const verify=await createProfileTicketVerifier({epoch:value.epoch,clock:()=>value.now});
const input={ticket:value.stamp,challengeDigest:value.challengeDigest,expiresAt:value.expiresAt};
const ok=await verify(input);
const changedChallengeAccepted=await verify({...input,challengeDigest:Buffer.alloc(32,99).toString('base64url')});
process.stdout.write(JSON.stringify({ok,changedChallengeAccepted,issueBytes:Buffer.from(await keyAccessIssueBytes(value.issueRequest)).toString('base64url')}));
