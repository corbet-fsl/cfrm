// Test-only fixed Ed25519 seed. Never used by the runtime or a deployment.
import { createPrivateKey,sign } from 'node:crypto';
import { AccountClient,verifyAccountAcceptance } from '../client.mjs';
const chunks=[];for await(const chunk of process.stdin)chunks.push(chunk);
const input=JSON.parse(Buffer.concat(chunks));
if(process.argv[2]==='prepare') {
  const key=createPrivateKey({format:'der',type:'pkcs8',key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.alloc(32,2)])});
  const client=new AccountClient({transport:()=>{throw new Error('No transport in signing phase');},
    sign:bytes=>sign(null,bytes,key),operatorPublicKey:input.operatorPublicKey});
  const request=await client.prepareApply(input.prepare);
  process.stdout.write(JSON.stringify({action:'apply',grant:input.grant,authorization:input.authorization,request}));
} else if(process.argv[2]==='verify') {
  await verifyAccountAcceptance(input.acceptance,input.operatorPublicKey,input.request);
  process.stdout.write(JSON.stringify({ok:true}));
} else throw new Error('Unknown test mode');
