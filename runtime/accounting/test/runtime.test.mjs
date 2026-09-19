import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, verify } from 'node:crypto';
import { loadArtifacts, resourceLimits, withPinnedBrowserWasm } from '../artifacts.mjs';
import { AccountClient, accountAcceptanceBytes, accountRequestBytes, verifyAccountAcceptance } from '../client.mjs';
import { policyDigest } from '../hashes.mjs';
import { validateStatement } from '../runtime.mjs';
import { cat, be, sha, hex } from '../encoding.mjs';
import { statementBytes } from '../witness.mjs';

const policy = {initialCredit:3,maximumAvailable:4,outgoingReservation:1,incomingReservation:1,
  policyRevision:1,policyValidFrom:1,policyValidUntil:10000,newcomerPeriod:100,rateWindow:100,
  newcomerAdmissions:2,maximumAdmissions:4,refillPeriod:100,refillUnits:1,abandonAfter:500};
const field = n => [...new Uint8Array(31),n], bytes = n => Array(32).fill(n);
const scope = {circuitDigest:bytes(41),verifyingKeyDigest:bytes(42)};
const text = value => new TextEncoder().encode(value);
const b64=(n,size=32)=>Buffer.alloc(size,n).toString('base64url');
const identity={grant:{version:1,issuerKeyId:b64(1),communityId:'test',memberId:b64(2),chatPublicKey:b64(3),policyDigest:b64(4),issuedAt:100,expiresAt:1000,signature:b64(5,64)},
  authorization:{version:1,communityId:'test',memberId:b64(2),rootPublicKey:b64(6),devicePublicKey:b64(3),issuedAt:100,expiresAt:1000,signature:b64(7,64)}};
async function statement() {
  return {protocolVersion:2,community:bytes(1),owner:bytes(2),policyDigest:Array.from(await policyDigest(Uint8Array.from(bytes(1)),policy)),
    enrollmentRoot:field(3),now:110,validUntil:200,genesis:true,previousVersion:0,nextVersion:0,
    previousState:field(0),nextState:field(4),settlementMarker:field(0),policy:{...policy}};
}
function key() { const pair=generateKeyPairSync('ed25519'); return {...pair,
  raw:new Uint8Array(pair.publicKey.export({format:'der',type:'spki'}).subarray(-32))}; }

test('artifact loading pins manifest and every byte, bounds cumulative bytes and rejects duplicate setup', async () => {
  const files={'circuit.json':text(JSON.stringify({bytecode:'test'})),'vk.bin':new Uint8Array([1]),
    'setup/g1.dat':new Uint8Array(32),'setup/g2.dat':new Uint8Array([2])};
  const manifest={version:1,compiler:'1.0.0-beta.26',backend:'5.0.0',verifierTarget:'noir-recursive',accountingMode:'account-state-v2',hashScheme:'poseidon2-bn254-fixed-128-v1',numPoints:1,
    circuitSha256:hex(await sha(files['circuit.json'])),vkSha256:hex(await sha(files['vk.bin'])),setup:[]};
  for(const name of ['g1.dat','g2.dat'])manifest.setup.push({name,bytes:files['setup/'+name].length,sha256:hex(await sha(files['setup/'+name]))});
  const make=async()=>{const manifestBytes=text(JSON.stringify(manifest));return {manifestBytes,manifestSha256:hex(await sha(manifestBytes)),readArtifact:async name=>files[name]};};
  const options=await make(); assert.equal((await loadArtifacts(options)).verificationKey[0],1);
  files['vk.bin'][0]=4; await assert.rejects(loadArtifacts(options),/digest/);files['vk.bin'][0]=1;
  await assert.rejects(loadArtifacts({...options,manifestSha256:'00'.repeat(32)}),/pin/);
  await assert.rejects(loadArtifacts({...options,limits:{maxTotalBytes:1}}),/total/);
  manifest.setup[1]=manifest.setup[0];await assert.rejects(loadArtifacts(await make()),/setup/);
  assert.throws(()=>resourceLimits({memoryPages:65536}),/limits/);
});

test('manifest and artifact bytes are snapshotted before asynchronous digest checks', async () => {
  const files={'circuit.json':text(JSON.stringify({bytecode:'verified-bytecode'})),'vk.bin':new Uint8Array([1,2,3]),
    'setup/g1.dat':new Uint8Array(32),'setup/g2.dat':new Uint8Array([2]),
    'barretenberg-threads.wasm':new Uint8Array([0,97,115,109,1,0,0,0,0,1,0])};
  const manifest={version:1,compiler:'1.0.0-beta.26',backend:'5.0.0',verifierTarget:'noir-recursive',
    accountingMode:'account-state-v2',hashScheme:'poseidon2-bn254-fixed-128-v1',numPoints:1,
    circuitSha256:hex(await sha(files['circuit.json'])),vkSha256:hex(await sha(files['vk.bin'])),setup:[],wasm:[]};
  for(const name of ['g1.dat','g2.dat'])manifest.setup.push({name,bytes:files['setup/'+name].length,sha256:hex(await sha(files['setup/'+name]))});
  manifest.wasm.push({name:'barretenberg-threads.wasm',bytes:files['barretenberg-threads.wasm'].length,
    sha256:hex(await sha(files['barretenberg-threads.wasm']))});
  const manifestBytes=text(JSON.stringify(manifest)),manifestSha256=hex(await sha(manifestBytes));
  const expectedWasm=files['barretenberg-threads.wasm'].slice();
  const original=crypto.subtle.digest,ownDescriptor=Object.getOwnPropertyDescriptor(crypto.subtle,'digest');
  let current='manifest';
  Object.defineProperty(crypto.subtle,'digest',{configurable:true,value:function(algorithm,data){
    const result=original.call(this,algorithm,data);
    // WebCrypto has copied its input. Mutate the provider's retained backing
    // buffer before digest completion; returned/parsed bytes must stay pinned.
    if(current==='manifest')manifestBytes.fill(0);
    else if(current==='vk.bin'||current==='barretenberg-threads.wasm')files[current].fill(255);
    return result;
  }});
  try {
    const loaded=await loadArtifacts({manifestBytes,manifestSha256,loadBrowserWasm:true,
      readArtifact:async name=>{current=name;return files[name];}});
    assert.equal(loaded.manifest.numPoints,1);
    assert.deepEqual(loaded.verificationKey,new Uint8Array([1,2,3]));
    assert.deepEqual(loaded.browserWasm,expectedWasm);
    assert.notDeepEqual(loaded.browserWasm,files['barretenberg-threads.wasm']);
  } finally {
    if(ownDescriptor)Object.defineProperty(crypto.subtle,'digest',ownDescriptor);
    else delete crypto.subtle.digest;
  }
});

test('bb.js suffix rewriting fetches only immutable pinned Blob bytes and URLs are revoked', async () => {
  const verified=new Uint8Array([0,97,115,109,1,0,0,0,0,1,0]),expected=verified.slice();
  let consumedUrl;
  const received=await withPinnedBrowserWasm(verified,async wasmPath=>{
    // Exact public bb.js 5.0.0 fetchCode URL behavior; fetch itself is real.
    const filePath=wasmPath.split('/').slice(0,-1).join('/');
    const [fileName,...extensions]=wasmPath.split('/').pop().split('.');
    consumedUrl=`${filePath}/${fileName}-threads.${extensions.join('.')}`;
    assert.equal(new URL(consumedUrl).protocol,'blob:');
    verified.fill(255);
    const response=await fetch(consumedUrl);
    return new Uint8Array(await response.arrayBuffer());
  });
  assert.deepEqual(received,expected);
  await assert.rejects(fetch(consumedUrl));
  let failedUrl;
  await assert.rejects(withPinnedBrowserWasm(expected,async wasmPath=>{failedUrl=wasmPath;throw new Error('init failed');}),/init failed/);
  await assert.rejects(fetch(failedUrl));
});

test('live statement times and policy encoding replace synthetic acceptedTimes lists', async () => {
  const s=await statement();s.now=Date.UTC(2026,8,19)/1000;s.policy.policyValidUntil=s.now+10000;
  s.validUntil=(Math.floor(s.now/s.policy.rateWindow)+1)*s.policy.rateWindow;
  s.policyDigest=Array.from(await policyDigest(Uint8Array.from(s.community),s.policy));
  assert.equal((await validateStatement(s)).length,243);
  const changed=structuredClone(s);changed.policy.abandonAfter+=1;await assert.rejects(validateStatement(changed),/policy/);
  const extra={...s,privateOpening:{}};await assert.rejects(validateStatement(extra),/Exact/);
});

test('signed public request has the Rust transcript; verified response must bind the exact retry', async () => {
  const device=key(),operator=key(),s=await statement();let transported;
  const client=new AccountClient({operatorPublicKey:operator.raw,sign:async bytes=>sign(null,bytes,device.privateKey),
    transport:async envelope=>{transported=envelope;const r=envelope.request;
      const a={statement:r.statement,requestId:r.requestId,requestDigest:Array.from(await sha(cat(await accountRequestBytes(r),Buffer.from(r.signature,'base64url')))),
        proofScope:r.proofScope,acceptedAt:111,signature:''};
      a.signature=sign(null,await accountAcceptanceBytes(a),operator.privateKey).toString('base64url');return {action:'apply',value:a};}});
  const request=await client.prepareApply({record:{statement:s,proof:'010203',proofScope:scope},chatPublicKey:Buffer.from(device.raw).toString('base64url'),expiresAt:180,requestId:bytes(9)});
  const independent=cat(text('cfrm.account.request.v1\0'),bytes(9),scope.circuitDigest,scope.verifyingKeyDigest,device.raw,
    be(110,8),be(180,8),await sha(statementBytes(s)),await sha(new Uint8Array([1,2,3])));
  assert(verify(null,independent,device.publicKey,Buffer.from(request.signature,'base64url')));
  const acceptance=await client.apply({...identity,request});
  assert.equal(transported.action,'apply');assert.equal(acceptance.statement.nextVersion,0);
  const altered=structuredClone(request);altered.requestId[0]^=1;
  await assert.rejects(verifyAccountAcceptance(acceptance,operator.raw,altered),/match/);
  await assert.rejects(client.prepareApply({record:{statement:s,proof:'01',proofScope:scope,input:{secret:true}},chatPublicKey:request.chatPublicKey,expiresAt:180}),/Public/);
  await assert.rejects(client.apply({grant:{},authorization:{},request:{...request,input:{secret:true}}}),/Exact/);
  await assert.rejects(client.apply({grant:{...identity.grant,privateOpening:{}},authorization:identity.authorization,request}),/Exact public/);
  await assert.rejects(client.apply({...identity,request:{...request,proofScope:{...scope,privateOpening:{}}}}),/Exact public proof/);
});
