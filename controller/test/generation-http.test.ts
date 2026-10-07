import test from 'node:test';
import assert from 'node:assert/strict';
import {generationHTTP} from '../src/candidate/http.ts';
import {generationRequest} from '../src/candidate/wire.ts';
const enc=new TextEncoder();
const packet=text=>text.length+4<65536?(text.length+4).toString(16).padStart(4,'0')+text:'';
const advert=enc.encode(packet('# service=git-receive-pack\n')+'0000'+packet('0'.repeat(40)+' capabilities^{}\0report-status object-format=sha1\n')+'0000');
const intent={generationID:'a'.repeat(64),commitSHA:'b'.repeat(40)};
const pack=new Uint8Array(32);pack.set([80,65,67,75,0,0,0,2]);
function fixture(){
 let released=0,posts=0;const state={redirect:false,wrongOwner:false,noCapability:false,cleanupFail:false,lost:false};
 const credentials={acquire:async binding=>({id:'fixture-lease',token:'fixture_token',...binding,expiresAt:Math.floor(Date.now()/1000)+60}),release:async()=>{released++;if(state.cleanupFail)throw Error('SECRET-CLEANUP');}};
 const fetcher=async(url,options)=>{
  assert.equal(options.redirect,'manual');assert.equal(options.credentials,'omit');assert.equal(options.cache,'no-store');
  assert.ok(options.headers.Authorization.startsWith('Basic '));
  if(url==='https://api.github.com/repos/owner/fixture')return Response.json({id:7,full_name:'owner/fixture',owner:{id:state.wrongOwner?8:9,type:'User'},archived:false,fork:false});
  if(url==='https://github.com/owner/fixture.git/info/refs?service=git-receive-pack')return state.redirect?new Response('',{status:302,headers:{location:'https://evil.invalid'}}):new Response(state.noCapability?enc.encode('0000'):advert,{headers:{'content-type':'application/x-git-receive-pack-advertisement'}});
  assert.equal(url,'https://github.com/owner/fixture.git/git-receive-pack');assert.equal(options.method,'POST');posts++;if(state.lost)throw Error('SECRET-PROVIDER');
  return new Response(enc.encode(packet('unpack ok\n')+packet('ok refs/heads/int/'+intent.generationID+'\n')+'0000'),{headers:{'content-type':'application/x-git-receive-pack-result'}});
 };
 return {state,credentials,fetcher,api:generationHTTP({repository:'owner/fixture',repositoryID:7,ownerID:9,credentials,fetcher}),released:()=>released,posts:()=>posts};
}
test('fixed GitHub transport sends once and releases its scoped lease',async()=>{
 const f=fixture(),signal=new AbortController().signal;
 const bytes=await f.api.send(generationRequest(intent,pack),{signal});assert.ok(bytes.length);assert.equal(f.posts(),1);assert.equal(f.released(),1);
});
test('redirect, owner mismatch and unsupported discovery deny transfer and release credentials',async()=>{
 for(const key of ['redirect','wrongOwner','noCapability']){const f=fixture();f.state[key]=true;await assert.rejects(f.api.send(generationRequest(intent,pack),{signal:new AbortController().signal}));assert.equal(f.posts(),0);assert.equal(f.released(),1);}
});
test('lost transfer and cleanup failure are sanitized and never retried',async()=>{
 for(const key of ['lost','cleanupFail']){const f=fixture();f.state[key]=true;await assert.rejects(f.api.send(generationRequest(intent,pack),{signal:new AbortController().signal}),error=>!error.message.includes('SECRET'));assert.equal(f.posts(),1);assert.equal(f.released(),1);}
});

test('stalled discovery is bounded, aborted and cleans its lease without transfer',async()=>{
 const f=fixture();let observed;
 const fetcher=async(url,options)=>{if(url.includes('/info/refs')){observed=options.signal;return new Promise(()=>{});}return f.fetcher(url,options);};
 const api=generationHTTP({repository:'owner/fixture',repositoryID:7,ownerID:9,credentials:f.credentials,fetcher,timeoutMS:100});
 await assert.rejects(api.send(generationRequest(intent,pack),{signal:new AbortController().signal}),/uncertain/);
 assert.equal(observed.aborted,true);assert.equal(f.posts(),0);assert.equal(f.released(),1);
});
