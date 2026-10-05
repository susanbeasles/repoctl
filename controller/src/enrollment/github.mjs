import {appJWTSigner} from '../runtime/app-signer.mjs';
const roles={writer:{contents:'write'},validator:{contents:'read',checks:'read',actions:'read',security_events:'read'},builder:{contents:'write',pull_requests:'write'},release:{contents:'write'}};
const sorted=x=>JSON.stringify(Object.entries(x).sort(([a],[b])=>a.localeCompare(b)));
export function githubEnrollmentProvider(fetcher=fetch,clock=()=>Math.floor(Date.now()/1000)){
 async function request(path,options){
  const r=await fetcher(`https://api.github.com${path}`,{...options,redirect:'error',signal:AbortSignal.timeout(10000),headers:{Accept:'application/vnd.github+json','User-Agent':'repoctl-isolated-enrollment','X-GitHub-Api-Version':'2026-03-10',...options.headers}});
  if(!r.ok)throw Error('GitHub enrollment request rejected');
  const reader=r.body?.getReader();if(!reader)throw Error('Empty GitHub enrollment response');let size=0;const chunks=[];
  while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>65536){await reader.cancel();throw Error('Oversized GitHub enrollment response');}chunks.push(value);}
  const raw=new Uint8Array(size);let offset=0;for(const c of chunks){raw.set(c,offset);offset+=c.length;}return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
 }
 return {
  exchangeManifestCode(code){if(typeof code!=='string'||! /^[A-Za-z0-9_-]{1,200}$/.test(code))throw Error('Invalid manifest conversion code');return request(`/app-manifests/${code}/conversions`,{method:'POST'});},
  async verifyApp({appID,ownerID,role,key},session){
   if(!roles[role]||session.ownerID!==ownerID||session.role!==role)throw Error('Enrollment identity mismatch');
   const now=clock(),jwt=await appJWTSigner({appID,key,clock})({appID,issuedAt:now-60,expiresAt:now+300});
   const app=await request('/app',{method:'GET',headers:{Authorization:`Bearer ${jwt}`}});
   // Metadata read is GitHub's mandatory implicit repository permission.
   const expected={...roles[role],metadata:'read'};
   if(app.id!==appID||app.owner?.id!==ownerID||!app.permissions||sorted(app.permissions)!==sorted(expected)||!Array.isArray(app.events)||app.events.length!==0)throw Error('GitHub App owner, permissions or events differ from approved role');
   const payload=JSON.stringify({appID,ownerID,role,permissions:expected,events:[]});
   const digest=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(payload))),b=>b.toString(16).padStart(2,'0')).join('');
   return {verified:true,appID,ownerID,role,digest};
  }
 };
}
