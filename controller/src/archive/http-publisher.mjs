import {digest} from '../ledger.mjs';
// The private service performs R2 readback. This client validates its receipt;
// get() returns the exact locally retained envelope confirmed by that receipt.
export function recoveryHTTPPublisher({origin,audiencePrefix,oidcURL,oidcBearer,runID,runAttempt,intent,fetcher=fetch,clock=()=>Date.now()}){
 const endpoint=new URL(origin),oidc=new URL(oidcURL);
 if(endpoint.protocol!=='https:'||endpoint.username||endpoint.password||endpoint.pathname!=='/'||endpoint.search||endpoint.hash||oidc.protocol!=='https:'||!oidc.hostname.endsWith('.actions.githubusercontent.com')||oidc.username||oidc.password||oidc.hash||typeof audiencePrefix!=='string'||!/^[-A-Za-z0-9_.]{1,100}$/.test(audiencePrefix)||typeof oidcBearer!=='string'||!oidcBearer||!Number.isSafeInteger(runID)||runID<1||!Number.isSafeInteger(runAttempt)||runAttempt<1)throw Error('Invalid recovery transport installation');
 const approved=structuredClone(intent);let confirmed;
 async function json(url,options){const r=await fetcher(url,{...options,redirect:'error',signal:AbortSignal.timeout(15000)});if(!r.ok)throw Error('Recovery transport refused');const bytes=await r.text();if(bytes.length>20000)throw Error('Oversized transport response');return JSON.parse(bytes);}
 return {async create(key,envelope){
  const expectedKey='recovery/v1/'+approved.repositoryID+'/'+await digest(approved)+'.json';if(key!==expectedKey)throw Error('Recovery publication key differs');
  const publication={intent:approved,envelope:structuredClone(envelope)},envelopeDigest=await digest(envelope);
  const url=new URL(oidc);url.searchParams.set('audience',audiencePrefix+':'+await digest(publication));
  const identity=await json(url,{headers:{Authorization:'Bearer '+oidcBearer}});if(typeof identity.value!=='string'||!identity.value||identity.value.length>20000)throw Error('Missing recovery identity');
  const receipt=await json(new URL('/v1/archive/recovery/upload',endpoint),{method:'POST',headers:{Authorization:'Bearer '+identity.value,'Content-Type':'application/json'},body:JSON.stringify({publication,runID,runAttempt})});
  if(receipt.protocol!=='repoctl-recovery-publication-v1'||receipt.published!==true||receipt.repositoryID!==approved.repositoryID||receipt.key!==key||receipt.envelopeDigest!==envelopeDigest||receipt.reportDigest!==await digest(envelope.payload.report)||receipt.expiresAt!==envelope.payload.expiresAt||receipt.expiresAt<=clock())throw Error('Recovery publication receipt differs');
  confirmed={key,envelope:publication.envelope};
 },async get(key){if(!confirmed||confirmed.key!==key)throw Error('Recovery publication not confirmed');return structuredClone(confirmed.envelope);}};
}
