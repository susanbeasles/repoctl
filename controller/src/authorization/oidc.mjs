const encoder=new TextEncoder();
const issuer='https://token.actions.githubusercontent.com';
const reject=message=>{throw new Error(message);};
function decode(value){
 if(typeof value!=='string'||!value.length||!/^[A-Za-z0-9_-]+$/.test(value))reject('Invalid OIDC encoding');
 return Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-value.length%4)%4)),c=>c.charCodeAt(0));
}
function json(value){return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(decode(value)));}
// No JWT-selected URL, algorithm, issuer or JWK. The only production JWKS origin
// is GitHub's documented issuer; tests inject key inventory, not an alternate URL.
export async function githubJWKS(fetcher=fetch){
 const response=await fetcher(`${issuer}/.well-known/jwks`,{redirect:'error',signal:AbortSignal.timeout(10000)});
 if(!response.ok)reject('OIDC trust-key retrieval failed');
 const raw=await response.text();if(raw.length>128000)reject('OIDC trust-key inventory too large');
 const data=JSON.parse(raw);if(!Array.isArray(data.keys)||data.keys.length>32)reject('Invalid OIDC trust-key inventory');
 return data;
}
export async function verifyExecutorOIDC(token,trust,{operationID,runID,runAttempt},jwks,now=Math.floor(Date.now()/1000)){
 if(typeof token!=='string'||token.length>20000)reject('Invalid OIDC token size');
 const parts=token.split('.');if(parts.length!==3)reject('Invalid OIDC token');
 const header=json(parts[0]);
 if(header.alg!=='RS256'||typeof header.kid!=='string'||header.jku||header.jwk||header.x5u||header.crit)reject('Unsupported OIDC signature header');
 const keys=jwks?.keys?.filter(k=>k.kid===header.kid&&k.kty==='RSA'&&(k.alg===undefined||k.alg==='RS256')&&(k.use===undefined||k.use==='sig')&&!k.d);
 if(keys?.length!==1)reject('Unknown or ambiguous OIDC signing key');
 const key=await crypto.subtle.importKey('jwk',keys[0],{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
 if(!await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,decode(parts[2]),encoder.encode(`${parts[0]}.${parts[1]}`)))reject('Invalid OIDC signature');
 const c=json(parts[1]);
 if(c.iss!==issuer||c.aud!==`${trust.audiencePrefix}:${operationID}`)reject('Wrong OIDC issuer/audience');
 if(![c.exp,c.iat,c.nbf].every(Number.isSafeInteger)||c.exp<=now||c.iat>now+30||c.nbf>now+30||c.exp<=c.iat||c.exp-c.iat>600||c.iat<now-600)reject('Expired or invalid OIDC lifetime');
 const exact={repository:trust.repository,repository_id:String(trust.repositoryID),repository_owner_id:String(trust.ownerID),ref:trust.ref,workflow_ref:trust.workflowRef,workflow_sha:trust.workflowSHA,job_workflow_ref:trust.jobWorkflowRef,job_workflow_sha:trust.jobWorkflowSHA,runner_environment:'github-hosted',run_id:String(runID),run_attempt:String(runAttempt)};
 for(const [name,value]of Object.entries(exact))if(typeof value!=='string'||!value.length||c[name]!==value)reject(`Untrusted executor claim: ${name}`);
 if(!trust.eventNames?.includes(c.event_name)||!trust.actorIDs?.includes(Number(c.actor_id)))reject('Untrusted executor event/actor');
 if(typeof c.jti!=='string'||c.jti.length<8||c.jti.length>200)reject('Missing OIDC replay identity');
 return {jti:c.jti,runID:String(runID),runAttempt:String(runAttempt),expiresAt:c.exp,workflowSHA:c.job_workflow_sha};
}
