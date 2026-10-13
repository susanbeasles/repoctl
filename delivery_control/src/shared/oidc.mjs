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
 const response=await fetcher(`${issuer}/.well-known/jwks`,{redirect:'manual',signal:AbortSignal.timeout(10000)});
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

// Shared deployment wrapper keeps the reviewed signature verifier above intact.
// Trust comes from installed policy, never from the token or request body.
export function validateTrust(t){
 const fields=['audiencePrefix','repository','repositoryID','ownerID','ref','workflowRef','workflowSHA','jobWorkflowRef','jobWorkflowSHA','eventNames','actorIDs'];
 const positive=v=>Number.isSafeInteger(v)&&v>0,sha=/^[a-f0-9]{40}$/;
 if(!t||Object.getPrototypeOf(t)!==Object.prototype||Object.keys(t).sort().join()!==fields.sort().join())reject('Invalid executor trust schema');
 if(!['audiencePrefix','repository','ref','workflowRef','workflowSHA','jobWorkflowRef','jobWorkflowSHA'].every(k=>typeof t[k]==='string'))reject('Invalid executor trust field type');
 if(typeof t.audiencePrefix!=='string'||! /^[A-Za-z0-9_.:-]{1,200}$/.test(t.audiencePrefix)||! /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(t.repository)||!positive(t.repositoryID)||!positive(t.ownerID)||! /^refs\/heads\/[A-Za-z0-9_.\/-]+$/.test(t.ref)||![t.workflowSHA,t.jobWorkflowSHA].every(v=>sha.test(v)))reject('Invalid executor trust identity');
 const workflow=/^([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)\/\.github\/workflows\/[A-Za-z0-9_.-]+\.ya?ml@(refs\/heads\/[A-Za-z0-9_.\/-]+|[a-f0-9]{40})$/;
 const caller=typeof t.workflowRef==='string'&&t.workflowRef.match(workflow),job=typeof t.jobWorkflowRef==='string'&&t.jobWorkflowRef.match(workflow);
 if(!caller||caller[1]!==t.repository||caller[2]!==t.ref||!job||(sha.test(job[2])&&job[2]!==t.jobWorkflowSHA))reject('Invalid pinned workflow identity');
 if(!Array.isArray(t.eventNames)||!t.eventNames.length||t.eventNames.length>20||!t.eventNames.every(v=>typeof v==='string'&&/^[a-z][a-z0-9_]{0,63}$/.test(v))||new Set(t.eventNames).size!==t.eventNames.length||!Array.isArray(t.actorIDs)||!t.actorIDs.length||t.actorIDs.length>100||!t.actorIDs.every(positive)||new Set(t.actorIDs).size!==t.actorIDs.length)reject('Invalid executor event or actor policy');
 return t;
}
export async function verifyOIDC(token,trust,binding,jwks,now=Math.floor(Date.now()/1000)){
 validateTrust(trust);
 if(!binding||Object.keys(binding).sort().join()!==['operationID','runID','runAttempt'].sort().join()||typeof binding.operationID!=='string'||! /^[a-f0-9]{64}$/.test(binding.operationID)||![binding.runID,binding.runAttempt,now].every(v=>Number.isSafeInteger(v)&&v>0))reject('Invalid execution binding');
 return verifyExecutorOIDC(token,trust,binding,jwks,now);
}
