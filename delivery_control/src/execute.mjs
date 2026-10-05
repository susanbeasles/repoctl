// Built-ins only. No candidate checkout, package install, shell, or dynamic import.
const oidcIssuer='https://token.actions.githubusercontent.com';
const sha=/^[a-f0-9]{40}$/;
async function jsonFetch(url,options,fetcher){const r=await fetcher(url,{...options,redirect:'error',signal:AbortSignal.timeout(15000)});if(!r.ok)throw Error(`Remote operation failed (HTTP ${r.status})`);return r.json();}
export async function execute({operationID,controller,oidcURL,oidcBearer,audiencePrefix},fetcher=fetch,clock=()=>Math.floor(Date.now()/1000)){
 if(!/^[a-f0-9]{64}$/.test(operationID??''))throw Error('Invalid operation identity');
 const origin=new URL(controller);if(origin.protocol!=='https:'||origin.username||origin.password||origin.pathname!=='/'||origin.search||origin.hash)throw Error('Invalid trusted controller origin');
 const oidc=new URL(oidcURL);if(oidc.protocol!=='https:'||!oidc.hostname.endsWith('.actions.githubusercontent.com')||oidc.username||oidc.password)throw Error('Invalid GitHub OIDC request endpoint');
 oidc.searchParams.set('audience',`${audiencePrefix}:${operationID}`);
 async function jwt(){const r=await jsonFetch(oidc,{headers:{Authorization:`Bearer ${oidcBearer}`}},fetcher);if(typeof r.value!=='string')throw Error('Missing OIDC token');return r.value;}
 let grant,outcome='failed',revoked=false;
 try{
  grant=await jsonFetch(new URL('/v1/execution/lease',origin),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({operationID,oidcToken:await jwt()})},fetcher);
  const p=grant.intent;
  if(grant.operationID!==operationID||typeof grant.token!=='string'||!Number.isSafeInteger(grant.operationExpiresAt)||grant.operationExpiresAt<=clock()||!p||!Number.isSafeInteger(p.repositoryID)||!/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(p.repository)||!['main','master'].includes(p.branch)||![p.baseSHA,p.commitSHA,p.treeSHA].every(s=>sha.test(s)))throw Error('Invalid controller lease');
  const root=`https://api.github.com/repos/${p.repository}`;
  const headers={Authorization:`Bearer ${grant.token}`,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2026-03-10','User-Agent':'repoctl-central-executor','Content-Type':'application/json'};
  const metadata=await jsonFetch(root,{headers},fetcher);if(metadata.id!==p.repositoryID||metadata.archived||metadata.fork)throw Error('Repository identity mismatch');
  const commit=await jsonFetch(`${root}/git/commits/${p.commitSHA}`,{headers},fetcher);
  if(commit.sha!==p.commitSHA||commit.parents?.length!==1||commit.parents[0].sha!==p.baseSHA||commit.tree?.sha!==p.treeSHA||commit.verification?.verified!==true)throw Error('Candidate integrity mismatch');
  const tip=await jsonFetch(`${root}/git/ref/heads/${p.branch}`,{headers},fetcher);
  if(tip.object?.sha!==p.baseSHA||grant.operationExpiresAt<=clock())throw Error('Stale or expired promotion');
  outcome='uncertain';
  await jsonFetch(`${root}/git/refs/heads/${p.branch}`,{method:'PATCH',headers,body:JSON.stringify({sha:p.commitSHA,force:false})},fetcher);
  const after=await jsonFetch(`${root}/git/ref/heads/${p.branch}`,{headers},fetcher);
  if(after.object?.sha!==p.commitSHA)throw Error('Ref readback mismatch');
  outcome='updated';
 }finally{
  if(grant?.token){try{const r=await fetcher('https://api.github.com/installation/token',{method:'DELETE',redirect:'error',signal:AbortSignal.timeout(10000),headers:{Authorization:`Bearer ${grant.token}`,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2026-03-10'}});revoked=r.ok;}catch{} }
  // Report even failed writes, but the controller must independently read main.
  if(grant){try{await jsonFetch(new URL('/v1/execution/complete',origin),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({operationID,oidcToken:await jwt(),outcome})},fetcher);}catch{throw Error('Controller reconciliation required');}}
  if(grant?.token&&!revoked)throw Error('Temporary credential revocation unconfirmed; reconcile');
 }
 return {operationID,outcome};
}
if(process.argv[1]?.endsWith('/execute.mjs')){
 try{const result=await execute({operationID:process.env.REPOCTL_OPERATION_ID,controller:process.env.REPOCTL_CONTROLLER_ORIGIN,oidcURL:process.env.ACTIONS_ID_TOKEN_REQUEST_URL,oidcBearer:process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN,audiencePrefix:process.env.REPOCTL_OIDC_AUDIENCE_PREFIX});console.log(JSON.stringify(result));}
 catch{console.error('Central execution failed; inspect controller reconciliation status. Credentials and provider payloads suppressed.');process.exitCode=1;}
}
