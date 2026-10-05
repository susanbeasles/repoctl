// Secret material stays in the remote signer adapter. It accepts only a known
// App identity and internally constructed JWT, never an arbitrary JWT payload.
export function installationCredentials({appID,installationID,repositoryIDs,signAppJWT,fetcher=fetch,clock=()=>Math.floor(Date.now()/1000)}){
 if(!Number.isSafeInteger(appID)||!Number.isSafeInteger(installationID)||!Array.isArray(repositoryIDs)||!repositoryIDs.length||!repositoryIDs.every(Number.isSafeInteger))throw Error('Invalid trusted App enrollment');
 const headers=token=>({Accept:'application/vnd.github+json',Authorization:`Bearer ${token}`,'X-GitHub-Api-Version':'2026-03-10','User-Agent':'repoctl-broker','Content-Type':'application/json'});
 return {
  async issueInstallationToken(request){
   if(request.installationID!==installationID||request.repositoryIDs?.length!==1||!repositoryIDs.includes(request.repositoryIDs[0])||JSON.stringify(request.permissions)!==JSON.stringify({contents:'write'}))throw Error('Requested authority is outside enrolled writer scope');
   const now=clock();
   const jwt=await signAppJWT({appID,issuedAt:now-60,expiresAt:now+300});
   const url=`https://api.github.com/app/installations/${installationID}/access_tokens`;
   const response=await fetcher(url,{method:'POST',redirect:'error',signal:AbortSignal.timeout(10000),headers:headers(jwt),body:JSON.stringify({repository_ids:request.repositoryIDs,permissions:{contents:'write'}})});
   if(!response.ok)throw Error(`Installation-token issuance failed (HTTP ${response.status})`);
   const result=await response.json();
   return {token:result.token,expiresAt:Math.floor(Date.parse(result.expires_at)/1000),repositoryIDs:result.repositories?.map(r=>r.id),permissions:result.permissions};
  },
  async revoke(token){
   const response=await fetcher('https://api.github.com/installation/token',{method:'DELETE',redirect:'error',signal:AbortSignal.timeout(10000),headers:headers(token)});
   // A previously revoked/expired token cannot authenticate this fixed endpoint.
   if(!response.ok&&response.status!==401)throw Error(`Installation-token revocation failed (HTTP ${response.status})`);
  }
 };
}
