import {integrationRef,isIntegrationRef} from './integration-ref.mjs';
import {digest} from './shared/contract.mjs';
const hash=/^[a-f0-9]{64}$/,sha=/^[a-f0-9]{40}$/;
const deny=()=>{throw Error('Deployment evidence denied');};
const require=value=>{if(!value)deny();};

// These readers are infrastructure-bound. A request cannot choose an evidence
// server, signing receipt store, provider origin or alternative policy.
export function deploymentEvidence({policy,github,signingReceipts,provenance}){
 if(typeof github?.read!=='function'||typeof signingReceipts?.lookupReceipt!=='function'||typeof provenance?.lookup!=='function'||!policy?.verification)deny();
 return {async verify(op){
  try{
   const s=op.source,v=policy.verification;
   require(v.signerKeyIDs.includes(s.signerKeyID));
   const read=path=>github.read(s.repository,path);
   const repo=await read('');
   require(repo.id===s.repositoryID&&repo.full_name===s.repository&&!repo.archived&&!repo.fork&&repo.default_branch==='main');
   const [tip,commit,run,receipt,build]=await Promise.all([
    read('/git/ref/heads/main'),read('/git/commits/'+s.commitSHA),read('/actions/runs/'+s.ciRunID),
    signingReceipts.lookupReceipt({receiptDigest:s.signingReceiptDigest}),provenance.lookup({artifactDigest:op.artifactDigest}),
   ]);
   require(tip.object?.sha===s.commitSHA&&commit.sha===s.commitSHA&&commit.verification?.verified===true&&commit.verification.reason==='valid');
   require(receipt?.schema==='repoctl-source-receipt/v1'&&await digest(receipt)===s.signingReceiptDigest&&receipt.repository===s.repository&&receipt.repositoryID===s.repositoryID&&receipt.finalSignedCommitSHA===s.commitSHA&&receipt.signerKeyID===s.signerKeyID&&receipt.hardwareApprovalVerified===true&&hash.test(receipt.ownerApprovalReference)&&Number.isSafeInteger(receipt.sequence)&&receipt.sequence>0);
   require(commit.parents?.length===1&&commit.parents[0].sha===receipt.baseSHA&&commit.tree?.sha===receipt.treeSHA);
   const pair=receipt.pairedTags;
   require(pair?.source?.name===`promotion/${receipt.sequence}/source`&&pair?.main?.name===`promotion/${receipt.sequence}/main`&&pair.source.targetSHA===receipt.sourceSHA&&pair.main.targetSHA===s.commitSHA&&sha.test(pair.source.objectSHA)&&sha.test(pair.main.objectSHA));
   // lookupReceipt must independently verify the retained owner approval and
   // both Git signatures/cross-links. GitHub's generic verified flag cannot
   // establish which enrolled signer or owner authorized this promotion.
   require(receipt.shadowRef===integrationRef(receipt.sourceRef));
   require(run.id===s.ciRunID&&run.run_attempt===s.ciRunAttempt&&run.head_sha===s.commitSHA&&run.head_branch===receipt.shadowRef.slice('refs/heads/'.length)&&run.event==='push'&&run.status==='completed'&&run.conclusion==='success'&&run.repository?.id===s.repositoryID&&run.repository.full_name===s.repository);
   require(run.referenced_workflows?.some(w=>w.path===v.ciWorkflowRef&&w.sha===v.ciWorkflowSHA));
   const jobs=[];let total;
   for(let page=1;page<=10;page++){
    const result=await read(`/actions/runs/${s.ciRunID}/attempts/${s.ciRunAttempt}/jobs?per_page=100&page=${page}`);
    require(Array.isArray(result.jobs)&&result.jobs.length<=100&&Number.isSafeInteger(result.total_count)&&result.total_count>=0&&result.total_count<=1000);
    if(total===undefined)total=result.total_count;
    require(total===result.total_count);
    jobs.push(...result.jobs);require(jobs.length<=total);
    if(jobs.length===total)break;
    require(result.jobs.length===100);if(page===10)deny();
   }
   require(Array.isArray(v.requiredJobs)&&v.requiredJobs.length>0);
   for(const name of v.requiredJobs){const matches=jobs.filter(j=>j.name===name);require(matches.length===1&&matches[0].status==='completed'&&matches[0].conclusion==='success'&&matches[0].head_sha===s.commitSHA);}
   const expected={schema:'workflow-depot-build-provenance/v1',repository:s.repository,repositoryID:s.repositoryID,sourceSHA:s.commitSHA,sourceRef:receipt.shadowRef,artifactDigest:op.artifactDigest,metadataDigest:op.metadataDigest,runID:s.ciRunID,runAttempt:s.ciRunAttempt,workflowRef:v.ciWorkflowRef,workflowSHA:v.ciWorkflowSHA};
   require(await digest(build)===await digest(expected));
   // Evidence reads can outlive a main update. Recheck after every dependency
   // has resolved; callers must still revalidate immediately before mutation.
   require((await read('/git/ref/heads/main')).object?.sha===s.commitSHA);
   return {verified:true,operationID:op.operationID,artifactDigest:op.artifactDigest,sourceSHA:s.commitSHA};
  }catch{deny();}
 }};
}

export function githubEvidenceReader({fetcher=fetch,token}={}){
 async function request(repository,path,raw=false){
  if(!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository))deny();
  const response=await fetcher(`https://api.github.com/repos/${repository}${path}`,{redirect:'error',signal:AbortSignal.timeout(10000),headers:{Accept:raw?'application/vnd.github.raw+json':'application/vnd.github+json','X-GitHub-Api-Version':'2026-03-10','User-Agent':'workflow-depot-evidence',...(token?{Authorization:`Bearer ${token}`}:{})}});
  if(!response.ok){await response.body?.cancel();deny();}
  const reader=response.body?.getReader();if(!reader)deny();const chunks=[];let size=0;
  try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>(raw?32768:512*1024)){await reader.cancel();deny();}chunks.push(value);}}finally{reader.releaseLock();}
  const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
  const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);return raw?text:JSON.parse(text);
 }
 return {async read(repository,path){
  if(!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)||!(path===''||/^\/(?:git\/ref\/heads\/(?:main|int\/[A-Za-z0-9_./-]+)|git\/commits\/[a-f0-9]{40}|actions\/runs\/[1-9][0-9]*(?:\/attempts\/[1-9][0-9]*\/jobs\?per_page=100&page=[1-9][0-9]*)?)$/.test(path)))deny();
  return request(repository,path);
 },async readWorkflow(repository,commitSHA){
  if(!sha.test(commitSHA))deny();
  return request(repository,'/contents/.github/workflows/build.yml?ref='+commitSHA,true);
 }};
}
