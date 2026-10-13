import {readFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {resolve} from 'node:path';
import {API} from './releases.mjs';
import {verifyDeploymentRequest} from './deployments.mjs';
import {createGitHubJournal} from './github-journal.mjs';
import {loadGitHubBundle} from './github-bundle.mjs';
import {authorizeAndExecute} from './workflow-deployment.mjs';
import {createCloudflareDeployer} from './cloudflare-deployer.mjs';
import {createCloudflareProvider} from './cloudflare-provider.mjs';
import {canonical,digest,sha256,validatePolicy,validateArtifact} from './shared/contract.mjs';
const need=v=>{if(!v)throw Error('Deployment workflow configuration or evidence denied');};
export function controllerContext(env){
  need(env.GITHUB_REPOSITORY==='susanbeasles/delivery_control'&&env.GITHUB_REPOSITORY_ID==='1405415291'&&env.GITHUB_EVENT_NAME==='workflow_dispatch'&&env.GITHUB_REF==='refs/heads/main'&&/^[a-f0-9]{40}$/.test(env.GITHUB_SHA??''));
  need(/^[1-9]\d*$/.test(env.GITHUB_RUN_ID??'')&&/^[1-9]\d*$/.test(env.GITHUB_RUN_ATTEMPT??''));
  return {repository:env.GITHUB_REPOSITORY,repositoryID:1405415291,sha:env.GITHUB_SHA,runID:Number(env.GITHUB_RUN_ID),runAttempt:Number(env.GITHUB_RUN_ATTEMPT)};
}
export async function workflowIdentity(env,audience,fetcher=fetch){
  need(typeof env.ACTIONS_ID_TOKEN_REQUEST_TOKEN==='string'&&env.ACTIONS_ID_TOKEN_REQUEST_TOKEN.length);
  const url=new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL);need(url.protocol==='https:'&&!url.username&&!url.password&&url.hostname.endsWith('.actions.githubusercontent.com'));
  url.searchParams.set('audience',audience);
  const response=await fetcher(url,{redirect:'error',signal:AbortSignal.timeout(15000),headers:{Authorization:`Bearer ${env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}`}});
  need(response.ok);const text=await response.text();need(text.length<=20000);const value=JSON.parse(text).value;need(typeof value==='string'&&value.length<=16384);return value;
}
export async function runWorkflow({env,config,request,modules,sourceAPI,journalAPI,bundleLoader=loadGitHubBundle,identityLoader=workflowIdentity,providerFactory=createCloudflareProvider,clock=()=>Math.floor(Date.now()/1000)}) {
  const context=controllerContext(env);
  need(config?.schema==='deployment-workflow-config/v1'&&config.enabled===true&&config.accountID==='1a799c6e699d2ef7e87398692ce3ad7b');
  need(/^[a-f0-9]{40}$/.test(config.journalAnchorSHA??'')&&/^[a-f0-9]{64}$/.test(config.verifierSHA256??'')&&Array.isArray(config.actorIDs)&&config.actorIDs.length);
  const assertController=async()=>{const [head,commit]=await Promise.all([journalAPI.request(`/repos/${context.repository}/git/ref/heads/main`),journalAPI.request(`/repos/${context.repository}/git/commits/${context.sha}`)]);need(head?.object?.sha===context.sha&&commit?.sha===context.sha&&commit.verification?.verified===true);};
  await assertController();
  const source=await verifyDeploymentRequest(request,sourceAPI);
  const selected=config.targets?.[source.target];need(selected&&source.service.state!=='retired'&&source.service.workers.length===1);
  need(selected.policy?.enabled===true&&selected.baselineDeploymentID&&selected.policy.targets?.length===1);
  // Bind trust to the controller's verified current main, not caller-provided
  // workflow hashes. The reusable job supplies job_workflow_ref/sha OIDC claims.
  const trust={repository:context.repository,repositoryID:context.repositoryID,ownerID:215839550,actorIDs:config.actorIDs,eventNames:['workflow_dispatch'],ref:'refs/heads/main',workflowRef:`${context.repository}/.github/workflows/deploy.yml@refs/heads/main`,workflowSHA:context.sha,jobWorkflowRef:`${context.repository}/.github/workflows/deployment-job.yml@refs/heads/main`,jobWorkflowSHA:context.sha};
  const policy={...selected.policy,authorizer:{...trust,audiencePrefix:'deployment-authorize'},executor:{...trust,audiencePrefix:'deployment-execute'}};
  validatePolicy(policy);
  const target=policy.targets[0];need(target.accountID===config.accountID&&target.scriptName===source.service.workers[0]&&target.sourceRepository===source.repository&&target.sourceRepositoryID===source.repositoryID);
  const bundle=await bundleLoader({source,api:sourceAPI,token:env.SOURCE_READ_TOKEN});
  need(bundle.schema==='deployment-workflow-bundle/v1'&&typeof bundle.artifactBase64==='string'&&bundle.artifactBase64.length<=8*1024*1024);
  const artifactBytes=Buffer.from(bundle.artifactBase64,'base64');need(artifactBytes.toString('base64')===bundle.artifactBase64);
  const journal=createGitHubJournal({api:journalAPI,repository:context.repository,repositoryID:context.repositoryID,anchorSHA:config.journalAnchorSHA});
  const prior=await journal.get(`baseline:${target.accountID}:${target.scriptName}`);
  const sourceReceipt=bundle.signingReceipt,build=bundle.provenance;
  const operation={schema:'workflow-depot-cloudflare-deploy/v1',operationID:await digest({repositoryID:source.repositoryID,sha:source.sha,target:source.target,runID:context.runID,runAttempt:context.runAttempt}),nonce:await digest({controller:context.repositoryID,runID:context.runID,runAttempt:context.runAttempt,target:source.target}),policyDigest:await digest(policy),artifactDigest:await sha256(artifactBytes),metadataDigest:target.metadataDigest,accountID:target.accountID,scriptName:target.scriptName,zoneID:target.zoneID,hostname:target.hostname,...(target.ingress?{ingress:target.ingress}:{}),expectedDeploymentID:prior?.deploymentID??selected.baselineDeploymentID,source:{repository:source.repository,repositoryID:source.repositoryID,commitSHA:source.sha,signerKeyID:sourceReceipt?.signerKeyID,signingReceiptDigest:await digest(sourceReceipt),ciRunID:build?.runID,ciRunAttempt:build?.runAttempt},execution:{runID:context.runID,runAttempt:context.runAttempt},expiresAt:clock()+300};
  await validateArtifact(artifactBytes,operation,policy);
  const github={read:async(repository,path)=>{need(repository===source.repository&&/^(?:|\/git\/(?:ref\/(?:heads\/main|tags\/promotion\/[1-9]\d*\/(?:source|main))|commits\/[a-f0-9]{40}|tags\/[a-f0-9]{40})|\/actions\/runs\/[1-9]\d*(?:\/attempts\/[1-9]\d*\/jobs\?per_page=100&page=[1-9]\d*)?)$/.test(path));return sourceAPI.request(`/repos/${repository}${path}`);}};
  const signingReceipts=modules.workflowSigningReceipts({bundle,enrollment:config.enrollment,github,verifierSHA256:config.verifierSHA256,now:clock});
  const proof=modules.deploymentEvidence({policy,github,signingReceipts,provenance:{lookup:async({artifactDigest})=>{need(artifactDigest===operation.artifactDigest);return bundle.provenance;}}});
  const evidence={verify:async op=>{await assertController();const result=await proof.verify(op);await assertController();return result;}};
  const authorizerToken=await identityLoader(env,policy.authorizer.audiencePrefix+':'+operation.operationID);
  const executorToken=await identityLoader(env,policy.executor.audiencePrefix+':'+operation.operationID);
  const result=await authorizeAndExecute({source,operation,policy,createAuthority:modules.createDeploymentAuthority,authorityStorage:journal,executionStorage:journal,evidence,identity:{authorizerToken,executorToken,runID:context.runID,runAttempt:context.runAttempt,sourceReadToken:env.SOURCE_READ_TOKEN},artifacts:{get:async key=>{need(key===`artifacts/sha256/${operation.artifactDigest}.json`);return {size:artifactBytes.length,body:new Response(artifactBytes).body};}},loadCredentials:()=>modules.loadEnvironment(env),createProvider:providerFactory,createExecutor:createCloudflareDeployer,now:clock});
  // A failed baseline checkpoint is uncertain, never silently reported success.
  // The existing provider preflight also refuses a stale configured baseline.
  await journal.put(`baseline:${target.accountID}:${target.scriptName}`,{operationID:operation.operationID,versionID:result.versionID,deploymentID:result.deploymentID});
  return result;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  try {
    const env=process.env,base=resolve('.deployment-capabilities');
    const modules=Object.assign({},...await Promise.all(['src/deployment-authority.mjs','src/deployment-evidence.mjs','src/workflow-receipts.mjs','capabilities/onepassword/environment.mjs'].map(p=>import(pathToFileURL(resolve(base,p))))));
    const config=JSON.parse(await readFile('deployment/workflow-config.json','utf8'));
    const result=await runWorkflow({env,config,request:JSON.parse(env.DEPLOY_REQUEST_JSON),modules,sourceAPI:new API(env.SOURCE_READ_TOKEN),journalAPI:new API(env.JOURNAL_TOKEN)});
    console.log(JSON.stringify(result));
  } catch {console.error('Central deployment failed; inspect retained journal before retrying. No automatic retry was performed.');process.exitCode=1;}
}
