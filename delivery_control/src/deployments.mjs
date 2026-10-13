import {readFile,appendFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {API,OWNER,OWNER_ID,validateRequest} from './releases.mjs';
export const services = JSON.parse(await readFile(new URL('../deployment/services.json',import.meta.url),'utf8')).services;
export function validateDeploymentRequest(input) {
  const q=validateRequest({repository:input.repository,repositoryID:input.repository_id,sha:input.sha,runID:input.source_run_id});
  const service=services.find(s=>s.target===input.target);
  if(!service || service.state==='retired' || service.repository!==q.repository || service.repository_id!==String(q.repositoryID)) throw Error('Unregistered source identity or target');
  return {...q,target:service.target,service};
}
export async function verifyDeploymentRequest(input,api,{sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms)),attempts=1,self=false}={}) {
  const q=validateDeploymentRequest(input),root=`/repos/${q.repository}`;
  const repo=await api.request(root);
  if(repo?.id!==q.repositoryID || repo.owner?.id!==OWNER_ID || repo.owner?.login!==OWNER || repo.fork || repo.archived || repo.default_branch!=='main') throw Error('Repository identity or main policy mismatch');
  let run;
  for(let i=0;i<attempts;i++) {
    run=await api.request(`${root}/actions/runs/${q.runID}`);
    if(run?.status==='completed'||self) break;
    if(i+1<attempts) await sleep(5000);
  }
  if(run?.event!=='push'||run.head_branch!=='main'||run.head_sha!==q.sha||run.repository?.id!==q.repositoryID||(!self&&(run.status!=='completed'||run.conclusion!=='success'))) throw Error('Source run must be a successful exact main push');
  if(self&&(q.repository!=='susanbeasles/delivery_control'||q.target!=='delivery-control-source')) throw Error('Invalid controller source receipt');
  const workflow=await api.request(`${root}/actions/workflows/${run.workflow_id}`);
  if(workflow?.path!=='.github/workflows/deploy.yml') throw Error('Unexpected source workflow');
  const commit=await api.request(`${root}/commits/${q.sha}`);
  if(commit?.sha!==q.sha||commit.commit?.verification?.verified!==true) throw Error('Verified signed source commit required');
  const head=await api.request(`${root}/git/ref/heads/main`);
  if(head?.object?.sha!==q.sha) throw Error('Source main advanced; stale deployment refused');
  return {...q,checkout_repository:q.repository,checkout_sha:q.sha};
}
export function requireCommissioned(service) {
  if(service.state!=='source-only') throw Error(`Deployment blocked for ${service.target}: ${service.blocker ?? 'retained authorization not commissioned'}`);
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href) {
  try {
    const env=process.env;
    if(env.GITHUB_REPOSITORY!=='susanbeasles/delivery_control'||env.GITHUB_REPOSITORY_ID!=='1405415291'||env.GITHUB_REF!=='refs/heads/main') throw Error('Controller main required');
    const self=env.GITHUB_EVENT_NAME==='push';
    const input=self?{repository:env.GITHUB_REPOSITORY,repository_id:env.GITHUB_REPOSITORY_ID,sha:env.GITHUB_SHA,source_run_id:env.GITHUB_RUN_ID,target:'delivery-control-source'}:JSON.parse(env.DEPLOY_REQUEST_JSON??'{}');
    if(!self&&env.GITHUB_EVENT_NAME!=='workflow_dispatch') throw Error('Explicit deployment dispatch required');
    if(process.argv[2]==='preflight') {
      const q=validateDeploymentRequest(input);
      if(env.GITHUB_OUTPUT) await appendFile(env.GITHUB_OUTPUT,`repository_name=${q.repository.split('/')[1]}\ntarget=${q.target}\n`);
      process.exit(0);
    }
    const q=await verifyDeploymentRequest(input,new API(env.GITHUB_TOKEN),{attempts:24,self});
    const receipt={repository:q.repository,sha:q.sha,target:q.target,state:q.service.state,blocker:q.service.blocker??null};
    console.log(JSON.stringify(receipt));
    if(env.GITHUB_STEP_SUMMARY) await appendFile(env.GITHUB_STEP_SUMMARY,`Deployment admission: ${JSON.stringify(receipt)}\n`);
    if(env.GITHUB_OUTPUT) await appendFile(env.GITHUB_OUTPUT,`state=${q.service.state}\ntarget=${q.target}\n`);
    if(process.argv[2]!=='admit') requireCommissioned(q.service);
  } catch(error) {console.error(error.message);process.exitCode=1;}
}
