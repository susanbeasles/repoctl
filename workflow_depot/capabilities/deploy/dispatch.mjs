import {pathToFileURL} from 'node:url';
export async function dispatch(env,fetcher=fetch) {
  if(env.GITHUB_EVENT_NAME!=='push'||env.GITHUB_REF!=='refs/heads/main'||!/^susanbeasles\/[A-Za-z0-9_.-]+$/.test(env.GITHUB_REPOSITORY??'')||!/^\d+$/.test(env.GITHUB_REPOSITORY_ID??'')||!/^\d+$/.test(env.GITHUB_RUN_ID??'')||!/^[a-f0-9]{40}$/.test(env.GITHUB_SHA??'')||!/^[a-z0-9-]+$/.test(env.DEPLOY_TARGET??'')) throw Error('Exact main source identity and target required');
  if(env.GITHUB_REPOSITORY==='susanbeasles/delivery_control') throw Error('Controller self-publication must not recursively dispatch');
  if(!env.RELEASE_DISPATCH_TOKEN) throw Error('Missing existing RELEASE_DISPATCH_TOKEN capability: Actions write on delivery_control is required; GITHUB_TOKEN and OP_SERVICE_ACCOUNT_TOKEN cannot substitute');
  const response=await fetcher('https://api.github.com/repos/susanbeasles/delivery_control/actions/workflows/deploy.yml/dispatches',{
    method:'POST',redirect:'error',signal:AbortSignal.timeout(30000),headers:{Authorization:`Bearer ${env.RELEASE_DISPATCH_TOKEN}`,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2026-03-10','Content-Type':'application/json'},
    body:JSON.stringify({ref:'main',inputs:{repository:env.GITHUB_REPOSITORY,repository_id:env.GITHUB_REPOSITORY_ID,sha:env.GITHUB_SHA,source_run_id:env.GITHUB_RUN_ID,target:env.DEPLOY_TARGET}})
  });
  if(response.status!==204) throw Error(`Central dispatch failed (${response.status}); inspect receiver before retrying`);
  return {state:'requested',target:env.DEPLOY_TARGET,sha:env.GITHUB_SHA};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href) {
  try {console.log(JSON.stringify(await dispatch(process.env)));} catch(error) {console.error(error.message);process.exitCode=1;}
}
