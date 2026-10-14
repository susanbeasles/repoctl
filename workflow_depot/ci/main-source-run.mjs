import {pathToFileURL} from 'node:url';
import {appendFileSync} from 'node:fs';
export async function acceptedRun(env,read) {
 if(env.GITHUB_EVENT_NAME!=='push'||env.GITHUB_REF!=='refs/heads/main'||!/^[a-f0-9]{40}$/.test(env.GITHUB_SHA||'')||!/^[1-9]\d*$/.test(env.INTEGRATION_RUN_ID||'')||!/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(env.GITHUB_REPOSITORY||'')||!/^[1-9]\d*$/.test(env.GITHUB_REPOSITORY_ID||''))throw Error('Exact accepted main push and integration run required');
 const root=`/repos/${env.GITHUB_REPOSITORY}`;
 const [main,run]=await Promise.all([read(root+'/git/ref/heads/main'),read(root+'/actions/runs/'+env.INTEGRATION_RUN_ID)]);
 if(main.object?.sha!==env.GITHUB_SHA||run.head_sha!==env.GITHUB_SHA||run.event!=='push'||!run.head_branch?.startsWith('int/')||run.status!=='completed'||run.conclusion!=='success'||String(run.repository?.id)!==env.GITHUB_REPOSITORY_ID||run.repository.full_name!==env.GITHUB_REPOSITORY)throw Error('Accepted integration identity or current main mismatch');
 return run;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 const read=async path=>{const r=await fetch('https://api.github.com'+path,{redirect:'error',signal:AbortSignal.timeout(20000),headers:{Authorization:'Bearer '+process.env.GITHUB_TOKEN,Accept:'application/vnd.github+json'}});if(!r.ok)throw Error('Source identity read failed');return r.json();};
 const run=await acceptedRun(process.env,read);
 if(process.env.GITHUB_OUTPUT)appendFileSync(process.env.GITHUB_OUTPUT,`integration_ref=refs/heads/${run.head_branch}\nrun_attempt=${run.run_attempt}\n`);
}
