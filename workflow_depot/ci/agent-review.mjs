import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
export function validateReview({enabled,image,approval,command,sourceSha}) {
 if(!enabled)return null;
 if(!/^[^\s]+@sha256:[a-f0-9]{64}$/.test(image||'')||typeof approval!=='string'||!approval.trim()||!/^[a-f0-9]{40}$/.test(sourceSha||'')||!Array.isArray(command)||!command.length||command.some(x=>typeof x!=='string'||!x||x.includes('\0')))throw Error('Agent review requires approved disclosure, immutable runtime, exact candidate and reviewed argv');
 return command;
}
export function validateReport(report,sha) {
 if(!report||Object.keys(report).sort().join()!=='findings,schema,sourceSha'||report.schema!=='workflow-depot-agent-review/v1'||report.sourceSha!==sha||!Array.isArray(report.findings))throw Error('Invalid candidate-bound advisory review');
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 const command=validateReview({enabled:process.env.REVIEW_ENABLED==='true',image:process.env.REVIEW_IMAGE,approval:process.env.REVIEW_APPROVAL,command:JSON.parse(process.env.REVIEW_COMMAND_JSON||'[]'),sourceSha:process.env.GITHUB_SHA});
 if(command){
  const env={PATH:process.env.PATH,HOME:process.env.HOME,LANG:'C.UTF-8',CI:'true',SOURCE_SHA:process.env.GITHUB_SHA,ANTHROPIC_API_KEY:process.env.ANTHROPIC_API_KEY||''};
  const result=spawnSync(command[0],command.slice(1),{env,shell:false,stdio:'inherit',timeout:600000});
  if(result.error||result.status!==0)throw Error('Approved reviewer failed');
  const raw=readFileSync('agent-review.json');if(raw.length>1048576)throw Error('Review exceeds size limit');validateReport(JSON.parse(raw),process.env.GITHUB_SHA);
 }
}
