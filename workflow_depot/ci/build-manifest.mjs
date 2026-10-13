import {lstatSync,readdirSync,readFileSync,writeFileSync,realpathSync} from 'node:fs';
import {resolve,relative,join} from 'node:path';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {candidate} from './project-profile.mjs';
export function inventory(root) {
 if(lstatSync(root).isSymbolicLink()||!lstatSync(root).isDirectory())throw Error('Build root must be a real directory');
 const base=realpathSync(root),files=[];
 function walk(path){for(const name of readdirSync(path).sort()){
  const full=join(path,name),stat=lstatSync(full);
  if(stat.isSymbolicLink()||(!stat.isDirectory()&&!stat.isFile()))throw Error('Build output cannot contain links or special files');
  if(stat.isDirectory())walk(full);else files.push({path:relative(base,full).split('\\').join('/'),bytes:stat.size,sha256:createHash('sha256').update(readFileSync(full)).digest('hex')});
 }}walk(base);if(!files.length)throw Error('Build output is empty');return files;
}
export function manifest(root,env){candidate(env);if(!/^\d+$/.test(env.GITHUB_RUN_ID||'')||!/^\d+$/.test(env.GITHUB_RUN_ATTEMPT||''))throw Error('Missing run identity');return {schema:1,repository:env.GITHUB_REPOSITORY,sourceSha:env.GITHUB_SHA,sourceRef:env.GITHUB_REF,runId:env.GITHUB_RUN_ID,runAttempt:env.GITHUB_RUN_ATTEMPT,files:inventory(root)};}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)writeFileSync(process.argv[3],JSON.stringify(manifest(process.argv[2],process.env),null,2)+'\n');
