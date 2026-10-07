// Exercise the checked-in deployment bundles in workerd, without provider access.
import {spawn} from 'node:child_process';
import {mkdtemp,readdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const temporary=await mkdtemp(join(tmpdir(),'repoctl-runtime-check-'));
const environment={HOME:temporary,XDG_CONFIG_HOME:temporary,WRANGLER_SEND_METRICS:'false',CLOUDFLARE_AUTH_USE_KEYRING:'false'};
for(const key of ['PATH','TMPDIR','LANG','LC_ALL','SYSTEMROOT'])if(process.env[key])environment[key]=process.env[key];
async function run(args){
 await new Promise((accept,reject)=>{
  const process=spawn(globalThis.process.execPath,args,{cwd:root,env:environment,stdio:'inherit'});
  let force;
  const timeout=setTimeout(()=>{process.kill('SIGTERM');force=setTimeout(()=>process.kill('SIGKILL'),2000);},120000);
  process.once('error',error=>{clearTimeout(timeout);clearTimeout(force);reject(error);});
  process.once('exit',(code,signal)=>{clearTimeout(timeout);clearTimeout(force);code===0?accept():reject(Error(`Runtime check failed (${signal??code}): ${args[0]}`));});
 });
}
const configs=['authority','checkpoint','enrollment-approval','evidence','observation','policy','receipts','registration','signer','broker'];
const bundles=new Map();
try{
 for(const role of configs){
  const out=join(temporary,role);
  await run(['node_modules/wrangler/bin/wrangler.js','deploy','--dry-run','--config',role==='broker'?'wrangler.jsonc':`wrangler.${role}.jsonc`,'--outdir',out]);
  const files=(await readdir(out)).filter(name=>/\.(?:mjs|js)$/.test(name));
  if(files.length!==1)throw Error(`Expected one deployment bundle for ${role}`);
  bundles.set(role,join(out,files[0]));
 }
 const checks=[['app-vault'],['authority','authority'],['broker'],['checkpoint','checkpoint'],
  ['completion','observation','broker'],['enrollment-approval','enrollment-approval'],
  ['enrollment','signer'],['evidence','evidence'],['policy','policy'],
  ['receipts','receipts','checkpoint'],['registration','registration'],['signer','signer'],['generation']];
 for(const [name,...roles] of checks){
  console.log(`QUALIFY ${name}`);
  await run([`scripts/qualify-${name}-local.mjs`,...roles.map(role=>bundles.get(role))]);
 }
 console.log(JSON.stringify({status:'passed',deploymentBundles:configs.length,workerdQualifications:checks.length,providerVerification:'not-performed'}));
}finally{await rm(temporary,{recursive:true,force:true});}
