import {createPrivateKey,sign} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {pathToFileURL} from 'node:url';
import {installCLI} from '../capabilities/onepassword/install-cli.mjs';
import {dispatch} from './dispatch-deployment.mjs';
const execute=promisify(execFile),owner='susanbeasles',ownerID=215839550,repositoryID=1405415291;
export function validateIdentity(env){
 if(env.DISPATCH_APP_COMMISSIONED!=='true'||!env.DISPATCH_APP_APPROVAL_REF?.trim())throw Error('Existing dispatch App identity must be separately commissioned');
 for(const name of ['DISPATCH_APP_ID','DISPATCH_INSTALLATION_ID'])if(!/^[1-9]\d*$/.test(env[name]||''))throw Error('Missing exact existing App/installation identity');
 if(!/^[A-Za-z0-9_-]+$/.test(env.DISPATCH_APP_CLIENT_ID||'')||!/^[-a-z0-9]+$/.test(env.DISPATCH_APP_SLUG||'')||!/^op:\/\/[A-Za-z0-9_-]{26}\/[A-Za-z0-9_-]{26}\/[A-Za-z0-9_%.-]+$/.test(env.DISPATCH_APP_PRIVATE_KEY_REF||''))throw Error('Missing existing App client/slug and exact 1Password item field reference');
 if(env.GITHUB_EVENT_NAME!=='push'||env.GITHUB_REF!=='refs/heads/main'||!/^susanbeasles\/[A-Za-z0-9_.-]+$/.test(env.GITHUB_REPOSITORY||'')||env.GITHUB_REPOSITORY==='susanbeasles/delivery_control'||!/^[a-f0-9]{40}$/.test(env.GITHUB_SHA||'')||!/^\d+$/.test(env.GITHUB_RUN_ID||'')||!/^\d+$/.test(env.GITHUB_REPOSITORY_ID||'')||!/^[a-z0-9-]+$/.test(env.DEPLOY_TARGET||''))throw Error('Exact main source and registered target required');
}
async function readPrivateKey(env){
 if(!env.OP_SERVICE_ACCOUNT_TOKEN)throw Error('Missing existing scoped 1Password bootstrap');
 const cli=await installCLI();
 try{return (await execute(cli.binary,['--config',cli.config,'--cache=false','read',env.DISPATCH_APP_PRIVATE_KEY_REF],{env:{PATH:env.PATH,HOME:env.HOME,LANG:'C.UTF-8',OP_SERVICE_ACCOUNT_TOKEN:env.OP_SERVICE_ACCOUNT_TOKEN},encoding:'utf8',timeout:30000,maxBuffer:32768})).stdout;}finally{await cli.cleanup();}
}
const encode=v=>Buffer.from(JSON.stringify(v)).toString('base64url');
export async function appDispatch(env,{api,readKey=readPrivateKey,clock=()=>Date.now(),dispatchRequest=dispatch}={}){
 validateIdentity(env);let token;
 const request=api??(async(method,path,auth,body)=>{const r=await fetch('https://api.github.com'+path,{method,redirect:'error',signal:AbortSignal.timeout(30000),headers:{...(auth?{Authorization:'Bearer '+auth}:{}),Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2026-03-10',...(body?{'Content-Type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})});if(!r.ok)throw Error('GitHub App operation failed');return r.status===204?{}:r.json();});
 try{
  const publicApp=await request('GET','/apps/'+env.DISPATCH_APP_SLUG,undefined);
  if(String(publicApp.id)!==env.DISPATCH_APP_ID||publicApp.client_id!==env.DISPATCH_APP_CLIENT_ID||publicApp.owner?.id!==ownerID||publicApp.owner?.login!==owner||publicApp.permissions?.actions!=='write')throw Error('Existing App identity or Actions permission differs');
  const key=createPrivateKey(await readKey(env));if(key.asymmetricKeyType!=='rsa')throw Error('Existing GitHub App RSA key required');
  const now=Math.floor(clock()/1000),claims=encode({iat:now-60,exp:now+480,iss:env.DISPATCH_APP_CLIENT_ID}),unsigned=encode({alg:'RS256',typ:'JWT'})+'.'+claims;
  const jwt=unsigned+'.'+sign('RSA-SHA256',Buffer.from(unsigned),key).toString('base64url');
  const actual=await request('GET','/app',jwt);if(actual.id!==publicApp.id||actual.client_id!==publicApp.client_id)throw Error('App key belongs to another identity');
  const installation=await request('GET','/app/installations/'+env.DISPATCH_INSTALLATION_ID,jwt);
  if(String(installation.id)!==env.DISPATCH_INSTALLATION_ID||String(installation.app_id)!==env.DISPATCH_APP_ID||installation.account?.id!==ownerID||installation.account?.login!==owner||installation.permissions?.actions!=='write'||installation.suspended_at)throw Error('Installation or Actions permission differs');
  const issued=await request('POST','/app/installations/'+env.DISPATCH_INSTALLATION_ID+'/access_tokens',jwt,{repository_ids:[repositoryID],permissions:{actions:'write'}});token=issued.token;
  const permissions=issued.permissions||{};
  if(typeof token!=='string'||!token||permissions.actions!=='write'||Object.entries(permissions).some(([k,v])=>k!=='actions'&&!(k==='metadata'&&v==='read'))||!Number.isFinite(Date.parse(issued.expires_at))||Date.parse(issued.expires_at)<=clock()||Date.parse(issued.expires_at)>clock()+3600000)throw Error('Issued token scope/expiry differs');
  const repos=await request('GET','/installation/repositories?per_page=100',token);
  if(repos.total_count!==1||repos.repositories?.length!==1||repos.repositories[0].id!==repositoryID||repos.repositories[0].full_name!=='susanbeasles/delivery_control')throw Error('Issued token has wrong repository scope');
  return await dispatchRequest({...env,RELEASE_DISPATCH_TOKEN:token});
 }catch{throw Error('Existing App dispatch failed closed; identity, permissions and credential output withheld');}
 finally{if(token){try{await request('DELETE','/installation/token',token);}catch{throw Error('Dispatch token revocation uncertain; no automatic retry');}}}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){appDispatch(process.env).then(r=>console.log(JSON.stringify(r))).catch(e=>{console.error(e.message);process.exitCode=1;});}
