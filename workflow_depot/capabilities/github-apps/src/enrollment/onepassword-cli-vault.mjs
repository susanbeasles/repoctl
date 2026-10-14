import {spawn} from 'node:child_process';
import {installCLI} from '../../../onepassword/install-cli.mjs';
import {importAppPrivateKey} from '../runtime/app-signer.mjs';
const validID=x=>typeof x==='string'&&/^[a-z2-7]{26}$/.test(x);
const operation=x=>{if(!/^[a-f0-9]{64}$/.test(x??''))throw Error('Invalid custody operation');return `dispatch-op:${x}`;};
// Only qualified official CLI; no shell, SDK, Connect, secret argv or files.
export async function officialOPRunner(bootstrap){
 if(typeof bootstrap!=='string'||!bootstrap)throw Error('Approved scoped CLI bootstrap unavailable');
 const cli=await installCLI();
 return {close:cli.cleanup,run:(args,input)=>new Promise((resolve,reject)=>{
  const child=spawn(cli.binary,['--cache=false','--config',cli.config,...args],{env:{PATH:process.env.PATH,LANG:'C.UTF-8',OP_SERVICE_ACCOUNT_TOKEN:bootstrap},stdio:['pipe','pipe','pipe']});
  let output='',size=0;const timeout=setTimeout(()=>child.kill('SIGKILL'),15000);
  child.stdout.on('data',chunk=>{size+=chunk.length;if(size>65536)child.kill('SIGKILL');else output+=chunk.toString('utf8');});
  child.stderr.on('data',()=>{});child.stdin.on('error',()=>{});
  child.on('error',()=>{clearTimeout(timeout);reject(Error('Official CLI custody failed'));});
  child.on('close',code=>{clearTimeout(timeout);if(code!==0||size>65536)reject(Error('Official CLI custody outcome uncertain'));else resolve(output);});
  child.stdin.end(input??'');
 })};
}
export function onepasswordCLIVault({storage,vaultID,runner}){
 if(!validID(vaultID)||!storage?.transaction||!runner?.run)throw Error('Approved CLI custody unavailable');
 const read=id=>storage.get(operation(id));
 return {
  async stage(id,value){
   if(!Number.isSafeInteger(value.appID)||value.appID<=0||!Number.isSafeInteger(value.ownerID)||value.role!=='deployment-dispatch'||typeof value.privateKey!=='string'||value.privateKey.length>12000||typeof value.webhookSecret!=='string'||typeof value.clientSecret!=='string')throw Error('Invalid dispatch credentials');
   await importAppPrivateKey(value.privateKey);
   await storage.transaction(async tx=>{if(await tx.get(operation(id)))throw Error('Custody already reserved');await tx.put(operation(id),{state:'creating',appID:value.appID,ownerID:value.ownerID,role:value.role});});
   try{
    const fields=[['private_key',value.privateKey],['webhook_secret',value.webhookSecret],['client_secret',value.clientSecret]].map(([label,v])=>({id:label,label,type:'CONCEALED',value:v}));
    const item=JSON.parse(await runner.run(['item','create','--vault',vaultID,'--format','json','-'],JSON.stringify({title:`Deployment dispatch ${id}`,category:'SECURE_NOTE',fields})));
    if(!validID(item.id)||item.vault?.id!==vaultID)throw Error('Unexpected custody destination');
    await storage.transaction(async tx=>{const r=await tx.get(operation(id));if(r?.state!=='creating')throw Error('Custody changed');await tx.put(operation(id),{...r,state:'staged',itemID:item.id});});
   }catch{throw Error('CLI custody uncertain; reconcile without conversion or creation retry');}
  },
  async status(id){const r=await read(id);return r&&r.state!=='creating'?{reference:id,appID:r.appID,ownerID:r.ownerID,role:r.role,state:r.state}:undefined;},
  async activate(id,verify){
   const r=await read(id);if(r?.state!=='staged'||!validID(r.itemID))throw Error('CLI custody not staged');
   try{
    const pem=await runner.run(['read',`op://${vaultID}/${r.itemID}/private_key`]);
    const key=await importAppPrivateKey(pem),e=await verify({appID:r.appID,ownerID:r.ownerID,role:r.role,key});
    if(e?.verified!==true||e.appID!==r.appID||e.ownerID!==r.ownerID||e.role!==r.role||!/^[a-f0-9]{64}$/.test(e.digest??''))throw Error('Verification rejected');
    await storage.transaction(async tx=>{if(JSON.stringify(await tx.get(operation(id)))!==JSON.stringify(r))throw Error('Custody changed');await tx.put(operation(id),{...r,state:'active',verificationDigest:e.digest});});
   }catch{throw Error('CLI custody verification failed');}
  },
  async reference(id){const r=await read(id);if(r?.state!=='active')throw Error('Dispatch App not verified');return {appID:r.appID,privateKeyReference:`op://${vaultID}/${r.itemID}/private_key`};}
 };
}
