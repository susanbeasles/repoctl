import {WorkerEntrypoint} from 'cloudflare:workers';
import {appVault} from '../enrollment/app-vault.mjs';
const headers={'Cache-Control':'no-store','Content-Type':'application/json'};
export class AppSignerCoordinator {
 constructor(ctx,env){this.ctx=ctx;this.env=env;}
 async fetch(request){
  if(this.env.APP_SIGNER_ENABLED!=='true'||typeof this.env.APP_KEYRING_JSON!=='string'||! /^[a-f0-9]{64}$/.test(this.env.APP_CREDENTIAL_REFERENCE??''))return Response.json({error:'signer_not_configured'},{status:503,headers});
  if(request.method!=='POST'||new URL(request.url).pathname!=='/v1/github/app-jwt')return Response.json({error:'not_found'},{status:404,headers});
  try{
   if(!request.body)throw Error('Missing request');
   const reader=request.body.getReader(),chunks=[];let size=0;
   while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>2048){await reader.cancel();throw Error('Oversized request');}chunks.push(value);}
   const raw=new Uint8Array(size);let offset=0;for(const chunk of chunks){raw.set(chunk,offset);offset+=chunk.length;}
   const claims=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
   const vault=await appVault(this.ctx.storage,JSON.parse(this.env.APP_KEYRING_JSON));
   const jwt=await vault.sign(this.env.APP_CREDENTIAL_REFERENCE,claims);
   return Response.json({jwt},{headers});
  }catch{return Response.json({error:'signing_denied'},{status:403,headers});}
 }
}
export class AppSignerService extends WorkerEntrypoint {
 fetch(request){
  if(!this.env.APP_SIGNER_COORDINATOR)return Response.json({error:'signer_not_configured'},{status:503,headers});
  return this.env.APP_SIGNER_COORDINATOR.get(this.env.APP_SIGNER_COORDINATOR.idFromName('remote-app-custody-v1')).fetch(request);
 }
}
// Only a broker's explicitly configured private service binding can request JWTs.
export default {fetch(){return new Response('Not found',{status:404,headers:{'Cache-Control':'no-store'}});}};
