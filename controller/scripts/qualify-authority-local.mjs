// Real workerd proves public/private ingress separation after Wrangler dry-run.
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import {readFile} from 'node:fs/promises';
import assert from 'node:assert/strict';
const bundle=process.argv[2];if(!bundle)throw Error('Usage: node scripts/qualify-authority-local.mjs DRY_RUN/entrypoint.js');
const script=await readFile(bundle,'utf8');
const mf=new Miniflare(convertV4MiniflareOptions({workers:[
 {name:'authority',modules:true,script,compatibilityDate:'2026-10-04',bindings:{AUTHORIZATION_ENABLED:'false'},durableObjects:{AUTHORIZATION_COORDINATOR:{className:'AuthorizationCoordinator',useSQLite:true}}},
 {name:'caller',modules:true,script:`export default {fetch(request,env){return env.AUTHORITY.fetch(request);}};`,compatibilityDate:'2026-10-04',serviceBindings:{AUTHORITY:{name:'authority',entrypoint:'AuthorizationService'}}}
]}));
try{
 const publicWorker=await mf.getWorker('authority');const publicResponse=await publicWorker.fetch('https://local/v1/authorization/admit');assert.equal(publicResponse.status,404);
 const caller=await mf.getWorker('caller');const privateResponse=await caller.fetch('https://internal/v1/authorization/load',{method:'POST',body:JSON.stringify({operationID:'a'.repeat(64)})});assert.equal(privateResponse.status,503);assert.equal(privateResponse.headers.get('cache-control'),'no-store');
 console.log('PASS: public authority ingress is closed; private entrypoint requires configured verifiers');
}finally{await mf.dispose();}
