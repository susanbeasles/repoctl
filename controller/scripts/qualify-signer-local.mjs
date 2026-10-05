import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import {readFile} from 'node:fs/promises';
import assert from 'node:assert/strict';
const bundle=process.argv[2];if(!bundle)throw Error('Usage: node scripts/qualify-signer-local.mjs DRY_RUN/entrypoint.js');
const script=await readFile(bundle,'utf8');
const mf=new Miniflare(convertV4MiniflareOptions({workers:[
 {name:'signer',modules:true,script,compatibilityDate:'2026-10-04',bindings:{APP_SIGNER_ENABLED:'false'},durableObjects:{APP_SIGNER_COORDINATOR:{className:'AppSignerCoordinator',useSQLite:true}}},
 {name:'caller',modules:true,script:`export default {fetch(request,env){return env.SIGNER.fetch(request);}};`,compatibilityDate:'2026-10-04',serviceBindings:{SIGNER:{name:'signer',entrypoint:'AppSignerService'}}}
]}));
try{
 const publicWorker=await mf.getWorker('signer');assert.equal((await publicWorker.fetch('https://local/v1/github/app-jwt',{method:'POST',body:'{}'})).status,404);
 const caller=await mf.getWorker('caller'),r=await caller.fetch('https://internal/v1/github/app-jwt',{method:'POST',body:'{}'});assert.equal(r.status,503);assert.equal(r.headers.get('cache-control'),'no-store');
 console.log('PASS: real workerd signer public ingress closed; private signing disabled without custody configuration');
}finally{await mf.dispose();}
