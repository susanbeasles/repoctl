import assert from 'node:assert/strict';import {createRequire} from 'node:module';import {mkdtemp,rm,realpath} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join,dirname,resolve} from 'node:path';import {fileURLToPath} from 'node:url';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..'),require=createRequire(join(root,'package.json'));
const {build}=require('esbuild'),{Miniflare,convertV4MiniflareOptions}=require('miniflare');
const task=await realpath(await mkdtemp(join(tmpdir(),'repoctl-generation-runtime-')));let mf;
try{
 const fixture=`import {generationJournal} from './src/candidate/journal.mjs';
 export class Journal {
  constructor(s){this.storage=s.storage;this.journal=generationJournal(s.storage,7);}
  async fetch(r){try{const {method,args}=await r.json();if(!['reserve','read','transition','race'].includes(method))throw Error('method');
   const result=method==='race'?await Promise.all(Array.from({length:8},()=>this.journal.reserve(args[0]))):await this.journal[method](...args);return Response.json({result});
  }catch{return new Response('denied',{status:403});}}
 }
 export default {fetch(r,e){return e.JOURNAL.get(e.JOURNAL.idFromName('fixture')).fetch(r);}};`;
 const built=await build({stdin:{contents:fixture,resolveDir:root,sourcefile:'generation-fixture.mjs'},bundle:true,write:false,format:'esm',platform:'browser',target:'es2022'});
 const options=convertV4MiniflareOptions({workers:[{name:'fixture',modules:true,script:built.outputFiles[0].text,compatibilityDate:'2026-10-04',durableObjects:{JOURNAL:{className:'Journal',useSQLite:true}}}],resourcePersistencePath:join(task,'persist')});
 mf=new Miniflare(options);
 const call=async(method,...args)=>{const r=await mf.dispatchFetch('https://fixture/',{method:'POST',body:JSON.stringify({method,args})});assert.equal(r.status,200);return (await r.json()).result;};
 const denied=async(method,...args)=>{const r=await mf.dispatchFetch('https://fixture/',{method:'POST',body:JSON.stringify({method,args})});assert.equal(r.status,403);};
 const id='e'.repeat(64),b={repositoryID:7,ref:'refs/heads/int/'+id,generationID:id,baseSHA:'a'.repeat(40),commitSHA:'b'.repeat(40),treeSHA:'c'.repeat(40)};
 const raced=await call('race',b);assert.equal(raced.filter(v=>v===true).length,1);assert.equal(raced.filter(v=>v===false).length,7);
 assert.equal(await call('transition',id,'reserved','creating'),true);assert.equal(await call('transition',id,'reserved','creating'),false);
 await mf.dispose();mf=new Miniflare(options);
 assert.equal((await call('read',id)).phase,'creating');assert.equal(await call('reserve',b),false);
 assert.equal(await call('transition',id,'creating','uncertain'),true);
 await mf.dispose();mf=new Miniflare(options);
 assert.equal((await call('read',id)).phase,'uncertain');await denied('reserve',{...b,commitSHA:'d'.repeat(40)});await denied('reserve',{...b,repositoryID:8});await denied('reserve',{...b,ref:'refs/heads/main'});
 assert.equal(await call('transition',id,'uncertain','confirmed'),true);await denied('transition',id,'confirmed','reserved');await denied('transition',id,'confirmed','creating');
 await mf.dispose();mf=new Miniflare(options);
 assert.equal((await call('read',id)).phase,'confirmed');assert.equal(await call('reserve',b),false);assert.deepEqual(await call('read',id),{...b,phase:'confirmed'});
 console.log('PASS: actual SQLite workerd atomic generation reservation, CAS, restart uncertainty/confirmation and permanent collision tombstones. No live provider operation.');
}finally{if(mf)await mf.dispose();await rm(task,{recursive:true,force:true});}
