import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {mkdtemp, rm, realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, dirname, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..'), require = createRequire(join(root, 'package.json'));
const {build} = require('esbuild'), {Miniflare, convertV4MiniflareOptions} = require('miniflare');
const task = await realpath(await mkdtemp(join(tmpdir(), 'repoctl-submission-runtime-')));
let runtime: InstanceType<typeof Miniflare> | undefined;
try {
 const fixture = `import {submissionJournal} from './src/candidate/submission-journal.ts';
 import {submissionQueue} from './src/candidate/submission-queue.ts';
 import {submissionProgress} from './src/candidate/submission-progress.ts';
 export class Journal {
  constructor(state){this.storage=state.storage;this.journal=submissionJournal(state.storage,9,7);this.queue=submissionQueue({ownerID:9,repositoryID:7,journal:this.journal,runner:{
   start:async reference=>{await this.storage.transaction(async transaction=>{await transaction.put('dispatches',(await transaction.get('dispatches')??0)+1);});if(this.lose)throw Error('lost reply');return {...reference,accepted:true};},
   reconcile:async()=>{await this.storage.transaction(async transaction=>{await transaction.put('reconciles',(await transaction.get('reconciles')??0)+1);});}
  }});}
  async fetch(request){try{const {method,args}=await request.json();
   if(method==='begin')return Response.json({result:await submissionProgress(this.journal,args[0]).begin(args[1],args[2])});
   if(method==='markUncertain'||method==='confirmProgress')return Response.json({result:await submissionProgress(this.journal,args[0])[method==='markUncertain'?'uncertain':'published']()});
   if(method==='counts')return Response.json({result:{dispatches:await this.storage.get('dispatches')??0,reconciles:await this.storage.get('reconciles')??0}});
   if(method==='queueRace')return Response.json({result:await Promise.all(Array.from({length:8},()=>this.queue.create(args[0])))});
   if(method==='loseDispatch'){this.lose=true;try{return Response.json({result:await this.queue.create(args[0])});}finally{this.lose=false;}}
   if(method==='queueCreate'||method==='queueReconcile')return Response.json({result:await this.queue[method==='queueCreate'?'create':'reconcile'](args[0])});
   if(!['create','read','claim','transition','createRace','claimRace','executionRace'].includes(method))throw Error('method');
   const result=method==='createRace'?await Promise.all(Array.from({length:8},()=>this.journal.create(args[0]))):method==='claimRace'?await Promise.all(Array.from({length:8},()=>this.journal.transition(args[0],'queued','preparing'))):method==='executionRace'?await Promise.all(Array.from({length:8},()=>this.journal.claim(args[0]))):await this.journal[method](...args);
   return Response.json({result});}catch{return new Response('denied',{status:403});}}
 }
 export default {fetch(request,env){return env.JOURNAL.get(env.JOURNAL.idFromName('fixture')).fetch(request);}};`;
 const built = await build({stdin: {contents: fixture, resolveDir: root, sourcefile: 'submission-fixture.ts'}, bundle: true, write: false, format: 'esm', platform: 'browser', target: 'es2022'});
 const options = convertV4MiniflareOptions({workers: [{name: 'fixture', modules: true, script: built.outputFiles[0].text, compatibilityDate: '2026-10-04', durableObjects: {JOURNAL: {className: 'Journal', useSQLite: true}}}], resourcePersistencePath: join(task, 'persist')});
 runtime = new Miniflare(options);
 async function call(method: string, ...args: unknown[]) {const response = await runtime!.dispatchFetch('https://fixture/', {method: 'POST', body: JSON.stringify({method, args})}); assert.equal(response.status, 200); return (await response.json()).result;}
 async function denied(method: string, ...args: unknown[]) {const response = await runtime!.dispatchFetch('https://fixture/', {method: 'POST', body: JSON.stringify({method, args})}); assert.equal(response.status, 403);}
 const id = 'a'.repeat(64), intent = {ownerID: 9, repositoryID: 7, generationID: id, baseSHA: 'b'.repeat(40), sourceSHA: 'c'.repeat(40), message: 'feat: fixture'};
 const created = await call('createRace', intent); assert.equal(created.filter((value: {created: boolean}) => value.created).length, 1);
 const claims = await call('claimRace', id); assert.equal(claims.filter(Boolean).length, 1);
 const executions = await call('executionRace', id); assert.equal(executions.filter(Boolean).length, 1);
 assert.equal(await call('transition', id, 'preparing', 'retaining', {treeSHA: 'd'.repeat(40), snapshotDigest: 'e'.repeat(64)}), true);
 assert.equal(await call('transition', id, 'retaining', 'signing', {retentionDigest: 'f'.repeat(64)}), true);
 await runtime.dispose(); runtime = new Miniflare(options);
 assert.equal((await call('read', id)).state, 'signing'); assert.equal(await call('transition', id, 'queued', 'preparing'), false);
 assert.equal((await call('create', intent)).created, false); await denied('create', {...intent, sourceSHA: 'd'.repeat(40)}); await denied('create', {...intent, ownerID: 10});
 assert.equal(await call('transition', id, 'signing', 'publishing', {commitSHA: 'f'.repeat(40)}), true);
 assert.equal(await call('transition', id, 'publishing', 'uncertain'), true);
 await runtime.dispose(); runtime = new Miniflare(options);
 assert.equal((await call('read', id)).state, 'uncertain'); await denied('transition', id, 'uncertain', 'signing');
 assert.equal(await call('transition', id, 'uncertain', 'published-awaiting-validation'), true);
 await runtime.dispose(); runtime = new Miniflare(options);
 assert.equal((await call('read', id)).state, 'published-awaiting-validation'); assert.equal((await call('create', intent)).created, false); await denied('transition', id, 'published-awaiting-validation', 'queued');
 const queued = {...intent, generationID: 'b'.repeat(64)};
 await call('queueRace', queued); assert.equal((await call('counts')).dispatches, 1);
 await runtime.dispose(); runtime = new Miniflare(options);
 await call('queueCreate', queued); assert.equal((await call('counts')).dispatches, 1);
 const lost = {...intent, generationID: 'c'.repeat(64)};
 await denied('loseDispatch', lost); assert.equal((await call('read', lost.generationID)).state, 'uncertain');
 await runtime.dispose(); runtime = new Miniflare(options);
 await call('queueCreate', lost); await call('queueReconcile', {ownerID: 9, repositoryID: 7, generationID: lost.generationID});
 assert.deepEqual(await call('counts'), {dispatches: 2, reconciles: 1});
 const execution = {...intent, generationID: 'd'.repeat(64)}, job = {repositoryID: 7, generationID: execution.generationID, baseSHA: execution.baseSHA, sourceSHA: execution.sourceSHA};
 await call('create', execution); assert.equal(await call('begin', execution.generationID, job, execution.message), false);
 await call('transition', execution.generationID, 'queued', 'preparing'); assert.equal(await call('begin', execution.generationID, job, execution.message), false);
 await call('claim', execution.generationID); assert.equal(await call('begin', execution.generationID, job, execution.message), true);
 assert.equal(await call('begin', execution.generationID, {...job, sourceSHA: 'e'.repeat(40)}, execution.message), false);
 assert.equal(await call('begin', execution.generationID, job, 'changed message'), false);
 await call('markUncertain', execution.generationID); assert.equal((await call('read', execution.generationID)).state, 'uncertain');
 assert.equal(await call('begin', execution.generationID, job, execution.message), false); await denied('confirmProgress', execution.generationID);
 console.log('PASS: actual SQLite workerd one submission reservation/claim/dispatch, lost-ack restart without redispatch, immutable owner/source binding and permanent tombstones; synthetic runner, no signer/provider execution');
} finally {if (runtime) await runtime.dispose(); await rm(task, {recursive: true, force: true});}
