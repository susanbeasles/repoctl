import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import * as core from '../src/cloudflare-deployer.mjs';
import * as providerModule from '../src/cloudflare-provider.mjs';
const canonical = value => value && typeof value === 'object'
  ? Array.isArray(value) ? '[' + value.map(canonical).join(',') + ']' : '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}'
  : JSON.stringify(value);
const hash = value => createHash('sha256').update(value).digest('hex');
const oidc = 'synthetic-oidc-do-not-persist';
const token = 'synthetic-provider-token-do-not-log';
const versionID = '11111111-1111-4111-8111-111111111111';
const deploymentID = '22222222-2222-4222-8222-222222222222';
const baselineID = '33333333-3333-4333-8333-333333333333';
const baselineVersionID = '44444444-4444-4444-8444-444444444444';

async function fixture() {
  const metadata = { main_module: 'worker.mjs', compatibility_date: '2026-10-12', compatibility_flags: [], bindings: [] };
  const artifact = { schema: 'workflow-depot-worker-artifact/v1', metadata, modules: [{ name: 'worker.mjs', type: 'esm', content: 'export default {fetch(){return new Response("fixture")}};' }] };
  const bytes = new TextEncoder().encode(JSON.stringify(artifact));
  const trust = {
    repository: 'susanbeasles/delivery_control', repositoryID: 2, ownerID: 215839550,
    actorIDs: [215839550], eventNames: ['workflow_dispatch'], ref: 'refs/heads/main', workflowRef: 'susanbeasles/delivery_control/.github/workflows/cloudflare-deploy.yml@refs/heads/main',
    workflowSHA: 'a'.repeat(40), jobWorkflowRef: 'susanbeasles/delivery_control/.github/workflows/cloudflare-deploy.yml@refs/heads/main',
    jobWorkflowSHA: 'a'.repeat(40), audiencePrefix: 'delivery-control-cloudflare',
  };
  const target = { accountID: 'a'.repeat(32), scriptName: 'fixture-worker', zoneID: 'b'.repeat(32), hostname: 'app.example.com', metadataDigest: hash(canonical(metadata)), sourceRepository: 'susanbeasles/fixture', sourceRepositoryID: 3 };
  const policy = { schema: 'workflow-depot-cloudflare-policy/v1', revision: 1, enabled: true, authorizer: trust, executor: trust, targets: [target], maxArtifactBytes: 5242880,
    verification: { signerKeyIDs: ['c'.repeat(64)], ciWorkflowRef: 'susanbeasles/fixture/.github/workflows/ci.yml@refs/heads/main', ciWorkflowSHA: 'd'.repeat(40), requiredJobs: ['test'] } };
  const operation = { schema: 'workflow-depot-cloudflare-deploy/v1', operationID: 'e'.repeat(64), nonce: 'f'.repeat(64), policyDigest: hash(canonical(policy)), artifactDigest: hash(bytes), metadataDigest: target.metadataDigest,
    accountID: target.accountID, scriptName: target.scriptName, zoneID: target.zoneID, hostname: target.hostname, expectedDeploymentID: baselineID,
    source: { repository: target.sourceRepository, repositoryID: 3, commitSHA: '1'.repeat(40), signerKeyID: 'c'.repeat(64), signingReceiptDigest: '2'.repeat(64), ciRunID: 11, ciRunAttempt: 1 },
    execution: { runID: 12, runAttempt: 1 }, expiresAt: 1200 };
  const events = [], records = new Map();
  let now = 1000;
  let transactionTail = Promise.resolve();
  const storage = {
    async get(key) { return structuredClone(records.get(key)); },
    async put(key, value) { records.set(key, structuredClone(value)); events.push('journal:' + value.state); },
    transaction(callback) {
      const pending = transactionTail.then(() => callback(storage));
      transactionTail = pending.catch(() => {});
      return pending;
    },
  };
  const grant = () => ({ operation: structuredClone(operation), leaseID: '3'.repeat(64), identityExpiresAt: 1150 });
  const authority = {
    async consume(input) { assert.deepEqual(input, { operationID: operation.operationID, oidcToken: oidc }); events.push('consume'); return grant(); },
    async check(input) { assert.deepEqual(Object.keys(input).sort(), ['leaseID', 'operationID', 'stage']); events.push('check:' + input.stage); return grant(); },
    async complete(input) { assert.deepEqual(Object.keys(input).sort(), ['leaseID', 'operationID', 'outcome', 'receipt']); assert.deepEqual(Object.keys(input.receipt).sort(), ['deploymentID', 'versionID']); events.push('complete:' + input.outcome); return { operationID: input.operationID, state: input.outcome }; },
  };
  const artifacts = { async get(key) { assert.equal(key, `artifacts/sha256/${operation.artifactDigest}.json`); events.push('artifact'); return { size: bytes.byteLength, body: new Response(bytes).body }; } };
  const provider = {
    async preflight() { events.push('preflight'); },
    async baseline() { events.push('baseline'); },
    async upload(op, parsed) { assert.deepEqual(op, operation); assert.deepEqual(parsed, artifact); events.push('upload'); return { versionID }; },
    async activate(op, id) { assert.equal(id, versionID); events.push('activate'); return { deploymentID }; },
    async verify(op, receipt) { assert.deepEqual(receipt, { versionID, deploymentID }); events.push('verify'); return receipt; },
  };
  return { metadata, artifact, bytes, policy, operation, records, storage, authority, artifacts, provider, events, clock: () => now, setTime(value) { now = value; },
    create() { return core.createCloudflareDeployer({ storage, authority, artifacts, provider, policy, clock: () => now }); }, request: { operationID: operation.operationID, oidcToken: oidc } };
}

test('trusted deployer and fixed provider adapter are implemented', () => {
  assert.equal(typeof core.createCloudflareDeployer, 'function');
  assert.equal(typeof core.handleDeploymentRequest, 'function');
  assert.equal(typeof providerModule.createCloudflareProvider, 'function');
});

test('deploys digest-verified bytes with durable intent and fresh authority before each mutation', async () => {
  const f = await fixture();
  const receipt = await f.create().execute(f.request);
  assert.deepEqual(receipt, { operationID: f.operation.operationID, state: 'completed', artifactDigest: f.operation.artifactDigest, versionID, deploymentID });
  for (const stage of ['upload', 'activate']) {
    assert.ok(f.events.indexOf(`journal:${stage}-intent`) < f.events.indexOf(`check:${stage}`));
    assert.equal(f.events.indexOf(stage), f.events.indexOf(`check:${stage}`) + 1);
  }
  assert.ok(f.events.indexOf('verify') < f.events.indexOf('complete:completed'));
  assert.equal([...f.records.values()].at(-1).state, 'completed');
  assert.ok(!JSON.stringify([...f.records]).includes(oidc));
});

test('changed artifact fails before any provider mutation', async () => {
  const f = await fixture();
  f.artifacts.get = async () => ({ size: 2, body: new Response('{}').body });
  await assert.rejects(f.create().execute(f.request), /Deployment failed/);
  assert.ok(!f.events.includes('upload'));
  assert.ok(!f.events.includes('activate'));
});

test('authority denial cannot poison local operation state or fetch artifacts', async () => {
  const f = await fixture();
  f.authority.consume = async () => { throw Error(token); };
  await assert.rejects(f.create().execute(f.request), /^Error: Deployment failed/);
  assert.equal(f.records.size, 0);
  assert.ok(!f.events.includes('artifact'));
});

for (const stage of ['upload', 'activate']) test(`revocation at ${stage} prevents that mutation`, async () => {
  const f = await fixture(), check = f.authority.check;
  f.authority.check = async input => { if (input.stage === stage) throw Error(token); return check(input); };
  await assert.rejects(f.create().execute(f.request), /Deployment failed/);
  assert.ok(!f.events.includes(stage));
  assert.ok(!f.events.includes('complete:completed'));
});

test('changed retained operation at fresh check is rejected', async () => {
  const f = await fixture(), check = f.authority.check;
  f.authority.check = async input => { const grant = await check(input); grant.operation.hostname = 'other.example.com'; return grant; };
  await assert.rejects(f.create().execute(f.request), /Deployment failed/);
  assert.ok(!f.events.includes('upload'));
});

test('expired executor identity prevents activation after upload', async () => {
  const f = await fixture(), upload = f.provider.upload;
  f.provider.upload = async (...args) => { const result = await upload(...args); f.setTime(1150); return result; };
  await assert.rejects(f.create().execute(f.request), /Deployment failed/);
  assert.ok(!f.events.includes('activate'));
});

for (const stage of ['upload', 'activate', 'verify']) test(`lost ${stage} response blocks automatic re-execution after restart`, async () => {
  const f = await fixture();
  f.provider[stage] = async () => { f.events.push(stage); throw Error(token); };
  await assert.rejects(f.create().execute(f.request), /Deployment failed/);
  await assert.rejects(f.create().execute(f.request), /Deployment failed/);
  assert.equal(f.events.filter(x => x === stage).length, 1);
  assert.equal([...f.records.values()].at(-1).state, 'uncertain');
  assert.ok(!JSON.stringify([...f.records]).includes(token));
});

test('journal failure before upload prevents provider mutation', async () => {
  const f = await fixture(), put = f.storage.put;
  f.storage.put = async (key, value) => { if (value.state === 'upload-intent') throw Error(token); return put(key, value); };
  await assert.rejects(f.create().execute(f.request), /Deployment failed/);
  assert.ok(!f.events.includes('upload'));
});

test('unconfirmed authority completion cannot return success', async () => {
  const f = await fixture();
  f.authority.complete = async () => { throw Error(token); };
  await assert.rejects(f.create().execute(f.request), /Deployment failed/);
  assert.equal([...f.records.values()].at(-1).state, 'uncertain');
});

test('public request handler rejects extra inputs, oversized bodies, and disabled execution', async () => {
  const f = await fixture(); let calls = 0;
  const executor = { execute: async () => { calls++; return {}; } };
  for (const body of [{ ...f.request, accountID: 'attacker' }, { ...f.request, oidcToken: 'a'.repeat(20000) }]) {
    const response = await core.handleDeploymentRequest(new Request('https://deployer.invalid/v1/deployments/execute', { method: 'POST', body: JSON.stringify(body) }), executor, { enabled: true });
    assert.equal(response.status, 400);
  }
  const response = await core.handleDeploymentRequest(new Request('https://deployer.invalid/v1/deployments/execute', { method: 'POST', body: JSON.stringify(f.request) }), executor, { enabled: false });
  assert.equal(response.status, 503);
  assert.equal(calls, 0);
});

test('public request handler exposes only execution and sanitized receipts', async () => {
  const f = await fixture();
  const request = () => new Request('https://deployer.invalid/v1/deployments/execute', { method: 'POST', body: JSON.stringify(f.request) });
  const response = await core.handleDeploymentRequest(request(), f.create(), { enabled: true });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('Cache-Control'), 'no-store');
  assert.equal((await response.json()).deploymentID, deploymentID);
  const rejected = await core.handleDeploymentRequest(request(), { execute() { throw Error(token); } }, { enabled: true });
  assert.equal(rejected.status, 409);
  assert.ok(!(await rejected.text()).includes(token));
  const other = await core.handleDeploymentRequest(new Request('https://deployer.invalid/v1/deployments/upload'), f.create(), { enabled: true });
  assert.equal(other.status, 404);
});

test('concurrent requests cannot reserve and mutate one operation twice', async () => {
  const f = await fixture();
  const results = await Promise.allSettled([f.create().execute(f.request), f.create().execute(f.request)]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(f.events.filter(event => event === 'upload').length, 1);
  assert.equal(f.events.filter(event => event === 'activate').length, 1);
});

function providerFixture() {
  const calls = [];
  const op = { accountID: 'a'.repeat(32), scriptName: 'fixture-worker', zoneID: 'b'.repeat(32), hostname: 'app.example.com', expectedDeploymentID: baselineID, source: { repository: 'susanbeasles/fixture', repositoryID: 3, commitSHA: '1'.repeat(40) } };
  const responses = new Map([
    [`https://api.cloudflare.com/client/v4/zones/${op.zoneID}`, { id: op.zoneID, name: 'example.com', status: 'active', account: { id: op.accountID } }],
    [`https://api.cloudflare.com/client/v4/accounts/${op.accountID}/workers/domains?hostname=app.example.com`, [{ id: 'domain-id', hostname: op.hostname, service: op.scriptName, zone_id: op.zoneID, enabled: true, previews_enabled: false }]],
    [`https://api.cloudflare.com/client/v4/accounts/${op.accountID}/workers/scripts/${op.scriptName}/subdomain`, { enabled: false, previews_enabled: false }],
    [`https://api.cloudflare.com/client/v4/accounts/${op.accountID}/workers/scripts/${op.scriptName}/deployments`, { deployments: [{ id: baselineID, strategy: 'percentage', versions: [{ version_id: baselineVersionID, percentage: 100 }] }] }],
    [`https://api.cloudflare.com/client/v4/accounts/${op.accountID}/workers/scripts/${op.scriptName}/versions?per_page=1`, { items: [{ id: baselineVersionID }] }],
    [`https://api.cloudflare.com/client/v4/accounts/${op.accountID}/workers/scripts/${op.scriptName}/versions/${baselineVersionID}`, { id: baselineVersionID, resources: { bindings: [] } }],
    ['https://api.github.com/repos/susanbeasles/fixture', { id: 3, archived: false, fork: false }],
    [`https://api.github.com/repos/susanbeasles/fixture/git/commits/${op.source.commitSHA}`, { sha: op.source.commitSHA, verification: { verified: true, reason: 'valid' } }],
  ]);
  const fetcher = async (url, options) => {
    calls.push({ url: String(url), options });
    const value = responses.get(String(url));
    if (value === undefined) throw Error('Unexpected test URL ' + url);
    return Response.json(String(url).startsWith('https://api.cloudflare.com/') ? { success: true, result: value } : value);
  };
  return { calls, op, responses, fetcher, create() { return providerModule.createCloudflareProvider({ token, fetcher }); } };
}

test('provider preflight verifies owned target and signed source without sending provider token to GitHub', async () => {
  const f = providerFixture();
  await f.create().preflight(f.op, (await fixture()).artifact);
  assert.equal(f.calls.length, 8);
  for (const { url, options } of f.calls) {
    assert.equal(options.redirect, 'error');
    assert.equal(options.method, 'GET');
    const headers = new Headers(options.headers);
    assert.equal(headers.get('Authorization'), url.startsWith('https://api.cloudflare.com/') ? `Bearer ${token}` : null);
  }
});
function ingressFixture(type='routes'){
 const f=providerFixture(),origin='https://api.cloudflare.com/client/v4',zones=['b'.repeat(32),'c'.repeat(32)],route={id:'d'.repeat(32),zoneID:zones[0],pattern:f.op.hostname+'/component*'};
 f.op.ingress={type,zoneIDs:zones,...(type==='routes'?{routes:[route]}:{})};if(type==='service-only')f.op.zoneID=f.op.hostname=null;
 f.responses.set(origin+`/zones?account.id=${f.op.accountID}&type=full,partial,secondary,internal&per_page=50&page=1`,zones.map((id,i)=>({id,name:i?'another.example':'example.com',status:'active',account:{id:f.op.accountID}})));
 f.responses.set(origin+`/accounts/${f.op.accountID}/workers/domains?service=${f.op.scriptName}`,[]);
 for(const id of zones)f.responses.set(origin+`/zones/${id}/workers/routes`,type==='routes'&&id===zones[0]?[{id:route.id,pattern:route.pattern,script:f.op.scriptName}]:[]);
 let malformed=null,round=0;const fetcher=async(url,options)=>{
  const response=await f.fetcher(url,options),body=await response.json();
  if(String(url).includes('per_page=50')||String(url).includes('/workers/domains?service=')){body.result_info={page:1,per_page:50,count:body.result.length,total_count:body.result.length,total_pages:1};if(malformed)malformed(body,String(url),++round);}
  return Response.json(body);
 };
 return {...f,origin,zones,route,setMalformed:fn=>malformed=fn,create:()=>providerModule.createCloudflareProvider({token,fetcher})};
}
test('existing path routes and service-only ingress are observed without route or domain mutations',async()=>{
 for(const type of ['routes','service-only']){const f=ingressFixture(type);await f.create().preflight(f.op,(await fixture()).artifact);assert(f.calls.every(c=>c.options.method==='GET'));for(const id of f.zones)assert(f.calls.some(c=>c.url.endsWith(`/zones/${id}/workers/routes`)));}
});
test('documented single-page domain list does not require optional pagination metadata',async()=>{
 const f=ingressFixture('service-only');f.setMalformed((body,url)=>{if(url.includes('/workers/domains?service='))delete body.result_info;});await f.create().preflight(f.op,(await fixture()).artifact);
});
test('ingress inventory exhausts real zone pagination and permits unrelated routes without changing them',async()=>{
 const f=ingressFixture('service-only'),zones=Array.from({length:51},(_,i)=>({id:(i+1).toString(16).padStart(32,'0'),name:`zone${i}.example`,status:'active',account:{id:f.op.accountID}}));
 f.op.ingress.zoneIDs=zones.map(z=>z.id);for(const zone of zones)f.responses.set(f.origin+`/zones/${zone.id}/workers/routes`,[{id:'e'.repeat(32),pattern:zone.name+'/*',script:'unrelated-worker'}]);
 let missing=false;
 const fetcher=async(url,options)=>{
  const parsed=new URL(url);if(parsed.pathname==='/client/v4/zones'){
   f.calls.push({url:String(url),options});const page=Number(parsed.searchParams.get('page')),result=zones.slice((page-1)*50,page*50);
   return Response.json({success:true,result:missing&&page===2?[]:result,result_info:{page,per_page:50,count:result.length,total_count:51,total_pages:2}});
  }
  return f.fetcher(url,options);
 };
 const provider=providerModule.createCloudflareProvider({token,fetcher});
 await provider.preflight(f.op,(await fixture()).artifact);assert(f.calls.some(c=>c.url.endsWith('&page=2')));assert(f.calls.every(c=>c.options.method==='GET'));
 missing=true;await assert.rejects(provider.preflight(f.op,(await fixture()).artifact));
});
test('ingress inventory denies foreign/changed/hidden public routes, incomplete pages and unknown account zones',async()=>{
 for(const defect of ['route','extra-route','other-zone-route','domain','unknown-zone','page','duplicate','drift']){
  const f=ingressFixture(),routeURL=f.origin+`/zones/${f.zones[0]}/workers/routes`,zoneURL=f.origin+`/zones?account.id=${f.op.accountID}&type=full,partial,secondary,internal&per_page=50&page=1`;
  if(defect==='route')f.responses.get(routeURL)[0].pattern=f.op.hostname+'/broader*';
  if(defect==='extra-route')f.responses.get(routeURL).push({id:'e'.repeat(32),pattern:f.op.hostname+'/extra*',script:f.op.scriptName});
  if(defect==='other-zone-route')f.responses.get(f.origin+`/zones/${f.zones[1]}/workers/routes`).push({id:'e'.repeat(32),pattern:'another.example/*',script:f.op.scriptName});
  if(defect==='domain')f.responses.get(f.origin+`/accounts/${f.op.accountID}/workers/domains?service=${f.op.scriptName}`).push({id:'hidden',service:f.op.scriptName});
  if(defect==='unknown-zone')f.responses.get(zoneURL).push({id:'f'.repeat(32),name:'other.example',status:'active',account:{id:f.op.accountID}});
  if(defect==='page')f.setMalformed(body=>delete body.result_info.total_pages);
  if(defect==='duplicate')f.responses.get(zoneURL).push(structuredClone(f.responses.get(zoneURL)[0]));
  if(defect==='drift')f.setMalformed((body,url,round)=>{if(url===zoneURL&&round>2)body.result[0].name='changed.example';});
  await assert.rejects(f.create().preflight(f.op,(await fixture()).artifact));assert(f.calls.every(c=>c.options.method==='GET'));
 }
 const privateWorker=ingressFixture('service-only');privateWorker.responses.get(privateWorker.origin+`/zones/${privateWorker.zones[1]}/workers/routes`).push({id:'e'.repeat(32),pattern:'another.example/*',script:privateWorker.op.scriptName});await assert.rejects(privateWorker.create().preflight(privateWorker.op,(await fixture()).artifact));
});
test('private source read credential remains confined to the fixed GitHub API', async () => {
  const f=providerFixture(),githubToken='synthetic-read-only-github-token';
  const provider=providerModule.createCloudflareProvider({token,githubToken,fetcher:f.fetcher});
  await provider.preflight(f.op,(await fixture()).artifact);
  for(const {url,options} of f.calls)assert.equal(new Headers(options.headers).get('Authorization'),`Bearer ${url.startsWith('https://api.github.com/')?githubToken:token}`);
});

test('provider refuses an unverified source or mismatched existing domain without a write', async () => {
  for (const defect of ['source', 'domain', 'zone', 'preview', 'baseline']) {
    const f = providerFixture();
    if (defect === 'source') f.responses.set(`https://api.github.com/repos/susanbeasles/fixture/git/commits/${f.op.source.commitSHA}`, { sha: f.op.source.commitSHA, verification: { verified: false, reason: 'unsigned' } });
    if (defect === 'domain') f.responses.get(`https://api.cloudflare.com/client/v4/accounts/${f.op.accountID}/workers/domains?hostname=app.example.com`)[0].service = 'other-worker';
    if (defect === 'zone') f.responses.get(`https://api.cloudflare.com/client/v4/zones/${f.op.zoneID}`).account.id = 'c'.repeat(32);
    if (defect === 'preview') f.responses.get(`https://api.cloudflare.com/client/v4/accounts/${f.op.accountID}/workers/scripts/${f.op.scriptName}/subdomain`).previews_enabled = true;
    if (defect === 'baseline') f.responses.get(`https://api.cloudflare.com/client/v4/accounts/${f.op.accountID}/workers/scripts/${f.op.scriptName}/deployments`).deployments[0].id = deploymentID;
    await assert.rejects(f.create().preflight(f.op, (await fixture()).artifact));
    assert.ok(f.calls.every(x => x.options.method === 'GET'));
  }
});

test('provider uses multipart version upload and an exact one-version activation body', async () => {
  const f = providerFixture(), artifact = (await fixture()).artifact;
  const provider = providerModule.createCloudflareProvider({ token, fetcher: async (url, options) => {
    f.calls.push({ url, options });
    return Response.json({ success: true, result: { id: url.includes('/versions?') ? versionID : deploymentID } });
  } });
  assert.deepEqual(await provider.upload(f.op, artifact), { versionID });
  assert.deepEqual(await provider.activate(f.op, versionID), { deploymentID });
  assert.equal(f.calls[0].url, `https://api.cloudflare.com/client/v4/accounts/${f.op.accountID}/workers/scripts/fixture-worker/versions?bindings_inherit=strict`);
  assert.equal(f.calls[0].options.method, 'POST');
  assert.deepEqual(JSON.parse(await f.calls[0].options.body.get('metadata').text()), artifact.metadata);
  assert.equal(await f.calls[0].options.body.get('worker.mjs').text(), artifact.modules[0].content);
  assert.equal(f.calls[0].options.body.get('worker.mjs').type, 'application/javascript+module');
  assert.deepEqual(JSON.parse(f.calls[1].options.body), { strategy: 'percentage', versions: [{ version_id: versionID, percentage: 100 }] });
});

test('provider errors suppress remote bodies and network exception secrets', async () => {
  for (const fetcher of [async () => { throw Error(token); }, async () => new Response(token, { status: 403 })]) {
    const f = providerFixture();
    await assert.rejects(providerModule.createCloudflareProvider({ token, fetcher }).preflight(f.op), error => !error.message.includes(token));
  }
});

test('named inheritance preserves every existing secret without accepting other bindings', async () => {
  const f = providerFixture(), artifact = (await fixture()).artifact;
  const key = `https://api.cloudflare.com/client/v4/accounts/${f.op.accountID}/workers/scripts/${f.op.scriptName}/versions/${baselineVersionID}`;
  f.responses.get(key).resources.bindings = [{ name: 'EXISTING_SECRET', type: 'secret_text' }];
  artifact.metadata.bindings = [{ name: 'EXISTING_SECRET', type: 'inherit' }];
  await f.create().preflight(f.op, artifact);
  artifact.metadata.bindings = [];
  await assert.rejects(f.create().preflight(f.op, artifact), /verification failed/);
  artifact.metadata.bindings = [{ name: 'OTHER_BINDING', type: 'inherit' }];
  await assert.rejects(f.create().preflight(f.op, artifact), /verification failed/);
});

test('a newer unactivated upload blocks inheritance and deployment before any mutation', async () => {
  const f = providerFixture();
  f.responses.get(`https://api.cloudflare.com/client/v4/accounts/${f.op.accountID}/workers/scripts/${f.op.scriptName}/versions?per_page=1`).items[0].id = versionID;
  await assert.rejects(f.create().preflight(f.op, (await fixture()).artifact), /verification failed/);
  assert.ok(f.calls.every(x => x.options.method === 'GET'));
});

test('readback requires the newly uploaded version at one hundred percent and exact domain', async () => {
  const f = providerFixture();
  const base = `https://api.cloudflare.com/client/v4/accounts/${f.op.accountID}/workers/scripts/${f.op.scriptName}`;
  f.responses.set(base + `/versions/${versionID}`, { id: versionID });
  f.responses.set(base + '/deployments', { deployments: [{ id: deploymentID, strategy: 'percentage', versions: [{ version_id: versionID, percentage: 100 }] }] });
  assert.deepEqual(await f.create().verify(f.op, { versionID, deploymentID }), { versionID, deploymentID });
  f.responses.get(base + '/deployments').deployments[0].versions[0].percentage = 50;
  await assert.rejects(f.create().verify(f.op, { versionID, deploymentID }), /verification failed/);
});
