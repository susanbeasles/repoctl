import {Miniflare, convertV4MiniflareOptions} from 'miniflare';
import {readFile} from 'node:fs/promises';
import assert from 'node:assert/strict';
const bundle = process.argv[2], ingress = process.argv[3]; if (!bundle || !ingress) throw Error('Operator and ingress bundles required');
const input = {operationID: 'a'.repeat(64), approvalReference: 'b'.repeat(64)};
const config = {issuer: 'https://personal-fixture.cloudflareaccess.com', audience: 'a'.repeat(64), subject: '12345678-1234-1234-1234-123456789abc', lifetime: 600};
const pair = await crypto.subtle.generateKey({name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1])}, true, ['sign', 'verify']);
const jwk = {...await crypto.subtle.exportKey('jwk', pair.publicKey), kid: 'access-fixture', alg: 'RS256', use: 'sig'};
async function token(changes: Record<string, unknown> = {}) {
 const now = Math.floor(Date.now()/1000), header = Buffer.from(JSON.stringify({alg: 'RS256', kid: jwk.kid})).toString('base64url');
 const payload = Buffer.from(JSON.stringify({iss: config.issuer, aud: [config.audience], sub: config.subject, type: 'app', iat: now-10, nbf: now-10, exp: now+300, ...changes})).toString('base64url');
 const body = header+'.'+payload;
 return body+'.'+Buffer.from(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', pair.privateKey, new TextEncoder().encode(body))).toString('base64url');
}
let approvals = 0, registrations = 0, sessions = 0, revoked = false, jobGrants = 0, jobCalls = 0;
const mf = new Miniflare(convertV4MiniflareOptions({workers: [
 {name: 'operator', modules: true, script: await readFile(bundle, 'utf8'), compatibilityDate: '2026-10-04', bindings: {OPERATOR_ENABLED: 'true', OPERATOR_SUBMISSION_ENABLED: 'true', OPERATOR_OWNER_ID: '7', OPERATOR_IDENTITY_CONFIG_JSON: JSON.stringify(config)},
  outboundService: async (r: Request) => {assert.equal(r.url, config.issuer+'/cdn-cgi/access/certs'); assert.equal(r.method, 'GET'); assert.equal(r.headers.get('Cf-Access-Jwt-Assertion'), null); return Response.json({keys: [jwk]});},
  serviceBindings: {
   OPERATOR_JOB_GRANTS: async (r: Request) => {jobGrants++; assert.equal(new URL(r.url).pathname, '/v1/submission/authorize'); return Response.json({...await r.json(), accepted: true});},
   OPERATOR_JOBS: async (r: Request) => {jobCalls++; const input = await r.json(); assert.equal(input.ownerID, 7); assert.ok(['/v1/submission/create', '/v1/submission/status', '/v1/submission/reconcile'].includes(new URL(r.url).pathname)); return Response.json({...input, baseSHA: 'b'.repeat(40), sourceSHA: 'c'.repeat(40), state: 'queued', token: 'SECRET'});},
   OPERATOR_SESSIONS: async (r: Request) => {sessions++; assert.equal(new URL(r.url).pathname, '/v1/operator/session'); const binding = await r.json(); assert.ok(!JSON.stringify(binding).includes('assertion')); return Response.json({...binding, active: true, revoked, validUntil: Math.floor(Date.now()/1000)+20});},
   OPERATOR_APPROVAL: async (r: Request) => {approvals++; const body = await r.json(); assert.equal(body.action, 'status'); return Response.json({...body, accepted: true, session: {ownerID: 7}});},
   OPERATOR_REGISTRATION: async (r: Request) => {registrations++; assert.ok(['/v1/registration/status', '/v1/registration/reconcile'].includes(new URL(r.url).pathname)); return Response.json({...input, state: 'active', appID: 12, token: 'SECRET', code: 'SECRET'});}
  }},
 {name: 'disabled', modules: true, script: await readFile(bundle, 'utf8'), compatibilityDate: '2026-10-04'},
 {name: 'ingress', modules: true, script: await readFile(ingress, 'utf8'), compatibilityDate: '2026-10-04', bindings: {OPERATOR_INGRESS_ENABLED: 'true'}, serviceBindings: {OPERATOR_SERVICE: {name: 'operator', entrypoint: 'OperatorService'}}},
 {name: 'disabled-ingress', modules: true, script: await readFile(ingress, 'utf8'), compatibilityDate: '2026-10-04'},
 {name: 'caller', modules: true, script: 'export default {fetch(r,e){return e.OPERATOR.fetch(r);}}', compatibilityDate: '2026-10-04', serviceBindings: {OPERATOR: {name: 'operator', entrypoint: 'OperatorService'}}},
 {name: 'disabled-caller', modules: true, script: 'export default {fetch(r,e){return e.OPERATOR.fetch(r);}}', compatibilityDate: '2026-10-04', serviceBindings: {OPERATOR: {name: 'disabled', entrypoint: 'OperatorService'}}}
 ,{name: 'submission-caller', modules: true, script: 'export default {fetch(r,e){return e.OPERATOR.fetch(r);}}', compatibilityDate: '2026-10-04', serviceBindings: {OPERATOR: {name: 'operator', entrypoint: 'SubmissionOperatorService'}}}
]}));
try {
 const publicWorker = await mf.getWorker('operator'), caller = await mf.getWorker('ingress'), disabled = await mf.getWorker('disabled-caller'), disabledIngress = await mf.getWorker('disabled-ingress');
 const path = 'https://operator.example/v1/operator/enrollment/status';
 const options = (assertion?: string) => ({method: 'POST', headers: {'Content-Type': 'application/json', ...(assertion ? {'Cf-Access-Jwt-Assertion': assertion} : {})}, body: JSON.stringify(input)});
 const good = await token();
 assert.equal((await publicWorker.fetch(path, options(good))).status, 404);
 assert.equal((await disabled.fetch(path, options(good))).status, 503);
 assert.equal((await disabledIngress.fetch(path, options(good))).status, 503);
 assert.equal((await caller.fetch(path+'?token=ignored', options(good))).status, 404);
 assert.equal((await caller.fetch(path, options())).status, 403);
 assert.equal((await caller.fetch(path, options(await token({sub: 'foreign'})))).status, 403);
 assert.equal((await caller.fetch(path, options(await token({aud: ['b'.repeat(64)]})))).status, 403);
 assert.equal((await caller.fetch(path, options(await token({exp: Math.floor(Date.now()/1000)-1})))).status, 403);
 assert.equal(sessions, 0); assert.equal(approvals, 0); assert.equal(registrations, 0);
 revoked = true; assert.equal((await caller.fetch(path, options(good))).status, 403); assert.equal(sessions, 1); assert.equal(approvals, 0);
 revoked = false;
 const response = await caller.fetch(path, options(good));
 assert.equal(response.status, 200); assert.equal(response.headers.get('Cache-Control'), 'no-store');
 assert.deepEqual(await response.json(), {protocol: 'repoctl-operator-enrollment-v1', operationID: input.operationID, state: 'active', appID: 12});
 assert.equal((await caller.fetch(path.replace('/status', '/reconcile'), options(good))).status, 200);
 assert.equal(approvals, 2); assert.equal(registrations, 2);
 const submit = await mf.getWorker('submission-caller'), submissionPath = 'https://operator.example/v1/operator/submission/create';
 const submitted = {repositoryID: 7, generationID: 'a'.repeat(64), baseSHA: 'b'.repeat(40), sourceSHA: 'c'.repeat(40), message: 'feat: fixture'};
 const submissionOptions = (assertion: string) => ({...options(assertion), body: JSON.stringify(submitted)});
 assert.equal((await submit.fetch(submissionPath, submissionOptions(await token({sub: 'foreign'})))).status, 403); assert.equal(jobCalls, 0); assert.equal(jobGrants, 0);
 revoked = true; assert.equal((await submit.fetch(submissionPath, submissionOptions(good))).status, 403); assert.equal(jobCalls, 0); revoked = false;
 const queued = await submit.fetch(submissionPath, submissionOptions(good)); assert.equal(queued.status, 200); assert.ok(!(await queued.text()).includes('SECRET')); assert.equal(jobGrants, 1); assert.equal(jobCalls, 1);
 console.log('PASS: actual workerd enrollment ingress/private RPC and private submission admission, RSA Access verification, foreign/expired/revoked denial before job grants, approved recovery and secret-free projection; synthetic JWKS/session/job providers');
} finally {await mf.dispose();}
