import test from 'node:test';
import assert from 'node:assert/strict';
import {operatorEnrollment} from '../src/operator/enrollment.ts';
import {operatorHTTP} from '../src/operator/http.ts';
const intent = {operationID: 'a'.repeat(64), approvalReference: 'b'.repeat(64)};
const request = (value: unknown = intent) => new Request('https://operator.example/v1/operator/enrollment/status', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(value)});
test('operator ingress is disabled by default and verifies owner before recovery', async () => {
 let calls = 0;
 const enrollment = {status: async () => {calls++; return {protocol: 'repoctl-operator-enrollment-v1', operationID: intent.operationID, state: 'active'};}, reconcile: async () => {calls++; return {protocol: 'repoctl-operator-enrollment-v1', operationID: intent.operationID, state: 'staged'};}};
 const disabled = operatorHTTP({ownerID: 7, enrollment, identity: {verify: async () => {calls++; return {ownerID: 7, authorized: true};}}});
 assert.equal((await disabled.fetch(request())).status, 503); assert.equal(calls, 0);
 const foreign = operatorHTTP({enabled: true, ownerID: 7, enrollment, identity: {verify: async () => ({ownerID: 8, authorized: true})}});
 assert.equal((await foreign.fetch(request())).status, 403); assert.equal(calls, 0);
 const service = operatorHTTP({enabled: true, ownerID: 7, enrollment, identity: {verify: async () => ({ownerID: 7, authorized: true})}});
 assert.equal((await service.fetch(request({...intent, ownerID: 7}))).status, 403); assert.equal(calls, 0);
 const response = await service.fetch(request()); assert.equal(response.status, 200); assert.equal(response.headers.get('Cache-Control'), 'no-store'); assert.equal(calls, 1);
});
test('operator ingress rejects routes, oversized bodies and identity errors without disclosure', async () => {
 let calls = 0;
 const service = operatorHTTP({enabled: true, ownerID: 7, enrollment: {status: async () => {calls++; return {};}, reconcile: async () => {calls++; return {};}} , identity: {verify: async () => {throw Error('SECRET');}}});
 const result = await service.fetch(request()); assert.equal(result.status, 403); assert.ok(!(await result.text()).includes('SECRET')); assert.equal(calls, 0);
 assert.equal((await service.fetch(new Request('https://operator.example/v1/operator/enrollment/status?token=x', {method: 'POST'}))).status, 404);
 assert.equal((await service.fetch(new Request('https://operator.example/v1/operator/enrollment/status'))).status, 405);
});

test('bounded ingress rejects oversized payloads and stalls before private recovery', async () => {
 let calls = 0;
 const enrollment = {status: async () => {calls++; return {};}, reconcile: async () => {calls++; return {};}};
 const identity = {verify: async () => ({ownerID: 7, authorized: true})};
 const service = operatorHTTP({enabled: true, ownerID: 7, enrollment, identity});
 assert.equal((await service.fetch(request('x'.repeat(1025)))).status, 403); assert.equal(calls, 0);
 let signal: AbortSignal | undefined;
 const stalled = operatorHTTP({enabled: true, ownerID: 7, timeoutMS: 100, enrollment, identity: {verify: async (_request, options) => {signal = options.signal; return await new Promise(() => {});}}});
 assert.equal((await stalled.fetch(request())).status, 403); assert.equal(signal?.aborted, true); assert.equal(calls, 0);
});

test('an expired HTTP request cannot begin recovery after delayed approval resolves', async () => {
 let approve!: (value: {accepted: boolean; operationID: string; approvalReference: string; session: {ownerID: number}}) => void;
 let calls = 0;
 const enrollment = operatorEnrollment({ownerID: 7, authority: {authorize: async () => new Promise(resolve => {approve = resolve;})}, registration: {status: async () => {calls++; return {operationID: intent.operationID, state: 'active'};}, reconcile: async () => {calls++; return {operationID: intent.operationID, state: 'active'};}}});
 const service = operatorHTTP({enabled: true, ownerID: 7, timeoutMS: 100, enrollment, identity: {verify: async () => ({ownerID: 7, authorized: true})}});
 const response = await service.fetch(new Request('https://operator.example/v1/operator/enrollment/reconcile', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(intent)}));
 assert.equal(response.status, 403);
 approve({...intent, accepted: true, session: {ownerID: 7}});
 await new Promise(resolve => setTimeout(resolve, 10));
 assert.equal(calls, 0);
});
