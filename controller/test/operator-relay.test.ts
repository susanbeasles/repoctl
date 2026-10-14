import test from 'node:test';
import assert from 'node:assert/strict';
import {operatorRelay} from '../src/operator/relay.ts';
const input = {operationID: 'a'.repeat(64), approvalReference: 'b'.repeat(64)};
const request = (body: unknown = input, path = '/v1/operator/enrollment/status') => new Request('https://operator.example' + path, {method: 'POST', headers: {'Content-Type': 'application/json', 'Cf-Access-Jwt-Assertion': 'synthetic.header.signature', 'Authorization': 'SECRET', 'Cookie': 'SECRET'}, body: JSON.stringify(body)});
test('relay gates routes and forwards only fixed enrollment headers and binding', async () => {
 let calls = 0;
 const service = {fetch: async (source: Request) => {
  calls++; assert.equal(source.url, 'https://operator.internal/v1/operator/enrollment/status');
  assert.equal(source.headers.get('Authorization'), null); assert.equal(source.headers.get('Cookie'), null);
  assert.equal(source.headers.get('Cf-Access-Jwt-Assertion'), 'synthetic.header.signature');
  assert.deepEqual(await source.json(), input);
  return Response.json({protocol: 'repoctl-operator-enrollment-v1', operationID: input.operationID, state: 'active', appID: 12, token: 'SECRET'}, {headers: {'Set-Cookie': 'SECRET'}});
 }};
 assert.equal((await operatorRelay({service}).fetch(request())).status, 503);
 const relay = operatorRelay({enabled: true, service});
 assert.equal((await relay.fetch(request(input, '/v1/operator/enrollment/status?token=x'))).status, 404);
 assert.equal((await relay.fetch(request({...input, ownerID: 7}))).status, 403);
 assert.equal(calls, 0);
 const response = await relay.fetch(request()); assert.equal(response.status, 200);
 assert.equal(response.headers.get('Set-Cookie'), null); assert.equal(response.headers.get('Cache-Control'), 'no-store');
 assert.deepEqual(await response.json(), {protocol: 'repoctl-operator-enrollment-v1', operationID: input.operationID, state: 'active', appID: 12}); assert.equal(calls, 1);
});
test('relay bounds bodies, stalls and provider errors without replay or secret output', async () => {
 let calls = 0;
 for (const mode of ['denied', 'oversized', 'foreign', 'stall']) {
  const relay = operatorRelay({enabled: true, timeoutMS: 100, service: {fetch: async () => {
   calls++;
   if (mode === 'stall') return await new Promise(() => {});
   if (mode === 'denied') throw Error('SECRET');
   if (mode === 'oversized') return new Response('SECRET'.repeat(12000));
   return Response.json({protocol: 'repoctl-operator-enrollment-v1', operationID: 'b'.repeat(64), state: 'active', token: 'SECRET'});
  }}});
  assert.equal((await relay.fetch(request('x'.repeat(1025)))).status, 403);
  const response = await relay.fetch(request()); assert.equal(response.status, 403); assert.ok(!(await response.text()).includes('SECRET'));
 }
 assert.equal(calls, 4);
});
