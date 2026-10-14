import test from 'node:test';
import assert from 'node:assert/strict';
import {operatorSubmission} from '../src/operator/submission.ts';
import {submissionHTTP} from '../src/operator/submission-http.ts';
const intent = {repositoryID: 7, generationID: 'a'.repeat(64), baseSHA: 'b'.repeat(40), sourceSHA: 'c'.repeat(40), message: 'feat: fixture'};
const request = (value: unknown = intent) => new Request('https://operator.example/v1/operator/submission/create', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(value)});
test('submission HTTP verifies owner before exact job grant and projects no private queue data', async () => {
 let grants = 0, jobs = 0;
 const queue = async (input: {ownerID: number}) => {jobs++; return {...intent, ownerID: input.ownerID, state: 'queued', token: 'SECRET'};};
 const submission = operatorSubmission({ownerID: 9, authority: {authorize: async input => {grants++; return {...input, accepted: true};}}, jobs: {create: queue, status: queue, reconcile: queue}});
 const disabled = submissionHTTP({ownerID: 9, submission, identity: {verify: async () => ({ownerID: 9, authorized: true})}});
 assert.equal((await disabled.fetch(request())).status, 503); assert.equal(grants, 0);
 const foreign = submissionHTTP({enabled: true, ownerID: 9, submission, identity: {verify: async () => ({ownerID: 10, authorized: true})}});
 assert.equal((await foreign.fetch(request())).status, 403); assert.equal(grants, 0);
 const http = submissionHTTP({enabled: true, ownerID: 9, submission, identity: {verify: async () => ({ownerID: 9, authorized: true})}});
 assert.equal((await http.fetch(request({...intent, ownerID: 9}))).status, 403); assert.equal(grants, 0);
 const response = await http.fetch(request()); assert.equal(response.status, 200); assert.equal(response.headers.get('Cache-Control'), 'no-store'); assert.ok(!(await response.text()).includes('SECRET')); assert.equal(grants, 1); assert.equal(jobs, 1);
});
test('expired submission ingress cannot create a job after late grant completion', async () => {
 let finish!: () => void, jobs = 0;
 const queue = async () => {jobs++; throw Error('SECRET');};
 const submission = operatorSubmission({ownerID: 9, authority: {authorize: async input => await new Promise(resolve => {finish = () => resolve({...input, accepted: true});})}, jobs: {create: queue, status: queue, reconcile: queue}});
 const http = submissionHTTP({enabled: true, ownerID: 9, timeoutMS: 100, submission, identity: {verify: async () => ({ownerID: 9, authorized: true})}});
 const response = await http.fetch(request()); assert.equal(response.status, 403); finish(); await new Promise(resolve => setTimeout(resolve, 10)); assert.equal(jobs, 0);
});
