import test from 'node:test';
import assert from 'node:assert/strict';
import {operatorSubmission} from '../src/operator/submission.ts';
const intent = {repositoryID: 7, generationID: 'a'.repeat(64), baseSHA: 'b'.repeat(40), sourceSHA: 'c'.repeat(40), message: 'feat: fixture'};
const owner = {ownerID: 9, authorized: true};
test('submission admission binds owner, exact intent and action before queued job creation', async () => {
 let calls = 0;
 const observed = async (input: {ownerID: number; repositoryID: number; generationID: string}) => {calls++; return {...input, ...intent, state: 'queued', token: 'SECRET'};};
 const api = operatorSubmission({ownerID: 9, authority: {authorize: async input => ({...input, accepted: true})}, jobs: {create: observed, status: observed, reconcile: observed}});
 await assert.rejects(api.create(intent, {...owner, ownerID: 8}));
 await assert.rejects(api.create({...intent, ownerID: 9}, owner)); assert.equal(calls, 0);
 const result = await api.create(intent, owner); assert.equal(result.state, 'queued'); assert.ok(!JSON.stringify(result).includes('SECRET')); assert.equal(calls, 1);
 assert.equal((await api.status({repositoryID: 7, generationID: intent.generationID}, owner)).sourceSHA, intent.sourceSHA);
});
test('foreign grants and late approval cannot start or replay a submission job', async () => {
 let calls = 0, finish!: (value: unknown) => void;
 const observed = async () => {calls++; throw Error('SECRET');};
 const jobs = {create: observed, status: observed, reconcile: observed};
 const denied = operatorSubmission({ownerID: 9, authority: {authorize: async input => ({...input, accepted: true, action: 'status'})}, jobs});
 await assert.rejects(denied.create(intent, owner)); assert.equal(calls, 0);
 const delayed = operatorSubmission({ownerID: 9, timeoutMS: 100, authority: {authorize: async input => await new Promise(resolve => {finish = () => resolve({...input, accepted: true});})}, jobs});
 await assert.rejects(delayed.create(intent, owner)); finish(null); await new Promise(resolve => setTimeout(resolve, 10)); assert.equal(calls, 0);
});
