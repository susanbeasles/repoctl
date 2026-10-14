import test from 'node:test';
import assert from 'node:assert/strict';
import {operatorEnrollment} from '../src/operator/enrollment.ts';
const request = {operationID: 'a'.repeat(64), approvalReference: 'b'.repeat(64)};
const context = {ownerID: 7, authorized: true};
test('operator recovery requires owner context and independently retained approval before private work', async () => {
 let calls = 0;
 const service = operatorEnrollment({ownerID: 7, authority: {authorize: async input => {calls++; return {...input, accepted: true, session: {ownerID: 7}};}}, registration: {status: async () => {calls++; return {operationID: request.operationID, state: 'active', appID: 12, token: 'SECRET'};}, reconcile: async () => {calls++; return {operationID: request.operationID, state: 'staged'};}}});
 for (const c of [{ownerID: 8, authorized: true}, {ownerID: 7, authorized: false}]) await assert.rejects(service.status(request, c), /owner denied/);
 await assert.rejects(service.status({...request, code: 'secret'}, context), /Invalid operator/);
 assert.equal(calls, 0);
 assert.deepEqual(await service.status(request, context), {protocol: 'repoctl-operator-enrollment-v1', operationID: request.operationID, state: 'active', appID: 12});
 assert.deepEqual(await service.reconcile(request, context), {protocol: 'repoctl-operator-enrollment-v1', operationID: request.operationID, state: 'staged'});
 assert.equal(calls, 4);
});
test('foreign approval denies recovery and provider failures never leak or retry', async () => {
 let calls = 0;
 const registration = {status: async () => {calls++; throw Error('SECRET');}, reconcile: async () => {calls++; throw Error('SECRET');}};
 const denied = operatorEnrollment({ownerID: 7, authority: {authorize: async input => ({...input, accepted: true, session: {ownerID: 8}})}, registration});
 await assert.rejects(denied.reconcile(request, context), /^Error: Operator enrollment denied or outcome uncertain$/);
 assert.equal(calls, 0);
 const service = operatorEnrollment({ownerID: 7, authority: {authorize: async input => ({...input, accepted: true, session: {ownerID: 7}})}, registration});
 await assert.rejects(service.reconcile(request, context), /^Error: Operator enrollment denied or outcome uncertain$/);
 assert.equal(calls, 1);
});
