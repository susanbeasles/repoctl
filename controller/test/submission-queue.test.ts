import test from 'node:test';
import assert from 'node:assert/strict';
import {submissionJournal} from '../src/candidate/submission-journal.ts';
import {submissionQueue} from '../src/candidate/submission-queue.ts';
async function fixture(mode = 'good') {
 const data = new Map<string, unknown>(); let tail = Promise.resolve();
 const transaction = {get: async <T>(key: string) => structuredClone(data.get(key)) as T | undefined, put: async <T>(key: string, value: T) => {data.set(key, structuredClone(value));}};
 const storage = {...transaction, transaction: <T>(callback: (value: typeof transaction) => Promise<T>) => {const task = tail.then(() => callback(transaction)); tail = task.then(() => {}, () => {}); return task;}};
 const journal = submissionJournal(storage, 9, 7), calls: string[] = [];
 const queue = submissionQueue({ownerID: 9, repositoryID: 7, journal, timeoutMS: 100, runner: {
  start: async reference => {calls.push('start'); assert.equal((await journal.read(reference.generationID))?.state, 'preparing'); if (mode === 'lost') throw Error('SECRET'); return {...reference, accepted: true};},
  reconcile: async () => {calls.push('reconcile');}
 }});
 return {queue, journal, calls};
}
const intent = {ownerID: 9, repositoryID: 7, generationID: 'a'.repeat(64), baseSHA: 'b'.repeat(40), sourceSHA: 'c'.repeat(40), message: 'feat: fixture'};
const reference = {ownerID: 9, repositoryID: 7, generationID: intent.generationID};
test('duplicate queue creation claims and dispatches exactly once', async () => {
 const f = await fixture(); const results = await Promise.all(Array.from({length: 8}, () => f.queue.create(intent)));
 assert.equal(f.calls.filter(value => value === 'start').length, 1); assert.equal(results.length, 8);
 assert.equal((await f.queue.status(reference)).state, 'preparing');
 await f.queue.reconcile(reference); assert.deepEqual(f.calls, ['start', 'reconcile']);
 await assert.rejects(f.queue.create({...intent, message: 'changed'})); assert.equal(f.calls.length, 2);
});
test('lost dispatch is retained uncertain and a duplicate cannot restart work', async () => {
 const f = await fixture('lost'); await assert.rejects(f.queue.create(intent), error => !String(error).includes('SECRET'));
 assert.equal((await f.queue.status(reference)).state, 'uncertain');
 assert.equal((await f.queue.create(intent)).state, 'uncertain');
 await f.queue.reconcile(reference); assert.deepEqual(f.calls, ['start', 'reconcile']);
 await assert.rejects(f.queue.status({...reference, ownerID: 10}));
});
