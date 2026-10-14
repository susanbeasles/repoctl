import test from 'node:test';
import assert from 'node:assert/strict';
import {submissionJournal} from '../src/candidate/submission-journal.ts';
import {submissionRunner} from '../src/candidate/submission-runner.ts';
test('duplicate runner deliveries execute one immutable job and recovery never calls submit', async () => {
 const records = new Map<string, unknown>(); let tail = Promise.resolve(), executions = 0, reconciles = 0;
 const transaction = {get: async <T>(key: string) => structuredClone(records.get(key)) as T | undefined, put: async <T>(key: string, value: T) => {records.set(key, structuredClone(value));}};
 const storage = {...transaction, transaction: <T>(callback: (value: typeof transaction) => Promise<T>) => {const pending = tail.then(() => callback(transaction)); tail = pending.then(() => {}, () => {}); return pending;}};
 const journal = submissionJournal(storage, 9, 7), generationID = 'a'.repeat(64);
 const intent = {ownerID: 9, repositoryID: 7, generationID, baseSHA: 'b'.repeat(40), sourceSHA: 'c'.repeat(40), message: 'feat: fixture'};
 const binding = {ownerID: 9, repositoryID: 7, generationID};
 const result = {protocol: 'repoctl-submission-v1', state: 'published-awaiting-validation', repositoryID: 7, generationID, ref: 'refs/heads/int/'+generationID, baseSHA: intent.baseSHA, treeSHA: 'd'.repeat(40), commitSHA: 'e'.repeat(40)};
 await journal.create(intent); await journal.transition(generationID, 'queued', 'preparing');
 const runner = submissionRunner({ownerID: 9, repositoryID: 7, journal, jobs: {open: async (record, progress) => ({
  submit: async (value, message) => {executions++; assert.equal(message, record.message); assert.equal(await progress.begin(value, message), true); await progress.prepared({treeSHA: result.treeSHA, snapshotDigest: 'f'.repeat(64)}); await progress.retained('a'.repeat(64)); await progress.signed(result.commitSHA); await progress.published(); return result;},
  reconcile: async () => {reconciles++; await progress.published(); return result;}
 })}});
 const answers = await Promise.all(Array.from({length: 8}, () => runner.run(binding)));
 assert.equal(answers.filter(answer => answer.accepted).length, 1); assert.equal(executions, 1);
 assert.deepEqual(await runner.reconcile(binding), result); assert.equal(reconciles, 1); assert.equal(executions, 1);
 assert.equal((await runner.run(binding)).accepted, false);
 await assert.rejects(runner.run({...binding, ownerID: 10}));
});
