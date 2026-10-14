import test from 'node:test';
import assert from 'node:assert/strict';
import {generationJournal} from '../src/candidate/journal.mjs';

test('generation journal rejects coercible identities before touching storage', async () => {
 let calls = 0;
 const storage = {get: async () => {calls++;}, transaction: async () => {calls++;}};
 const journal = generationJournal(storage, 7);
 const id = 'a'.repeat(64), sha = 'b'.repeat(40);
 const binding = {repositoryID: 7, ref: 'refs/heads/int/'+id, generationID: id, baseSHA: sha, commitSHA: sha, treeSHA: sha};
 for (const field of ['generationID', 'baseSHA', 'commitSHA', 'treeSHA']) {
  const value = {...binding, [field]: {toString: () => binding[field as keyof typeof binding]}};
  await assert.rejects(() => journal.reserve(value), /Invalid generation binding/);
 }
 for (const field of ['baseSHA', 'commitSHA', 'treeSHA']) {
  await assert.rejects(() => journal.reserve({...binding, [field]: '0'.repeat(40)}), /Invalid generation binding/);
 }
 assert.equal(calls, 0);
});
