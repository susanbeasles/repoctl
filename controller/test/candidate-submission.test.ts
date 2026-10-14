import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, realpath, rm, readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {candidateSubmission} from '../src/candidate/submission.ts';
const intent = {repositoryID: 7, baseSHA: 'a'.repeat(40), sourceSHA: 'b'.repeat(40), generationID: 'c'.repeat(64)};
async function fixture(mode = 'good') {
 const root = await realpath(await mkdtemp(join(tmpdir(), 'repoctl-submission-'))), directory = join(root, 'job'), calls: string[] = [];
 const prepared = {protocol: 'repoctl-candidate-preparation-v1', state: 'prepared-awaiting-signature', ...intent, treeSHA: 'd'.repeat(40), snapshotDigest: 'e'.repeat(64)};
 const report = (binding: object) => ({protocol: 'repoctl-integration-generation-v1', published: true, repositoryID: 7, ref: 'refs/heads/int/'+intent.generationID, ...binding, token: 'SECRET'});
 const job = candidateSubmission({repositoryID: 7, directory, timeoutMS: 100,
  preparation: {prepare: async () => {calls.push('prepare'); return prepared;}},
  snapshots: {retain: async binding => {calls.push('retain'); prepared.treeSHA = 'f'.repeat(40); if (mode === 'stall') return await new Promise(() => {}); return {...binding, verified: true, immutable: mode !== 'unretained', receiptDigest: 'f'.repeat(64)};}},
  signing: {finalize: async () => {calls.push('sign'); return {...prepared, treeSHA: 'd'.repeat(40), protocol: 'repoctl-signed-candidate-v1', state: 'signed-awaiting-integration-generation', commitSHA: 'f'.repeat(40)};}},
  generations: {publish: async binding => {calls.push('publish'); if (mode === 'lost') throw Error('SECRET'); return report(binding);}, reconcile: async binding => {calls.push('reconcile'); return report(binding);}}
 });
 return {root, directory, calls, job};
}
test('submission preserves phase order and returns publication without promotion authority', async () => {
 const f = await fixture(); try {
  const result = await f.job.submit(intent, 'feat: fixture');
  assert.deepEqual(f.calls, ['prepare', 'retain', 'sign', 'publish']);
  assert.equal(result.state, 'published-awaiting-validation'); assert.ok(!JSON.stringify(result).includes('SECRET'));
  assert.equal(JSON.parse(await readFile(join(f.directory, 'generation.json'), 'utf8')).treeSHA, 'd'.repeat(40));
  await assert.rejects(f.job.submit(intent, 'retry')); assert.equal(f.calls.length, 4);
  assert.deepEqual(await f.job.reconcile(), result); assert.deepEqual(f.calls, ['prepare', 'retain', 'sign', 'publish', 'reconcile']);
 } finally {await rm(f.root, {recursive: true, force: true});}
});
test('lost publication retains exact generation and reconciles without repeating preparation/signing', async () => {
 const f = await fixture('lost'); try {
  await assert.rejects(f.job.submit(intent, 'feat: fixture'), error => !String(error).includes('SECRET'));
  assert.equal(JSON.parse(await readFile(join(f.directory, 'failed.json'), 'utf8')).phase, 'publication');
  assert.equal((await f.job.reconcile()).state, 'published-awaiting-validation');
  assert.deepEqual(f.calls, ['prepare', 'retain', 'sign', 'publish', 'reconcile']);
 } finally {await rm(f.root, {recursive: true, force: true});}
});
test('unretained or stalled snapshots cannot reach signing/publication', async () => {
 for (const mode of ['unretained', 'stall']) {
  const f = await fixture(mode); try {
   await assert.rejects(f.job.submit(intent, 'feat: fixture'));
   assert.deepEqual(f.calls, ['prepare', 'retain']);
   await assert.rejects(f.job.reconcile()); assert.deepEqual(f.calls, ['prepare', 'retain']);
  } finally {await rm(f.root, {recursive: true, force: true});}
 }
});
