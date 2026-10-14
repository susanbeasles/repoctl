import type {candidateSubmission, SubmissionProgress} from './submission.ts';
import type {submissionJournal} from './submission-journal.ts';
import {submissionProgress} from './submission-progress.ts';
interface Reference {readonly ownerID: number; readonly repositoryID: number; readonly generationID: string;}
type Journal = ReturnType<typeof submissionJournal>;
type Job = NonNullable<Awaited<ReturnType<Journal['read']>>>;
interface Configuration {
 readonly ownerID: number; readonly repositoryID: number; readonly journal: Journal;
 readonly jobs: {open(record: Readonly<Job>, progress: SubmissionProgress, context: {signal: AbortSignal}): Promise<ReturnType<typeof candidateSubmission>>};
}
// Installed isolated runner. The queue grants dispatch; this separate atomic
// claim grants one execution. Restarts never recreate a claimed signing job.
export function submissionRunner({ownerID, repositoryID, journal, jobs}: Configuration) {
 if (![ownerID, repositoryID].every(value => Number.isSafeInteger(value) && value > 0) || ![journal?.claim, journal?.read, jobs?.open].every(value => typeof value === 'function')) throw Error('Invalid submission runner configuration');
 function reference(value: Reference) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype || Object.keys(value).sort().join() !== 'generationID,ownerID,repositoryID' || value.ownerID !== ownerID || value.repositoryID !== repositoryID || typeof value.generationID !== 'string' || !/^[a-f0-9]{64}$/.test(value.generationID)) throw Error('Runner identity differs');
  return Object.freeze({...value});
 }
 async function open(record: Job, progress: SubmissionProgress) {
  const controller = new AbortController(); let timer: ReturnType<typeof setTimeout> | undefined;
  try {return await Promise.race([jobs.open(Object.freeze({...record}), progress, {signal: controller.signal}), new Promise<never>((_, reject) => {timer = setTimeout(() => {controller.abort(); reject(Error('Job adapter timeout'));}, 10000);})]);}
  finally {clearTimeout(timer); controller.abort();}
 }
 async function verify(record: Job, result: Awaited<ReturnType<ReturnType<typeof candidateSubmission>['submit']>>) {
  const retained = await journal.read(record.generationID);
  if (!retained || retained.state !== 'published-awaiting-validation' || retained.ownerID !== ownerID || result.protocol !== 'repoctl-submission-v1' || result.ref !== 'refs/heads/int/'+record.generationID || result.repositoryID !== repositoryID || result.generationID !== record.generationID || result.baseSHA !== record.baseSHA || result.commitSHA !== retained.commitSHA || result.treeSHA !== retained.treeSHA || result.state !== 'published-awaiting-validation') throw Error('Runner result differs from retained job');
  return Object.freeze({protocol: 'repoctl-submission-v1', state: 'published-awaiting-validation', repositoryID, generationID: record.generationID, ref: 'refs/heads/int/'+record.generationID, baseSHA: record.baseSHA, treeSHA: retained.treeSHA!, commitSHA: retained.commitSHA!});
 }
 return {
  async run(value: Reference) {
   const binding = reference(value), record = await journal.claim(binding.generationID);
   if (!record) return {accepted: false, ...binding};
   if (record.ownerID !== ownerID || record.repositoryID !== repositoryID) throw Error('Retained runner identity differs');
   const progress = submissionProgress(journal, binding.generationID);
   try {
    const job = await open(record, progress);
    const result = await job.submit({repositoryID, generationID: record.generationID, baseSHA: record.baseSHA, sourceSHA: record.sourceSHA}, record.message);
    return {accepted: true, ...binding, result: await verify(record, result)};
   } catch {
    let journalAcknowledged = false;
    try {journalAcknowledged = await progress.uncertain();} catch {journalAcknowledged = false;}
    throw Error(journalAcknowledged ? 'Submission execution uncertain; reconcile retained job without rerunning' : 'Submission execution and journal checkpoint uncertain; inspect both before recovery');
   }
  },
  async reconcile(value: Reference) {
   const binding = reference(value), record = await journal.read(binding.generationID);
   if (!record || record.ownerID !== ownerID || record.repositoryID !== repositoryID || !record.started || !['publishing', 'uncertain', 'published-awaiting-validation'].includes(record.state) || !record.commitSHA || !record.treeSHA || !record.retentionDigest) throw Error('No retained publication to reconcile; no execution started');
   try {const progress = submissionProgress(journal, binding.generationID); const job = await open(record, progress); return await verify(record, await job.reconcile());}
   catch {throw Error('Submission publication reconciliation unresolved; no execution started');}
  }
 };
}
