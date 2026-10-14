import type {submissionJournal} from './submission-journal.ts';
import type {SubmissionProgress} from './submission.ts';
// Installed journal binding: metadata checkpoints cannot change the immutable
// owner/repository/source/message or rewind a claimed execution.
export function submissionProgress(journal: ReturnType<typeof submissionJournal>, generationID: string): SubmissionProgress {
 if (typeof generationID !== 'string' || !/^[a-f0-9]{64}$/.test(generationID)) throw Error('Invalid submission progress reference');
 return {
  async begin(intent, message) {
   const record = await journal.read(generationID);
   return record?.state === 'preparing' && record.started === true && intent.generationID === generationID && intent.repositoryID === record.repositoryID && intent.baseSHA === record.baseSHA && intent.sourceSHA === record.sourceSHA && message === record.message;
  },
  prepared: value => journal.transition(generationID, 'preparing', 'retaining', {...value}),
  retained: retentionDigest => journal.transition(generationID, 'retaining', 'signing', {retentionDigest}),
  signed: commitSHA => journal.transition(generationID, 'signing', 'publishing', {commitSHA}),
  async published() {
   const record = await journal.read(generationID);
   if (record?.state === 'published-awaiting-validation') return true;
   if (record?.state !== 'publishing' && record?.state !== 'uncertain') return false;
   return journal.transition(generationID, record.state, 'published-awaiting-validation');
  },
  async uncertain() {
   const record = await journal.read(generationID);
   if (!record) return false;
   if (['uncertain', 'failed', 'published-awaiting-validation'].includes(record.state)) return true;
   return journal.transition(generationID, record.state, 'uncertain');
  }
 };
}
