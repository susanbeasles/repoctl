import type {submissionJournal} from './submission-journal.ts';
interface Reference {readonly ownerID: number; readonly repositoryID: number; readonly generationID: string;}
interface Intent extends Reference {readonly baseSHA: string; readonly sourceSHA: string; readonly message: string;}
interface Context {readonly signal?: AbortSignal;}
interface Configuration {
 readonly ownerID: number; readonly repositoryID: number; readonly timeoutMS?: number;
 readonly journal: ReturnType<typeof submissionJournal>;
 readonly runner: {start(reference: Reference, context: {signal: AbortSignal}): Promise<Reference & {accepted: boolean}>; reconcile(reference: Reference, context: {signal: AbortSignal}): Promise<unknown>};
}
// Private installed queue. Its calling boundary must verify the exact job grant.
// Runner has no caller-selected endpoint and loads immutable intent from journal.
export function submissionQueue({ownerID, repositoryID, journal, runner, timeoutMS = 10000}: Configuration) {
 if (![ownerID, repositoryID].every(value => Number.isSafeInteger(value) && value > 0) || !Number.isSafeInteger(timeoutMS) || timeoutMS < 100 || timeoutMS > 10000 || ![journal?.create, journal?.read, journal?.transition, runner?.start, runner?.reconcile].every(value => typeof value === 'function')) throw Error('Invalid submission queue configuration');
 function reference(value: unknown): Readonly<Reference> {
  if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype || Object.keys(value).sort().join() !== 'generationID,ownerID,repositoryID') throw Error('Invalid queue reference');
  const input = value as Reference;
  if (input.ownerID !== ownerID || input.repositoryID !== repositoryID || typeof input.generationID !== 'string' || !/^[a-f0-9]{64}$/.test(input.generationID)) throw Error('Queue identity differs');
  return Object.freeze({...input});
 }
 async function bounded<T>(job: (context: {signal: AbortSignal}) => Promise<T>, external?: AbortSignal): Promise<T> {
  const controller = new AbortController(); let timer: ReturnType<typeof setTimeout> | undefined;
  const abort = () => controller.abort(); external?.addEventListener('abort', abort, {once: true}); if (external?.aborted) controller.abort();
  try {
   controller.signal.throwIfAborted();
   const result = await Promise.race([Promise.resolve().then(() => {controller.signal.throwIfAborted(); return job({signal: controller.signal});}), new Promise<never>((_, reject) => {timer = setTimeout(() => {controller.abort(); reject(Error('Runner timeout'));}, timeoutMS);})]);
   controller.signal.throwIfAborted(); return result;
  } finally {clearTimeout(timer); external?.removeEventListener('abort', abort); controller.abort();}
 }
 async function status(binding: Reference) {
  const record = await journal.read(binding.generationID);
  if (!record || record.ownerID !== ownerID || record.repositoryID !== repositoryID) throw Error('Unknown submission job');
  return Object.freeze({...binding, state: record.state, baseSHA: record.baseSHA, sourceSHA: record.sourceSHA, ...(record.treeSHA ? {treeSHA: record.treeSHA} : {}), ...(record.commitSHA ? {commitSHA: record.commitSHA} : {})});
 }
 return {
  async create(value: Intent, context: Context = {}) {
   context.signal?.throwIfAborted();
   // The journal validates and snapshots the complete primitive intent before I/O.
   const saved = await journal.create(value);
   const binding = reference({ownerID: saved.record.ownerID, repositoryID: saved.record.repositoryID, generationID: saved.record.generationID});
   if (!saved.created) return status(binding); // Never repeat a prior dispatch.
   try {
    context.signal?.throwIfAborted();
    if (await journal.transition(binding.generationID, 'queued', 'preparing') !== true) throw Error('Job already claimed');
    const accepted = await bounded(options => runner.start(binding, options), context.signal);
    if (accepted.accepted !== true || Object.entries(binding).some(([field, expected]) => accepted[field as keyof Reference] !== expected)) throw Error('Runner acknowledgment differs');
    return await status(binding);
   } catch {
    // Do not overwrite later progress retained by an already-running job.
    await journal.transition(binding.generationID, 'queued', 'uncertain');
    await journal.transition(binding.generationID, 'preparing', 'uncertain');
    throw Error('Submission dispatch outcome uncertain; inspect retained job without restarting');
   }
  },
  async status(value: Reference) {return status(reference(value));},
  async reconcile(value: Reference, context: Context = {}) {
   const binding = reference(value); await status(binding);
   try {await bounded(options => runner.reconcile(binding, options), context.signal); return await status(binding);}
   catch {throw Error('Submission reconciliation unresolved; no dispatch attempted');}
  }
 };
}
