interface Context {readonly ownerID: number; readonly authorized: boolean;}
interface Reference {readonly repositoryID: number; readonly generationID: string;}
interface Intent extends Reference {readonly baseSHA: string; readonly sourceSHA: string; readonly message: string;}
type Action = 'create' | 'status' | 'reconcile';
interface Options {
 readonly ownerID: number; readonly timeoutMS?: number;
 readonly authority: {authorize(input: Reference & {ownerID: number; action: Action; intent?: Intent}, context: {signal: AbortSignal}): Promise<{accepted: boolean; ownerID: number; repositoryID: number; generationID: string; action: Action; intent?: Intent}>};
 readonly jobs: Record<Action, (input: Reference & {ownerID: number; intent?: Intent}, context: {signal: AbortSignal}) => Promise<unknown>>;
}
const sha = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{40}$/.test(value) && !/^0+$/.test(value);
const hash = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
// A job grant is separate from promotion authority. Installed authority must
// verify the enrolled personal repository/builder and exact immutable submission.
export function operatorSubmission({ownerID, authority, jobs, timeoutMS = 10000}: Options) {
 if (!Number.isSafeInteger(ownerID) || ownerID < 1 || !Number.isSafeInteger(timeoutMS) || timeoutMS < 100 || timeoutMS > 10000 || typeof authority?.authorize !== 'function' || !['create', 'status', 'reconcile'].every(action => typeof jobs?.[action as Action] === 'function')) throw Error('Invalid submission operator configuration');
 async function invoke(action: Action, value: unknown, context: Context, external?: AbortSignal) {
  if (context.authorized !== true || context.ownerID !== ownerID) throw Error('Submission owner denied');
  const fields = action === 'create' ? 'baseSHA,generationID,message,repositoryID,sourceSHA' : 'generationID,repositoryID';
  if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype || Object.keys(value).sort().join() !== fields) throw Error('Invalid submission input');
  const raw = value as Record<string, unknown>;
  if (!Number.isSafeInteger(raw.repositoryID) || (raw.repositoryID as number) < 1 || !hash(raw.generationID)) throw Error('Invalid submission reference');
  const reference = Object.freeze({repositoryID: raw.repositoryID as number, generationID: raw.generationID});
  let intent: Readonly<Intent> | undefined;
  if (action === 'create') {
   if (!sha(raw.baseSHA) || !sha(raw.sourceSHA) || typeof raw.message !== 'string' || !raw.message.trim() || new TextEncoder().encode(raw.message).length > 4096 || raw.message.includes('\0')) throw Error('Invalid submission intent');
   intent = Object.freeze({...reference, baseSHA: raw.baseSHA, sourceSHA: raw.sourceSHA, message: raw.message});
  }
  const request = Object.freeze({...reference, ownerID, ...(intent ? {intent} : {})});
  const controller = new AbortController(); let timer: ReturnType<typeof setTimeout> | undefined;
  const abort = () => controller.abort(); external?.addEventListener('abort', abort, {once: true}); if (external?.aborted) controller.abort();
  try {
   const work = async () => {
    controller.signal.throwIfAborted();
    const accepted = await authority.authorize({...request, action}, {signal: controller.signal});
    controller.signal.throwIfAborted();
    if (accepted.accepted !== true || accepted.ownerID !== ownerID || accepted.repositoryID !== reference.repositoryID || accepted.generationID !== reference.generationID || accepted.action !== action || (intent && (!accepted.intent || Object.keys(accepted.intent).sort().join() !== fields || Object.entries(intent).some(([key, expected]) => accepted.intent![key as keyof Intent] !== expected)))) throw Error('Job grant differs');
    const result = await jobs[action](request, {signal: controller.signal});
    controller.signal.throwIfAborted();
    if (!result || typeof result !== 'object') throw Error('Invalid job observation');
    const observed = result as Record<string, unknown>;
    if (observed.ownerID !== ownerID || observed.repositoryID !== reference.repositoryID || observed.generationID !== reference.generationID || !['queued', 'preparing', 'retaining', 'signing', 'publishing', 'published-awaiting-validation', 'uncertain', 'failed'].includes(observed.state as string) || !sha(observed.baseSHA) || !sha(observed.sourceSHA) || (intent && (observed.baseSHA !== intent.baseSHA || observed.sourceSHA !== intent.sourceSHA)) || (observed.state === 'published-awaiting-validation' && (!sha(observed.commitSHA) || !sha(observed.treeSHA)))) throw Error('Job observation differs');
    return Object.freeze({protocol: 'repoctl-operator-submission-v1', ...reference, state: observed.state as string, baseSHA: observed.baseSHA, sourceSHA: observed.sourceSHA, ...(sha(observed.commitSHA) ? {commitSHA: observed.commitSHA} : {}), ...(sha(observed.treeSHA) ? {treeSHA: observed.treeSHA} : {})});
   };
   return await Promise.race([work(), new Promise<never>((_, reject) => {timer = setTimeout(() => {controller.abort(); reject(Error('Submission request timeout'));}, timeoutMS);})]);
  } catch {throw Error('Submission denied or outcome uncertain; inspect retained job before retrying');}
  finally {clearTimeout(timer); external?.removeEventListener('abort', abort); controller.abort();}
 }
 return {create: (value: unknown, context: Context, options: {signal?: AbortSignal} = {}) => invoke('create', value, context, options.signal), status: (value: unknown, context: Context, options: {signal?: AbortSignal} = {}) => invoke('status', value, context, options.signal), reconcile: (value: unknown, context: Context, options: {signal?: AbortSignal} = {}) => invoke('reconcile', value, context, options.signal)};
}
