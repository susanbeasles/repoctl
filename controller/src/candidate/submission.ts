import {mkdir, open, realpath, writeFile} from 'node:fs/promises';
import {constants} from 'node:fs';
import {dirname, isAbsolute, join} from 'node:path';
interface Intent {readonly repositoryID: number; readonly baseSHA: string; readonly sourceSHA: string; readonly generationID: string;}
interface Generation {readonly generationID: string; readonly baseSHA: string; readonly commitSHA: string; readonly treeSHA: string;}
interface Prepared {readonly protocol: string; readonly state: string; readonly repositoryID: number; readonly baseSHA: string; readonly sourceSHA: string; readonly treeSHA: string; readonly snapshotDigest: string;}
interface Signed extends Prepared {readonly commitSHA: string;}
interface Snapshot {readonly repositoryID: number; readonly sourceSHA: string; readonly snapshotDigest: string;}
interface Context {readonly signal: AbortSignal;}
export interface SubmissionProgress {
 begin(intent: Intent, message: string): Promise<boolean>;
 prepared(value: {treeSHA: string; snapshotDigest: string}): Promise<boolean>;
 retained(receiptDigest: string): Promise<boolean>;
 signed(commitSHA: string): Promise<boolean>;
 published(): Promise<boolean>;
 uncertain(): Promise<boolean>;
}
interface Configuration {
 readonly repositoryID: number; readonly directory: string; readonly timeoutMS?: number;
 readonly preparation: {prepare(intent: Omit<Intent, 'generationID'>, directory: string): Promise<Prepared>};
 readonly snapshots: {retain(binding: Snapshot, pack: string, context: Context): Promise<Snapshot & {verified: boolean; immutable: boolean; receiptDigest: string}>};
 readonly progress?: SubmissionProgress;
 readonly signing: {finalize(preparation: string, output: string, message: string): Promise<Signed>};
 readonly generations: {publish(intent: Generation, context: Context): Promise<unknown>; reconcile(intent: Generation, context: Context): Promise<unknown>};
}
const sha = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{40}$/.test(value) && !/^0+$/.test(value);
const hash = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
function generation(value: unknown): Readonly<Generation> {
 if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype || Object.keys(value).sort().join() !== 'baseSHA,commitSHA,generationID,treeSHA') throw Error('Invalid retained submission');
 const input = value as Record<string, unknown>;
 if (!hash(input.generationID) || !sha(input.baseSHA) || !sha(input.commitSHA) || !sha(input.treeSHA)) throw Error('Invalid retained submission');
 return Object.freeze({generationID: input.generationID, baseSHA: input.baseSHA, commitSHA: input.commitSHA, treeSHA: input.treeSHA});
}
// One installed isolated job. Capabilities own custody, remote retention,
// designated signing and durable generation provenance; none come from intent.
export function candidateSubmission({repositoryID, directory, preparation, snapshots, signing, generations, progress, timeoutMS = 10000}: Configuration) {
 if (!Number.isSafeInteger(repositoryID) || repositoryID < 1 || !isAbsolute(directory) || !Number.isSafeInteger(timeoutMS) || timeoutMS < 100 || timeoutMS > 10000 || ![preparation?.prepare, snapshots?.retain, signing?.finalize, generations?.publish, generations?.reconcile].every(value => typeof value === 'function')) throw Error('Invalid submission job configuration');
 if (progress && ![progress.begin, progress.prepared, progress.retained, progress.signed, progress.published, progress.uncertain].every(value => typeof value === 'function')) throw Error('Invalid submission progress configuration');
 async function canonical() {if (join(await realpath(dirname(directory)), directory.split('/').at(-1)!) !== directory) throw Error('Submission directory must be canonical');}
 async function bounded<T>(job: (context: Context) => Promise<T>): Promise<T> {
  const signal = new AbortController(); let timer: ReturnType<typeof setTimeout> | undefined;
  try {return await Promise.race([Promise.resolve().then(() => job({signal: signal.signal})), new Promise<never>((_, reject) => {timer = setTimeout(() => {signal.abort(); reject(Error('Submission capability timeout'));}, timeoutMS);})]);}
  finally {clearTimeout(timer); signal.abort();}
 }
 async function project(value: unknown, intent: Generation) {
  if (!value || typeof value !== 'object') throw Error('Invalid publication result');
  const result = value as Record<string, unknown>;
  if (result.protocol !== 'repoctl-integration-generation-v1' || result.published !== true || result.repositoryID !== repositoryID || result.ref !== 'refs/heads/int/'+intent.generationID || Object.entries(intent).some(([key, expected]) => result[key] !== expected)) throw Error('Publication binding differs');
  return Object.freeze({protocol: 'repoctl-submission-v1', state: 'published-awaiting-validation', repositoryID, ref: result.ref as string, ...intent});
 }
 return {
  async submit(value: Intent, message: string) {
   if (!value || Object.getPrototypeOf(value) !== Object.prototype || Object.keys(value).sort().join() !== 'baseSHA,generationID,repositoryID,sourceSHA' || value.repositoryID !== repositoryID || !sha(value.baseSHA) || !sha(value.sourceSHA) || !hash(value.generationID) || typeof message !== 'string' || !message.trim() || Buffer.byteLength(message) > 4096 || message.includes('\0')) throw Error('Invalid submission intent');
   const intent = Object.freeze({...value});
   if (progress && await bounded(() => progress.begin(intent, message)) !== true) throw Error('Retained submission claim differs');
   await canonical(); await mkdir(directory, {mode: 0o700});
   let phase = 'preparation';
   try {
    const observed = await bounded(() => preparation.prepare({repositoryID, baseSHA: intent.baseSHA, sourceSHA: intent.sourceSHA}, join(directory, 'prepared')));
    if (observed.protocol !== 'repoctl-candidate-preparation-v1' || observed.state !== 'prepared-awaiting-signature' || observed.repositoryID !== repositoryID || observed.baseSHA !== intent.baseSHA || observed.sourceSHA !== intent.sourceSHA || !sha(observed.treeSHA) || !hash(observed.snapshotDigest)) throw Error('Preparation binding differs');
    const prepared = Object.freeze({treeSHA: observed.treeSHA, snapshotDigest: observed.snapshotDigest});
    if (progress && await bounded(() => progress.prepared(prepared)) !== true) throw Error('Preparation progress not retained');
    phase = 'snapshot-retention';
    const snapshot = Object.freeze({repositoryID, sourceSHA: intent.sourceSHA, snapshotDigest: prepared.snapshotDigest});
    const retained = await bounded(context => snapshots.retain(snapshot, join(directory, 'prepared/submission.pack'), context));
    if (retained.verified !== true || retained.immutable !== true || !hash(retained.receiptDigest) || Object.entries(snapshot).some(([key, expected]) => retained[key as keyof Snapshot] !== expected)) throw Error('Immutable snapshot not confirmed');
    if (progress && await bounded(() => progress.retained(retained.receiptDigest)) !== true) throw Error('Retention progress not retained');
    phase = 'signing';
    const candidate = await bounded(() => signing.finalize(join(directory, 'prepared'), join(directory, 'signed'), message));
    if (candidate.protocol !== 'repoctl-signed-candidate-v1' || candidate.state !== 'signed-awaiting-integration-generation' || candidate.repositoryID !== repositoryID || candidate.sourceSHA !== intent.sourceSHA || candidate.baseSHA !== intent.baseSHA || candidate.treeSHA !== prepared.treeSHA || candidate.snapshotDigest !== prepared.snapshotDigest || !sha(candidate.commitSHA)) throw Error('Signed candidate binding differs');
    const binding = generation({generationID: intent.generationID, baseSHA: intent.baseSHA, commitSHA: candidate.commitSHA, treeSHA: candidate.treeSHA});
    await writeFile(join(directory, 'generation.json'), JSON.stringify(binding)+'\n', {flag: 'wx', mode: 0o600});
    if (progress && await bounded(() => progress.signed(candidate.commitSHA)) !== true) throw Error('Signed candidate progress not retained');
    phase = 'publication';
    const result = await project(await bounded(context => generations.publish(binding, context)), binding);
    if (progress && await bounded(() => progress.published()) !== true) throw Error('Publication progress not retained');
    return result;
   } catch {
    let journalAcknowledged: boolean | null = null;
    if (progress) {try {journalAcknowledged = await bounded(() => progress.uncertain());} catch {journalAcknowledged = false;}}
    await writeFile(join(directory, 'failed.json'), JSON.stringify({protocol: 'repoctl-submission-failure-v1', phase, state: 'outcome-uncertain', journalAcknowledged, retry: 'reconcile-only'})+'\n', {flag: 'wx', mode: 0o600});
    throw Error('Submission failed or outcome uncertain; inspect retained job, never repeat signing or upload');
   }
  },
  async reconcile() {
   await canonical();
   if (await realpath(directory) !== directory) throw Error('Submission directory must be canonical');
   const file = await open(join(directory, 'generation.json'), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
   let binding;
   try {
    const info = await file.stat(); if (!info.isFile() || info.size > 1024) throw Error('Invalid retained submission');
    const chunks: Buffer[] = []; let size = 0; const buffer = Buffer.alloc(1025);
    for (;;) {const result = await file.read(buffer, 0, buffer.length, null); if (!result.bytesRead) break; size += result.bytesRead; if (size > 1024) throw Error('Invalid retained submission'); chunks.push(Buffer.from(buffer.subarray(0, result.bytesRead)));}
    binding = generation(JSON.parse(new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(Buffer.concat(chunks))));
   }
   finally {await file.close();}
   try {
    const result = await project(await bounded(context => generations.reconcile(binding, context)), binding);
    if (progress && await bounded(() => progress.published()) !== true) throw Error('Publication progress not retained');
    return result;
   }
   catch {throw Error('Submission reconciliation unresolved; no signing or upload attempted');}
  }
 };
}
