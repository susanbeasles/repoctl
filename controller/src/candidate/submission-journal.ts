interface Transaction {get<T>(key: string): Promise<T | undefined>; put<T>(key: string, value: T): Promise<void>;}
interface Storage extends Transaction {transaction<T>(callback: (transaction: Transaction) => Promise<T>): Promise<T>;}
interface Intent {ownerID: number; repositoryID: number; generationID: string; baseSHA: string; sourceSHA: string; message: string;}
type State = 'queued' | 'preparing' | 'retaining' | 'signing' | 'publishing' | 'published-awaiting-validation' | 'uncertain' | 'failed';
interface Record extends Intent {state: State; started: boolean; treeSHA: string | null; snapshotDigest: string | null; retentionDigest: string | null; commitSHA: string | null;}
const states: State[] = ['queued', 'preparing', 'retaining', 'signing', 'publishing', 'published-awaiting-validation', 'uncertain', 'failed'];
const sha = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{40}$/.test(value) && !/^0+$/.test(value);
const hash = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const intentFields = 'baseSHA,generationID,message,ownerID,repositoryID,sourceSHA';
// Private storage capability only. Transactions contain no provider I/O, signer
// calls or project execution. Every generation remains a permanent tombstone.
export function submissionJournal(storage: Storage, ownerID: number, repositoryID: number) {
 if (![ownerID, repositoryID].every(value => Number.isSafeInteger(value) && value > 0) || !['get', 'put', 'transaction'].every(method => typeof storage?.[method as keyof Storage] === 'function')) throw Error('Invalid submission journal configuration');
 const key = (id: string) => {if (!hash(id)) throw Error('Invalid submission reference'); return `submission:v1:${ownerID}:${repositoryID}:${id}`;};
 function intent(value: unknown): Intent {
  if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype || Object.keys(value).sort().join() !== intentFields) throw Error('Invalid submission binding');
  const input = value as Intent;
  if (input.ownerID !== ownerID || input.repositoryID !== repositoryID || !hash(input.generationID) || !sha(input.baseSHA) || !sha(input.sourceSHA) || typeof input.message !== 'string' || !input.message.trim() || new TextEncoder().encode(input.message).length > 4096 || input.message.includes('\0')) throw Error('Invalid submission binding');
  return {...input};
 }
 function record(value: unknown, id: string): Record | null {
  if (value === undefined) return null;
  if (!value || typeof value !== 'object' || Object.keys(value).sort().join() !== 'baseSHA,commitSHA,generationID,message,ownerID,repositoryID,retentionDigest,snapshotDigest,sourceSHA,started,state,treeSHA') throw Error('Corrupt submission record');
  const {state, started, treeSHA, snapshotDigest, retentionDigest, commitSHA, ...binding} = value as Record;
  intent(binding);
  if (binding.generationID !== id || !states.includes(state) || (treeSHA !== null && !sha(treeSHA)) || (snapshotDigest !== null && !hash(snapshotDigest)) || (retentionDigest !== null && !hash(retentionDigest)) || (commitSHA !== null && !sha(commitSHA)) || ((treeSHA === null) !== (snapshotDigest === null)) || (retentionDigest !== null && treeSHA === null) || (commitSHA !== null && retentionDigest === null)) throw Error('Corrupt submission record');
  if (['queued', 'preparing'].includes(state) && treeSHA !== null) throw Error('Corrupt submission record');
  if (typeof started !== 'boolean' || (state === 'queued' && started) || (['retaining', 'signing', 'publishing', 'published-awaiting-validation'].includes(state) && !started)) throw Error('Corrupt submission record');
  if (state === 'retaining' && retentionDigest !== null) throw Error('Corrupt submission record');
  if (state === 'signing' && commitSHA !== null) throw Error('Corrupt submission record');
  if (state === 'failed' && retentionDigest !== null) throw Error('Corrupt submission record');
  if (['retaining', 'signing', 'publishing', 'published-awaiting-validation'].includes(state) && treeSHA === null) throw Error('Corrupt submission record');
  if (['signing', 'publishing', 'published-awaiting-validation'].includes(state) && retentionDigest === null) throw Error('Corrupt submission record');
  if (['publishing', 'published-awaiting-validation'].includes(state) && commitSHA === null) throw Error('Corrupt submission record');
  return {...binding, state, started, treeSHA, snapshotDigest, retentionDigest, commitSHA};
 }
 return {
  async create(value: unknown) {
   const binding = intent(value), id = binding.generationID;
   return storage.transaction(async transaction => {
    const name = key(id), previous = record(await transaction.get(name), id);
    if (previous) {if (Object.entries(binding).some(([field, expected]) => previous[field as keyof Intent] !== expected)) throw Error('Submission generation collision'); return {created: false, record: previous};}
    const retained: Record = {...binding, state: 'queued', started: false, treeSHA: null, snapshotDigest: null, retentionDigest: null, commitSHA: null};
    await transaction.put(name, retained); return {created: true, record: retained};
   });
  },
  async read(id: string) {return record(await storage.get(key(id)), id);},
  async claim(id: string) {
   const name = key(id);
   return storage.transaction(async transaction => {
    const previous = record(await transaction.get(name), id);
    if (!previous || previous.state !== 'preparing' || previous.started) return null;
    const claimed = {...previous, started: true};
    await transaction.put(name, claimed); return claimed;
   });
  },
  async transition(id: string, from: State, to: State, fields: {treeSHA?: string; snapshotDigest?: string; retentionDigest?: string; commitSHA?: string} = {}) {
   key(id);
   let expected: string | undefined;
   if (from === 'queued' && to === 'preparing') expected = '';
   if (from === 'preparing' && to === 'retaining') expected = 'snapshotDigest,treeSHA';
   if (from === 'retaining' && to === 'signing') expected = 'retentionDigest';
   if (from === 'signing' && to === 'publishing') expected = 'commitSHA';
   if (from === 'publishing' && to === 'published-awaiting-validation') expected = '';
   if (from === 'uncertain' && to === 'published-awaiting-validation') expected = '';
   if (['queued', 'preparing', 'retaining', 'signing', 'publishing'].includes(from) && to === 'uncertain') expected = '';
   if (['queued', 'preparing', 'retaining'].includes(from) && to === 'failed') expected = '';
   if (expected === undefined || !fields || Object.getPrototypeOf(fields) !== Object.prototype || Object.keys(fields).sort().join() !== expected) throw Error('Invalid submission transition');
   const extra = {...fields};
   return storage.transaction(async transaction => {
    const name = key(id), previous = record(await transaction.get(name), id);
    if (!previous || previous.state !== from) return false;
    const next = record({...previous, ...extra, state: to}, id)!;
    await transaction.put(name, next); return true;
   });
  }
 };
}
