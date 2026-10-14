import type {operatorSubmission} from './submission.ts';
interface Context {readonly ownerID: number; readonly authorized: boolean;}
interface Options {readonly enabled?: boolean; readonly ownerID: number; readonly timeoutMS?: number; readonly identity: {verify(request: Request, context: {signal: AbortSignal}): Promise<Context>}; readonly submission: ReturnType<typeof operatorSubmission>;}
const headers = {'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer'};
const routes = new Map<string, 'create' | 'status' | 'reconcile'>([['/v1/operator/submission/create', 'create'], ['/v1/operator/submission/status', 'status'], ['/v1/operator/submission/reconcile', 'reconcile']]);
// Independent Access verification precedes body parsing or any job grant.
export function submissionHTTP({enabled = false, ownerID, identity, submission, timeoutMS = 10000}: Options) {
 if (!Number.isSafeInteger(ownerID) || ownerID < 1 || !Number.isSafeInteger(timeoutMS) || timeoutMS < 100 || timeoutMS > 10000) throw Error('Invalid submission ingress');
 return {async fetch(request: Request): Promise<Response> {
  const deny = (error: string, status: number) => Response.json({error}, {status, headers});
  if (!enabled) return deny('submission_not_configured', 503);
  const url = new URL(request.url), action = routes.get(url.pathname);
  if (url.search || !action) return deny('not_found', 404);
  if (request.method !== 'POST') return deny('method_not_allowed', 405);
  const controller = new AbortController(); let timer: ReturnType<typeof setTimeout> | undefined, reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  const abort = () => {controller.abort(); if (reader) void reader.cancel().catch(() => {});};
  request.signal.addEventListener('abort', abort, {once: true}); if (request.signal.aborted) abort();
  try {
   const job = async () => {
    controller.signal.throwIfAborted();
    const owner = await identity.verify(request, {signal: controller.signal}); controller.signal.throwIfAborted();
    if (owner.authorized !== true || owner.ownerID !== ownerID) throw Error('Owner denied');
    if (request.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase() !== 'application/json') throw Error('Invalid media type');
    reader = request.body?.getReader(); if (!reader) throw Error('Missing input');
    const chunks: Uint8Array[] = []; let size = 0;
    for (;;) {const next = await reader.read(); controller.signal.throwIfAborted(); if (next.done) break; size += next.value.length; if (size > 32768) throw Error('Oversized input'); chunks.push(next.value);}
    const bytes = new Uint8Array(size); let offset = 0; for (const chunk of chunks) {bytes.set(chunk, offset); offset += chunk.length;}
    const input = JSON.parse(new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(bytes));
    const result = await submission[action](input, Object.freeze({ownerID, authorized: true}), {signal: controller.signal});
    controller.signal.throwIfAborted();
    // Submission service owns the explicit bound public projection.
    return Response.json(result, {headers});
   };
   return await Promise.race([job(), new Promise<never>((_, reject) => {timer = setTimeout(() => {abort(); reject(Error('Timeout'));}, timeoutMS);})]);
  } catch {return deny('submission_denied_or_reconciliation_required', 403);}
  finally {clearTimeout(timer); request.signal.removeEventListener('abort', abort); abort();}
 }};
}
