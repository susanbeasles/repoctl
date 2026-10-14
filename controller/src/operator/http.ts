interface Context {readonly ownerID: number; readonly authorized: boolean;}
interface Options {
 readonly enabled?: boolean;
 readonly ownerID: number;
 readonly timeoutMS?: number;
 readonly identity: {verify(request: Request, options: {signal: AbortSignal}): Promise<Context>};
 readonly enrollment: {status(input: unknown, context: Context, options: {signal: AbortSignal}): Promise<unknown>; reconcile(input: unknown, context: Context, options: {signal: AbortSignal}): Promise<unknown>};
}
const headers = {'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer'};
const hash = /^[a-f0-9]{64}$/;
// Installed owner identity verifier is responsible for signature, issuer,
// audience, expiry and revocation. HTTP headers are never trusted as identity.
export function operatorHTTP({enabled = false, ownerID, identity, enrollment, timeoutMS = 10000}: Options) {
 if (!Number.isSafeInteger(ownerID) || ownerID < 1 || !Number.isSafeInteger(timeoutMS) || timeoutMS < 100 || timeoutMS > 10000) throw Error('Invalid operator ingress');
 return {async fetch(request: Request): Promise<Response> {
  const deny = (error: string, status: number) => Response.json({error}, {status, headers});
  if (!enabled) return deny('operator_not_configured', 503);
  const url = new URL(request.url);
  if (url.search || !['/v1/operator/enrollment/status', '/v1/operator/enrollment/reconcile'].includes(url.pathname)) return deny('not_found', 404);
  if (request.method !== 'POST') return deny('method_not_allowed', 405);
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  try {
   const job = async () => {
    const verified = await identity.verify(request, {signal: controller.signal});
    controller.signal.throwIfAborted();
    if (verified.authorized !== true || verified.ownerID !== ownerID) throw Error('Owner denied');
    const context = Object.freeze({ownerID, authorized: true});
    if (request.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase() !== 'application/json') throw Error('Invalid media type');
    reader = request.body?.getReader(); if (!reader) throw Error('Missing body');
    const chunks: Uint8Array[] = []; let size = 0;
    for (;;) { const result = await reader.read(); controller.signal.throwIfAborted(); if (result.done) break; size += result.value.length; if (size > 1024) throw Error('Oversized body'); chunks.push(result.value); }
    const bytes = new Uint8Array(size); let offset = 0; for (const chunk of chunks) {bytes.set(chunk, offset); offset += chunk.length;}
    const input = JSON.parse(new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(bytes));
    if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).sort().join() !== 'approvalReference,operationID' || ![input.operationID, input.approvalReference].every(v => typeof v === 'string' && hash.test(v))) throw Error('Invalid input');
    const action = url.pathname.endsWith('/status') ? 'status' : 'reconcile';
    const result = await enrollment[action](Object.freeze({...input}), context, {signal: controller.signal}) as Record<string, unknown>;
    controller.signal.throwIfAborted();
    if (!result || result.protocol !== 'repoctl-operator-enrollment-v1' || result.operationID !== input.operationID || !['ready', 'exchanging', 'staged', 'active'].includes(result.state as string) || (result.appID !== undefined && (typeof result.appID !== 'number' || !Number.isSafeInteger(result.appID) || result.appID < 1))) throw Error('Invalid observation');
    return Response.json({protocol: result.protocol, operationID: result.operationID, state: result.state, ...(result.appID !== undefined ? {appID: result.appID} : {})}, {headers});
   };
   return await Promise.race([job(), new Promise<never>((_, reject) => {timer = setTimeout(() => {controller.abort(); reject(Error('Operator request timeout'));}, timeoutMS);})]);
  } catch {return deny('operator_denied_or_reconciliation_required', 403);}
  finally {clearTimeout(timer); controller.abort(); if (reader) void reader.cancel().catch(() => {});}
 }};
}
