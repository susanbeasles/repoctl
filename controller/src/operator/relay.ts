interface Service {fetch(request: Request): Promise<Response>;}
interface Options {readonly enabled?: boolean; readonly service?: Service; readonly timeoutMS?: number;}
const headers = {'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer'};
const routes = ['/v1/operator/enrollment/status', '/v1/operator/enrollment/reconcile'];
async function bytes(body: ReadableStream<Uint8Array> | null, limit: number, signal: AbortSignal): Promise<Uint8Array> {
 if (!body) throw Error('Missing body');
 const reader = body.getReader();
 const cancel = () => {void reader.cancel().catch(() => {});};
 signal.addEventListener('abort', cancel, {once: true});
 try {
  signal.throwIfAborted();
  const chunks: Uint8Array[] = []; let size = 0;
  for (;;) {const next = await reader.read(); signal.throwIfAborted(); if (next.done) break; size += next.value.length; if (size > limit) throw Error('Oversized body'); chunks.push(next.value);}
  const result = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) {result.set(chunk, offset); offset += chunk.length;}
  return result;
 } finally {signal.removeEventListener('abort', cancel); await reader.cancel().catch(() => {}); reader.releaseLock();}
}
// No credentials, identity mapping or recovery authority are owned by ingress.
// The private OperatorService independently verifies Access and retained approval.
export function operatorRelay({enabled = false, service, timeoutMS = 10000}: Options) {
 if (!Number.isSafeInteger(timeoutMS) || timeoutMS < 100 || timeoutMS > 10000) throw Error('Invalid relay deadline');
 return {async fetch(request: Request): Promise<Response> {
  const deny = (error: string, status: number) => Response.json({error}, {status, headers});
  const url = new URL(request.url);
  if (url.search || !routes.includes(url.pathname)) return deny('not_found', 404);
  if (request.method !== 'POST') return deny('method_not_allowed', 405);
  if (!enabled || typeof service?.fetch !== 'function') return deny('operator_not_configured', 503);
  const controller = new AbortController(); let timer: ReturnType<typeof setTimeout> | undefined;
  const abort = () => controller.abort(); request.signal.addEventListener('abort', abort, {once: true});
  if (request.signal.aborted) controller.abort();
  try {
   const job = async () => {
    controller.signal.throwIfAborted();
    const assertion = request.headers.get('Cf-Access-Jwt-Assertion');
    if (!assertion || assertion.length > 16000 || !/^[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+[.][A-Za-z0-9_-]+$/.test(assertion)) throw Error('Missing assertion');
    if (request.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase() !== 'application/json') throw Error('Invalid media type');
    const body = await bytes(request.body, 1024, controller.signal);
    const input = JSON.parse(new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(body));
    if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).sort().join() !== 'approvalReference,operationID' || ![input.operationID, input.approvalReference].every(value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value))) throw Error('Invalid binding');
    controller.signal.throwIfAborted();
    const response = await service!.fetch(new Request('https://operator.internal' + url.pathname, {method: 'POST', headers: {'Content-Type': 'application/json', 'Cf-Access-Jwt-Assertion': assertion}, body: JSON.stringify(input), signal: controller.signal}));
    controller.signal.throwIfAborted();
    if (response.status !== 200) {await response.body?.cancel(); throw Error('Denied or uncertain');}
    const result = JSON.parse(new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(await bytes(response.body, 65536, controller.signal)));
    if (!result || result.protocol !== 'repoctl-operator-enrollment-v1' || result.operationID !== input.operationID || !['ready', 'exchanging', 'staged', 'active'].includes(result.state) || (result.appID !== undefined && (!Number.isSafeInteger(result.appID) || result.appID < 1))) throw Error('Invalid observation');
    return Response.json({protocol: result.protocol, operationID: result.operationID, state: result.state, ...(result.appID !== undefined ? {appID: result.appID} : {})}, {headers});
   };
   return await Promise.race([job(), new Promise<never>((_, reject) => {timer = setTimeout(() => {controller.abort(); reject(Error('Timeout'));}, timeoutMS);})]);
  } catch {return deny('operator_denied_or_reconciliation_required', 403);}
  finally {clearTimeout(timer); request.signal.removeEventListener('abort', abort); controller.abort();}
 }};
}
