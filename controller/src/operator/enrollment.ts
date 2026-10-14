export interface EnrollmentRequest {
 readonly operationID: string;
 readonly approvalReference: string;
}
interface Context { readonly ownerID: number; readonly authorized: boolean; }
interface Options {
 readonly ownerID: number;
 readonly timeoutMS?: number;
 readonly authority: {authorize(input: EnrollmentRequest & {action: 'status'}): Promise<{accepted: boolean; operationID: string; approvalReference: string; session: {ownerID: number}}>};
 readonly registration: {status(input: EnrollmentRequest): Promise<{operationID: string; state: string; appID?: number}>; reconcile(input: EnrollmentRequest): Promise<{operationID: string; state: string; appID?: number}>};
}
const hash = /^[a-f0-9]{64}$/;
// Installed private capabilities only. Public ingress must supply independently
// authenticated owner context; references never establish operator identity.
export function operatorEnrollment({ownerID, authority, registration, timeoutMS = 10000}: Options) {
 if (!Number.isSafeInteger(ownerID) || ownerID < 1 || !Number.isSafeInteger(timeoutMS) || timeoutMS < 100 || timeoutMS > 10000) throw Error('Invalid operator owner');
 async function bounded<T>(job: () => Promise<T>, signal?: AbortSignal): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { signal?.throwIfAborted(); const result = await Promise.race([Promise.resolve().then(() => {signal?.throwIfAborted(); return job();}), new Promise<never>((_, reject) => {timer = setTimeout(() => reject(Error('Operator capability timeout')), timeoutMS);})]); signal?.throwIfAborted(); return result; }
  finally { clearTimeout(timer); }
 }
 function binding(value: unknown, context: Context): EnrollmentRequest {
  if (context.authorized !== true || context.ownerID !== ownerID) throw Error('Operator owner denied');
  if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype || Object.keys(value).sort().join() !== 'approvalReference,operationID') throw Error('Invalid operator enrollment');
  const {operationID, approvalReference} = value as Record<string, unknown>;
  if (typeof operationID !== 'string' || !hash.test(operationID) || typeof approvalReference !== 'string' || !hash.test(approvalReference)) throw Error('Invalid operator enrollment');
  return Object.freeze({operationID, approvalReference});
 }
 async function observe(value: unknown, context: Context, action: 'status' | 'reconcile', options: {signal?: AbortSignal} = {}) {
  const intent = binding(value, context);
  try {
   const approval = await bounded(() => authority.authorize({...intent, action: 'status'}), options.signal);
   if (approval.accepted !== true || approval.operationID !== intent.operationID || approval.approvalReference !== intent.approvalReference || approval.session?.ownerID !== ownerID) throw Error('Approval denied');
   const result = await bounded(() => registration[action](intent), options.signal);
   if (result.operationID !== intent.operationID || !['ready', 'exchanging', 'staged', 'active'].includes(result.state) || (result.appID !== undefined && (!Number.isSafeInteger(result.appID) || result.appID < 1))) throw Error('Invalid enrollment observation');
   // Explicit projection: private capability responses must never expose state
   // tokens, callback codes, App credentials or provider errors to native clients.
   return Object.freeze({protocol: 'repoctl-operator-enrollment-v1', operationID: intent.operationID, state: result.state, ...(result.appID !== undefined ? {appID: result.appID} : {})});
  } catch { throw Error('Operator enrollment denied or outcome uncertain'); }
 }
 return {status: (value: unknown, context: Context, options?: {signal?: AbortSignal}) => observe(value, context, 'status', options), reconcile: (value: unknown, context: Context, options?: {signal?: AbortSignal}) => observe(value, context, 'reconcile', options)};
}
