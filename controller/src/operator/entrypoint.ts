import {WorkerEntrypoint} from 'cloudflare:workers';
import {operatorEnrollment} from './enrollment.ts';
import {operatorHTTP} from './http.ts';
import {accessIdentity} from './identity.ts';
import {boundJSON} from '../runtime/services.mjs';
import {operatorSubmission} from './submission.ts';
import {submissionHTTP} from './submission-http.ts';
interface Bindings {
 OPERATOR_ENABLED?: string; OPERATOR_OWNER_ID?: string;
 OPERATOR_IDENTITY_CONFIG_JSON?: string; OPERATOR_SESSIONS: Fetcher; OPERATOR_APPROVAL: Fetcher; OPERATOR_REGISTRATION: Fetcher;
 OPERATOR_SUBMISSION_ENABLED?: string; OPERATOR_JOB_GRANTS?: Fetcher; OPERATOR_JOBS?: Fetcher;
}
const headers = {'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'};
function identity(env: Bindings, ownerID: number) {
 if (typeof env.OPERATOR_IDENTITY_CONFIG_JSON !== 'string') throw Error('Missing identity configuration');
 const config = JSON.parse(env.OPERATOR_IDENTITY_CONFIG_JSON);
 if (!config || typeof config !== 'object' || Object.keys(config).sort().join() !== 'audience,issuer,lifetime,subject') throw Error('Invalid identity configuration');
 const access = accessIdentity({...config, ownerID, sessions: {verify: (binding, context) => boundJSON(env.OPERATOR_SESSIONS, '/v1/operator/session', binding, context)}});
 return {verify: (source: Request, {signal}: {signal: AbortSignal}) => access.verify(source.headers.get('Cf-Access-Jwt-Assertion'), {signal})};
}
// Private named service only. Public fetch never exposes operator or custody RPC.
export class OperatorService extends WorkerEntrypoint<Bindings> {
 async fetch(request: Request): Promise<Response> {
  if (this.env.OPERATOR_ENABLED !== 'true' || !/^[1-9][0-9]*$/.test(this.env.OPERATOR_OWNER_ID ?? '') || !(['OPERATOR_SESSIONS', 'OPERATOR_APPROVAL', 'OPERATOR_REGISTRATION'] as const).every(k => typeof this.env[k]?.fetch === 'function')) return Response.json({error: 'operator_not_configured'}, {status: 503, headers});
  const ownerID = Number(this.env.OPERATOR_OWNER_ID);
  if (!Number.isSafeInteger(ownerID) || typeof this.env.OPERATOR_IDENTITY_CONFIG_JSON !== 'string') return Response.json({error: 'operator_not_configured'}, {status: 503, headers});
  const enrollment = operatorEnrollment({ownerID, authority: {authorize: input => boundJSON(this.env.OPERATOR_APPROVAL, '/v1/enrollment/authorize', input)}, registration: {
   status: input => boundJSON(this.env.OPERATOR_REGISTRATION, '/v1/registration/status', input),
   reconcile: input => boundJSON(this.env.OPERATOR_REGISTRATION, '/v1/registration/reconcile', input)
  }});
  let owner;
  try {owner = identity(this.env, ownerID);} catch {return Response.json({error: 'operator_not_configured'}, {status: 503, headers});}
  return operatorHTTP({enabled: true, ownerID, identity: owner, enrollment}).fetch(request);
 }
}
export class SubmissionOperatorService extends WorkerEntrypoint<Bindings> {
 async fetch(request: Request): Promise<Response> {
  if (this.env.OPERATOR_SUBMISSION_ENABLED !== 'true' || !/^[1-9][0-9]*$/.test(this.env.OPERATOR_OWNER_ID ?? '') || !(['OPERATOR_SESSIONS', 'OPERATOR_JOB_GRANTS', 'OPERATOR_JOBS'] as const).every(key => typeof this.env[key]?.fetch === 'function')) return Response.json({error: 'submission_not_configured'}, {status: 503, headers});
  const ownerID = Number(this.env.OPERATOR_OWNER_ID); if (!Number.isSafeInteger(ownerID)) return Response.json({error: 'submission_not_configured'}, {status: 503, headers});
  let owner;
  try {owner = identity(this.env, ownerID);} catch {return Response.json({error: 'submission_not_configured'}, {status: 503, headers});}
  const jobs = this.env.OPERATOR_JOBS!;
  const submission = operatorSubmission({ownerID, authority: {authorize: (input, context) => boundJSON(this.env.OPERATOR_JOB_GRANTS, '/v1/submission/authorize', input, context)}, jobs: {
   create: (input, context) => boundJSON(jobs, '/v1/submission/create', input, context),
   status: (input, context) => boundJSON(jobs, '/v1/submission/status', input, context),
   reconcile: (input, context) => boundJSON(jobs, '/v1/submission/reconcile', input, context)
  }});
  return submissionHTTP({enabled: true, ownerID, identity: owner, submission}).fetch(request);
 }
}
export default {fetch(): Response {return new Response('Not found', {status: 404, headers});}};
