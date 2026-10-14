import {registrationSessions} from './provisioning/registration.mjs';
import {enrollmentJournal} from './enrollment/journal.mjs';
import {verifyAppPlan} from './provisioning/plan.mjs';
import {defaultProfiles,profileFor} from './profiles.mjs';
const need=v=>{if(!v)throw Error('GitHub App provisioning denied');};
const fields=(value,names)=>value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).sort().join()===names.slice().sort().join();
// Library composition only: no Worker host, credential store or authority is
// created here. Approved adapters are installed by the owning private runtime.
export function createGitHubAppProvisioner({storage,vault,provider,approval,owner,ownerID,callback,profiles=defaultProfiles,clock=()=>Date.now()}) {
 need(storage?.get&&storage?.transaction&&vault?.stage&&vault?.activate&&provider?.exchangeManifestCode&&provider?.verifyApp&&approval?.authorize);
 need(typeof owner==='string'&&/^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/.test(owner)&&Number.isSafeInteger(ownerID)&&ownerID>0);
 const accepted=structuredClone(profiles);for(const role of Object.keys(accepted))profileFor(role,accepted);
 const custody=enrollmentJournal(storage,vault,provider,clock,{profiles:accepted});
 async function authorize(operationID,approvalReference,action,reviewed) {
  const a=await approval.authorize({operationID,approvalReference,action});
  need(a?.accepted===true&&a.operationID===operationID&&a.approvalReference===approvalReference&&a.session?.ownerID===ownerID);
  const record=reviewed??await storage.get(`registration:${operationID}`);
  need(record&&record.manifestDigest===a.session.manifestDigest&&record.owner===owner&&record.role===a.session.role);
  profileFor(a.session.role,accepted);return a.session;
 }
 const registration=registrationSessions(storage,{
  create:async({operationID,approvalReference,reviewed})=>custody.create(operationID,await authorize(operationID,approvalReference,'create',reviewed)),
  exchange:async({operationID,approvalReference,code})=>{await authorize(operationID,approvalReference,'exchange');return custody.exchange(operationID,code);}
 },callback,clock,{profiles:accepted});
 return Object.freeze({
  async create(input){need(fields(input,['operationID','approvalReference','plan','expiresAt']));const reviewed=await verifyAppPlan(input.plan,{profiles:accepted});need(reviewed.owner===owner);return registration.create(input.operationID,input.plan,input.approvalReference,input.expiresAt);},
  async launch(input){need(fields(input,['state']));return registration.launch(await registration.resolve(input.state),input.state);},
  async complete(input){need(fields(input,['state','code']));return registration.complete(await registration.resolve(input.state),input.state,input.code);},
  async status(input){need(fields(input,['operationID','approvalReference']));await authorize(input.operationID,input.approvalReference,'status');return custody.status(input.operationID);},
  async reconcile(input){need(fields(input,['operationID','approvalReference']));await authorize(input.operationID,input.approvalReference,'reconcile');return custody.reconcile(input.operationID);}
 });
}
