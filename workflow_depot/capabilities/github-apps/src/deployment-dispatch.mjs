import {appManifest} from './provisioning/manifest.mjs';
import {verifyAppPlan} from './provisioning/plan.mjs';
import {createGitHubAppProvisioner} from './framework.mjs';
import {githubEnrollmentProvider} from './enrollment/github.mjs';
import {canonical,digest} from './ledger.mjs';
export const dispatchIdentity=Object.freeze({name:'Vespoli Deployment Dispatch',owner:'susanbeasles',ownerID:215839550,repository:'susanbeasles/delivery_control',repositoryID:1405415291,callback:'https://provision.vespoli.me/github/callback'});
export const dispatchProfiles=Object.freeze({'deployment-dispatch':{permissions:{actions:'write'},events:[]}});
export async function deploymentDispatchPlan(){
 const manifest=appManifest({name:dispatchIdentity.name,role:'deployment-dispatch',homepage:'https://vespoli.me',callback:dispatchIdentity.callback,profiles:dispatchProfiles});
 return {protocol:'repoctl-app-plan-v1',owner:dispatchIdentity.owner,role:'deployment-dispatch',repositories:[dispatchIdentity.repository],manifest,manifestBytes:Buffer.from(canonical(manifest)).toString('base64'),manifestDigest:await digest(manifest),registrationState:'not_registered',installationState:'not_installed'};
}
// Trusted adapters only. Request input cannot override owner, profile or callback.
export function createDeploymentDispatchProvisioner({storage,vault,approval,fetcher,clock}){
 const service=createGitHubAppProvisioner({storage,vault,approval,provider:githubEnrollmentProvider(fetcher,undefined,{profiles:dispatchProfiles}),owner:dispatchIdentity.owner,ownerID:dispatchIdentity.ownerID,callback:dispatchIdentity.callback,profiles:dispatchProfiles,clock});
 return Object.freeze({...service,async create(input){
  const reviewed=await verifyAppPlan(input.plan,{profiles:dispatchProfiles});
  if(reviewed.repositories.length!==1||reviewed.repositories[0]!==dispatchIdentity.repository||reviewed.manifest.name!==dispatchIdentity.name||reviewed.manifest.url!=='https://vespoli.me'||reviewed.manifest.redirect_url!==dispatchIdentity.callback)throw Error('Dispatch registration scope differs from reviewed identity');
  return service.create(input);
 }});
}
// Manifest permissions do not restrict an installation's repositories. This
// separate assertion is required before any commissioning or token minting.
export function verifyDispatchInstallation(installation,repositories,appID){
 if(!Number.isSafeInteger(appID)||appID<=0||!Number.isSafeInteger(installation?.id)||installation.id<=0||installation?.app_id!==appID||installation?.account?.id!==dispatchIdentity.ownerID||installation.suspended_at||installation.repository_selection!=='selected'||JSON.stringify(Object.entries(installation.permissions??{}).sort())!==JSON.stringify(Object.entries({actions:'write',metadata:'read'}).sort())||installation.events?.length)throw Error('Dispatch installation scope rejected');
 if(repositories?.total_count!==1||repositories.repositories?.length!==1||repositories.repositories[0].id!==dispatchIdentity.repositoryID||repositories.repositories[0].full_name!==dispatchIdentity.repository)throw Error('Only delivery_control may be installed');
 return {verified:true,installationID:installation.id,appID,repositoryID:dispatchIdentity.repositoryID};
}
