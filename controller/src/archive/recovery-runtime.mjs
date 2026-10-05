import {flarekitRestore} from './flarekit-restore.mjs';
import {restoredGitReader} from './restored-git-reader.mjs';
import {recoveryHTTPPublisher} from './http-publisher.mjs';
import {recoveryJob} from './recovery-job.mjs';
// Installed capabilities are captured once; callers provide only the archive intent.
export function recoveryRuntime({flarekit,gitExecutable,signer,policyDigest,transport,clock=()=>Date.now(),lifetimeMs=240000}){
 const restore=flarekitRestore(flarekit),installedTransport={...transport};
 if(typeof gitExecutable!=='string'||!gitExecutable.startsWith('/')||typeof signer?.sign!=='function'||!(signer.trustedKeys instanceof Map)||!/^[a-f0-9]{64}$/.test(policyDigest??''))throw Error('Invalid recovery runtime');
 return {async run(intent){
  const approved=structuredClone(intent);
  const publisher=recoveryHTTPPublisher({...installedTransport,intent:approved,clock});
  return recoveryJob({restore,signer,policyDigest,clock,lifetimeMs,publisher,
   readerFor:session=>restoredGitReader({directory:session.directory,gitExecutable,repositoryID:approved.repositoryID,archiveDigest:session.archiveDigest})
  }).run(approved);
 }};
}
