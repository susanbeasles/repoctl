import {mkdtemp,writeFile,rm,realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';import {isAbsolute,join} from 'node:path';
import {candidateGit} from './git-job.mjs';
const sha=/^[a-f0-9]{40}$/;
// Installed isolated job adapter. Reads signed objects; never signs or creates refs.
// The configured public key is the designated identity, not hardware proof.
export async function signedCandidateVerifier({repositoryID,objectDirectory,gitExecutable,sshKeygenExecutable,publicKey}){
 if(!Number.isSafeInteger(repositoryID)||repositoryID<1||![objectDirectory,gitExecutable,sshKeygenExecutable].every(v=>isAbsolute(v??''))||typeof publicKey!=='string'||publicKey.length>4096||!/^([-a-zA-Z0-9@.]+) [A-Za-z0-9+/]+={0,2}$/.test(publicKey))throw Error('Invalid designated candidate verifier configuration');
 if(await realpath(objectDirectory)!==objectDirectory)throw Error('Candidate object store must be canonical');
 const git=candidateGit(gitExecutable,16384);
 return {async verify(binding,{signal}={}){
  if(!binding||Object.getPrototypeOf(binding)!==Object.prototype||Object.keys(binding).sort().join()!==['repositoryID','baseSHA','commitSHA','treeSHA'].sort().join()||binding.repositoryID!==repositoryID||![binding.baseSHA,binding.commitSHA,binding.treeSHA].every(v=>sha.test(v??'')))throw Error('Invalid designated candidate binding');
  signal?.throwIfAborted();
  const raw=await git(objectDirectory,['cat-file','commit',binding.commitSHA],undefined,16384);
  const text=new TextDecoder('utf-8',{fatal:true}).decode(raw),split=text.indexOf('\n\n');if(split<0)throw Error('Invalid signed candidate header');
  const header=text.slice(0,split),lines=header.split('\n').filter(v=>!v.startsWith(' '));
  if(lines.filter(v=>v.startsWith('tree ')).join()!=='tree '+binding.treeSHA||lines.filter(v=>v.startsWith('parent ')).join()!=='parent '+binding.baseSHA||lines.filter(v=>v.startsWith('gpgsig ')).join()!=='gpgsig -----BEGIN SSH SIGNATURE-----'||lines.some(v=>v.startsWith('gpgsig-sha256 ')))throw Error('Designated candidate tree/parent/SSH signature rejected');
  const task=await mkdtemp(join(tmpdir(),'repoctl-candidate-verify-'));
  try{
   const allowed=join(task,'allowed-signers');await writeFile(allowed,'repoctl-candidate '+publicKey+'\n',{flag:'wx',mode:0o600});
   signal?.throwIfAborted();
   await git(objectDirectory,['-c','gpg.ssh.program='+sshKeygenExecutable,'-c','gpg.ssh.allowedSignersFile='+allowed,'verify-commit',binding.commitSHA],undefined,1024);
   signal?.throwIfAborted();
   const retained=await git(objectDirectory,['cat-file','commit',binding.commitSHA],undefined,16384);if(!retained.equals(raw))throw Error('Candidate object changed during verification');
   signal?.throwIfAborted();return {...binding,verified:true};
  }finally{await rm(task,{recursive:true,force:true});}
 }};
}
