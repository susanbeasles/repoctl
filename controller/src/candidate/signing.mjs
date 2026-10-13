import {open,writeFile,mkdir,realpath} from 'node:fs/promises';
import {isAbsolute,join} from 'node:path';
import {createHash} from 'node:crypto';
import {constants} from 'node:fs';
import {candidateGit} from './git-job.mjs';
import {candidatePreparation} from './preparation.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex'),sha=/^[a-f0-9]{40}$/;
async function readBounded(path,limit){
 const file=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{const info=await file.stat();if(!info.isFile()||info.size>limit)throw Error('Candidate input exceeds configured bound');
  const chunks=[];let size=0;const buffer=Buffer.alloc(Math.min(65536,limit+1));
  while(true){const {bytesRead}=await file.read(buffer,0,buffer.length,null);if(!bytesRead)break;size+=bytesRead;if(size>limit)throw Error('Candidate input exceeds configured bound');chunks.push(Buffer.from(buffer.subarray(0,bytesRead)));}
  return Buffer.concat(chunks);
 }finally{await file.close();}
}
async function boundedCapability(fn,timeout){
 const control=new AbortController();let timer;
 try{return await Promise.race([Promise.resolve().then(()=>fn(control.signal)),new Promise((_,reject)=>{timer=setTimeout(()=>{control.abort();reject(Error('Candidate capability timed out'));},timeout);})]);}
 finally{clearTimeout(timer);}
}
// Installed job capabilities only. No Worker route, provider credentials, refs,
// enrollment assertion or promotion authorization is exposed by this module.
export function candidateSigning({repositoryID,gitExecutable,sshKeygenExecutable,publicKey,authorName,authorEmail,signer,verifySnapshot,clock=()=>Date.now(),maxBytes=64*1024*1024,capabilityTimeoutMS=10000}){
 if(!Number.isSafeInteger(capabilityTimeoutMS)||capabilityTimeoutMS<100||capabilityTimeoutMS>10000||!Number.isSafeInteger(repositoryID)||repositoryID<1||!isAbsolute(gitExecutable??'')||!isAbsolute(sshKeygenExecutable??'')||typeof publicKey!=='string'||!/^([-a-zA-Z0-9@.]+) [A-Za-z0-9+/]+={0,2}$/.test(publicKey)||publicKey.length>4096||![authorName,authorEmail].every(v=>typeof v==='string'&&v.length>0&&v.length<200&&!/[\r\n<>\0]/.test(v))||/\s/.test(authorEmail)||typeof signer?.signGit!=='function'||typeof verifySnapshot!=='function'||!Number.isSafeInteger(maxBytes)||maxBytes<1||maxBytes>256*1024*1024)throw Error('Invalid candidate signing configuration');
 const git=candidateGit(gitExecutable,maxBytes);
 return {async finalize(preparationDirectory,outputDirectory,message){
  if(!isAbsolute(preparationDirectory??'')||!isAbsolute(outputDirectory??'')||typeof message!=='string'||!message.trim()||Buffer.byteLength(message)>4096||message.includes('\0'))throw Error('Invalid candidate signing job');
  const source=await realpath(preparationDirectory),parent=await realpath(join(outputDirectory,'..'));
  const output=join(parent,outputDirectory.split('/').at(-1));
  if(source!==preparationDirectory||output!==outputDirectory||output===source||output.startsWith(source+'/'))throw Error('Noncanonical signing directories');
  const bytes=await readBounded(join(source,'preparation.json'),8192);
  const p=JSON.parse(bytes);
  if(Object.keys(p).sort().join()!==['protocol','state','repositoryID','baseSHA','sourceSHA','mergeBaseSHA','treeSHA','snapshotDigest','patchDigest','signingRequired'].sort().join()||p.protocol!=='repoctl-candidate-preparation-v1'||p.state!=='prepared-awaiting-signature'||p.repositoryID!==repositoryID||p.signingRequired!==true||![p.baseSHA,p.sourceSHA,p.mergeBaseSHA,p.treeSHA].every(v=>sha.test(v??''))||![p.snapshotDigest,p.patchDigest].every(v=>/^[a-f0-9]{64}$/.test(v??'')))throw Error('Invalid prepared candidate');
  const pack=await readBounded(join(source,'submission.pack'),maxBytes);if(hash(pack)!==p.snapshotDigest)throw Error('Submitted snapshot digest changed');
  // Independently configured retention verifier must confirm the exact source
  // snapshot. A local digest, caller boolean or signer result cannot substitute.
  const binding={repositoryID,sourceSHA:p.sourceSHA,snapshotDigest:p.snapshotDigest};
  let receipt;try{receipt=await boundedCapability(signal=>verifySnapshot(binding,{signal}),capabilityTimeoutMS);}catch{throw Error('Independent snapshot verification unavailable');}
  if(receipt?.verified!==true||receipt.immutable!==true||Object.entries(binding).some(([k,v])=>receipt[k]!==v))throw Error('Independent immutable snapshot not confirmed');
  await mkdir(output,{mode:0o700});let requested=false;
  try {
   const store=join(output,'source.git');await git(store,['init','--bare','--quiet'],undefined,1024);await git(store,['index-pack','--stdin'],pack,1024);
   const builder=await candidatePreparation({sourceGitDirectory:store,gitExecutable,repositoryID,maxBytes});
   const rebuilt=await builder.prepare({repositoryID,baseSHA:p.baseSHA,sourceSHA:p.sourceSHA},join(output,'rebuilt'));
   if(rebuilt.treeSHA!==p.treeSHA||rebuilt.mergeBaseSHA!==p.mergeBaseSHA||rebuilt.patchDigest!==p.patchDigest)throw Error('Prepared tree differs from reconstructed submission');
   const commitStore=join(output,'rebuilt','objects.git');
   const stamp=Math.floor(clock()/1000);if(!Number.isSafeInteger(stamp)||stamp<0||stamp>4102444800)throw Error('Invalid candidate signing clock');
   const identity=`${authorName} <${authorEmail}> ${stamp} +0000`;
   const unsigned=Buffer.from(`tree ${p.treeSHA}\nparent ${p.baseSHA}\nauthor ${identity}\ncommitter ${identity}\n\n${message.trimEnd()}\n`);
   await writeFile(join(output,'unsigned.commit'),unsigned,{flag:'wx',mode:0o600});
   requested=true;
   const signature=await boundedCapability(signal=>signer.signGit({...binding,baseSHA:p.baseSHA,treeSHA:p.treeSHA,preparationDigest:hash(bytes),namespace:'git',bytes:Buffer.from(unsigned)},{signal}),capabilityTimeoutMS);
   if(typeof signature!=='string'||signature.length>8192||!/^-----BEGIN SSH SIGNATURE-----\n[A-Za-z0-9+/=\n]+\n-----END SSH SIGNATURE-----\n?$/.test(signature))throw Error('Invalid candidate signature');
   const text=unsigned.toString(),split=text.indexOf('\n\n');
   const signed=Buffer.from(text.slice(0,split)+'\ngpgsig '+signature.trimEnd().replaceAll('\n','\n ')+text.slice(split));
   const commitSHA=(await git(commitStore,['hash-object','-t','commit','-w','--stdin'],signed,64)).toString().trim();if(!sha.test(commitSHA))throw Error('Invalid signed candidate object');
   const allowed=join(output,'allowed-signers');await writeFile(allowed,'repoctl-candidate '+publicKey+'\n',{flag:'wx',mode:0o600});
   await git(commitStore,['-c','gpg.format=ssh','-c','gpg.ssh.program='+sshKeygenExecutable,'-c','gpg.ssh.allowedSignersFile='+allowed,'verify-commit',commitSHA],undefined,1024);
   const retained=await git(commitStore,['cat-file','commit',commitSHA],undefined,16384);if(!retained.equals(signed))throw Error('Signed candidate readback changed');
   const report={protocol:'repoctl-signed-candidate-v1',state:'signed-awaiting-integration-generation',repositoryID,sourceSHA:p.sourceSHA,baseSHA:p.baseSHA,treeSHA:p.treeSHA,commitSHA,snapshotDigest:p.snapshotDigest,preparationDigest:hash(bytes),commitDigest:hash(signed),signerFingerprint:'SHA256:'+createHash('sha256').update(Buffer.from(publicKey.split(' ')[1],'base64')).digest('base64').replace(/=+$/,'')};
   await writeFile(join(output,'candidate.json'),JSON.stringify(report)+'\n',{flag:'wx',mode:0o600});return report;
  }catch{await writeFile(join(output,'failed.json'),JSON.stringify({state:requested?'signing-or-verification-uncertain':'failed-before-signing',requiresNewJob:true})+'\n',{flag:'wx',mode:0o600});throw Error('Candidate signing failed; inspect retained job before a new attempt');}
 }};
}
