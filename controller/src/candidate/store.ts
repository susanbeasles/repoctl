import {realpath,lstat} from 'node:fs/promises';
import {join,isAbsolute} from 'node:path';
import {candidateGit} from './git-job.mjs';
import type {Generation} from './upload.ts';
interface Context {signal: AbortSignal}
interface Candidate {repositoryID: number; baseSHA: string; commitSHA: string; treeSHA: string}
interface Proof extends Candidate {verified: boolean}
interface Configuration {
 repositoryID: number;
 objectDirectory: string;
 gitExecutable: string;
 verifyCandidate(candidate: Readonly<Candidate>,context: Context): Promise<Proof>;
 maxBytes?: number;
}
// Fixed isolated signed-object store. This capability cannot accept caller paths,
// sign objects, inspect credentials, execute project files or create refs.
export async function candidateStore({repositoryID,objectDirectory,gitExecutable,verifyCandidate,maxBytes=64*1024*1024}: Configuration) {
 if(!Number.isSafeInteger(repositoryID)||repositoryID<1||![objectDirectory,gitExecutable].every(v=>typeof v==='string'&&isAbsolute(v))||typeof verifyCandidate!=='function'||!Number.isSafeInteger(maxBytes)||maxBytes<32||maxBytes>256*1024*1024)throw Error('Invalid candidate store configuration');
 async function independent() {
  for(const part of ['', 'objects','objects/info']){const path=join(objectDirectory,part);if(await realpath(path)!==path||!(await lstat(path)).isDirectory())throw Error('Candidate store must be canonical and independent');}
  for(const part of ['objects/info/alternates','objects/info/http-alternates','shallow','commondir','info/grafts']){
   try{await lstat(join(objectDirectory,part));}catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')continue;throw error;}
   throw Error('Candidate store must be complete and independent');
  }
 }
 await independent();
 const git=candidateGit(gitExecutable,maxBytes);
 return {async pack(value: Generation,context: Context): Promise<Uint8Array> {
  if(!value||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).sort().join()!=='baseSHA,commitSHA,generationID,ref,repositoryID,treeSHA')throw Error('Invalid candidate store binding');
  const candidate=Object.freeze({...value});
  if(candidate.repositoryID!==repositoryID||typeof candidate.generationID!=='string'||!/^[a-f0-9]{64}$/.test(candidate.generationID)||candidate.ref!=='refs/heads/int/'+candidate.generationID||![candidate.baseSHA,candidate.commitSHA,candidate.treeSHA].every(v=>typeof v==='string'&&/^[a-f0-9]{40}$/.test(v)&&!/^0+$/.test(v)))throw Error('Invalid candidate store binding');
  const binding=Object.freeze({repositoryID,baseSHA:candidate.baseSHA,commitSHA:candidate.commitSHA,treeSHA:candidate.treeSHA});
  async function verify() {
   context.signal.throwIfAborted();
   const proof=await verifyCandidate(binding,context);
   context.signal.throwIfAborted();
   if(proof?.verified!==true||Object.entries(binding).some(([key,v])=>proof[key as keyof Candidate]!==v))throw Error('Designated candidate store proof rejected');
  }
  try {
   context.signal.throwIfAborted();await independent();await verify();
   const format=await git(objectDirectory,['rev-parse','--show-object-format'],undefined,32);
   if(new TextDecoder().decode(format).trim()!=='sha1')throw Error('Unsupported candidate store object format');
   context.signal.throwIfAborted();
   const bytes=await git(objectDirectory,['pack-objects','--revs','--stdout','--threads=1'],new TextEncoder().encode(candidate.commitSHA+'\n'));
   if(!(bytes instanceof Uint8Array)||bytes.length>maxBytes)throw Error('Invalid candidate object pack');
   await independent();await verify();
   return new Uint8Array(bytes);
  }catch{throw Error('Candidate store packing denied or unavailable');}
 }};
}
