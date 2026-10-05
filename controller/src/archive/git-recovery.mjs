import {digest} from '../ledger.mjs';
const sha=/^[a-f0-9]{40}$/,hash=/^[a-f0-9]{64}$/;
const hex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
const text=bytes=>new TextDecoder('utf-8',{fatal:true}).decode(bytes);
// Reader supplies fully decoded Git objects from the approved archive set. It is
// installed recovery/decryption code, never request-supplied URLs or callbacks.
export function gitRecoveryVerifier({reader,maxObjects=10000,maxBytes=64*1024*1024}){
 if(typeof reader?.object!=='function'||!Number.isSafeInteger(maxObjects)||maxObjects<1||!Number.isSafeInteger(maxBytes)||maxBytes<1)throw Error('Invalid recovery configuration');
 return {async verify(intent){
  if(!intent||Object.keys(intent).sort().join()!==['repositoryID','commitSHA','sourceSHA','treeSHA','archiveDigests'].sort().join()||!Number.isSafeInteger(intent.repositoryID)||intent.repositoryID<=0||![intent.commitSHA,intent.sourceSHA,intent.treeSHA].every(v=>sha.test(v??''))||!Array.isArray(intent.archiveDigests)||!intent.archiveDigests.length||intent.archiveDigests.length>100||new Set(intent.archiveDigests).size!==intent.archiveDigests.length||!intent.archiveDigests.every(v=>hash.test(v??'')))throw Error('Invalid archive recovery intent');
  const objects=new Map(),queue=[],scheduled=new Map(),gitlinks=[];let total=0,candidateTree;
  function enqueue(id,type){if(scheduled.has(id)){if(scheduled.get(id)!==type)throw Error('Scheduled Git type conflict');return;}if(scheduled.size>=maxObjects)throw Error('Recovery object limit exceeded');scheduled.set(id,type);queue.push({id,type});}
  enqueue(intent.commitSHA,'commit');enqueue(intent.sourceSHA,'commit');
  while(queue.length){
   const {id,type}=queue.shift();if(objects.has(id)){if(objects.get(id).type!==type)throw Error('Git object type conflict');continue;}
   if(objects.size>=maxObjects)throw Error('Recovery object limit exceeded');
   const value=await reader.object({repositoryID:intent.repositoryID,objectID:id,archiveDigests:intent.archiveDigests});
   if(!value||Object.keys(value).sort().join()!==['archiveDigest','bytes'].sort().join()||!intent.archiveDigests.includes(value.archiveDigest)||!(value.bytes instanceof Uint8Array))throw Error('Archive reader returned foreign object');
   const bytes=value.bytes;total+=bytes.length;if(total>maxBytes)throw Error('Recovery byte limit exceeded');
   if(hex(new Uint8Array(await crypto.subtle.digest('SHA-1',bytes)))!==id)throw Error('Recovered Git object hash differs');
   const split=bytes.indexOf(0);if(split<1||split>80)throw Error('Invalid Git object header');const header=text(bytes.slice(0,split)),match=/^(commit|tree|blob) (0|[1-9][0-9]*)$/.exec(header);
   if(!match||match[1]!==type||Number(match[2])!==bytes.length-split-1)throw Error('Invalid Git object type or size');const body=bytes.slice(split+1);
   objects.set(id,{objectID:id,type,archiveDigest:value.archiveDigest,bytes:bytes.length,contentDigest:hex(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)))});
   if(type==='commit'){
    const end=body.indexOf(10);if(end<0)throw Error('Malformed commit');const first=text(body.slice(0,end));if(!/^tree [a-f0-9]{40}$/.test(first))throw Error('Missing commit tree');const tree=first.slice(5);enqueue(tree,'tree');if(id===intent.commitSHA)candidateTree=tree;
    const raw=text(body);const divider=raw.indexOf('\n\n');if(divider<0)throw Error('Malformed commit headers');
    for(const line of raw.slice(0,divider).split('\n').slice(1)){if(line.startsWith('parent ')){const parent=line.slice(7);if(!sha.test(parent))throw Error('Invalid parent');enqueue(parent,'commit');}}
   }else if(type==='tree'){
    let offset=0;const names=new Set();while(offset<body.length){
     const space=body.indexOf(32,offset),nul=body.indexOf(0,space+1);if(space<offset||nul<space||nul+21>body.length)throw Error('Malformed tree entry');
     const mode=text(body.slice(offset,space)),name=hex(body.slice(space+1,nul));if(!name||names.has(name)||body.slice(space+1,nul).includes(47))throw Error('Invalid or duplicate tree name');names.add(name);
     const child=hex(body.slice(nul+1,nul+21));offset=nul+21;
     if(mode==='40000')enqueue(child,'tree');else if(['100644','100755','120000'].includes(mode))enqueue(child,'blob');else if(mode==='160000')gitlinks.push(child);else throw Error('Unsupported tree mode');
    }
   }
  }
  if(candidateTree!==intent.treeSHA)throw Error('Recovered candidate tree differs');
  const report={protocol:'repoctl-archive-evidence-v1',intent,objects:[...objects.values()].sort((a,b)=>a.objectID.localeCompare(b.objectID)),recovery:{candidate:intent.commitSHA,source:intent.sourceSHA,tree:intent.treeSHA,reachableHistoryComplete:true,gitlinks:[...new Set(gitlinks)].sort(),totalBytes:total}};
  return {...report,archiveVerified:true,recoveryVerified:true,digest:await digest(report)};
 }};
}
