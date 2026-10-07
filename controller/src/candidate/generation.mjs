const sha=/^[a-f0-9]{40}$/,hash=/^[a-f0-9]{64}$/;
// Installed read/write/journal capabilities only. Signed objects must already
// exist remotely. Never reconstruct an unsigned GitHub API commit or update refs.
export function integrationGeneration({repository,repositoryID,branch='main',token,records,verifyNamespace,verifyCandidate,fetcher=fetch,timeoutMS=10000}){
 if(!Number.isSafeInteger(timeoutMS)||timeoutMS<100||timeoutMS>10000||!/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(repository??'')||!Number.isSafeInteger(repositoryID)||repositoryID<1||!['main','master'].includes(branch)||typeof token!=='function'||typeof verifyNamespace!=='function'||typeof verifyCandidate!=='function'||!['reserve','read','transition'].every(k=>typeof records?.[k]==='function'))throw Error('Invalid integration generation configuration');
 const root=`https://api.github.com/repos/${repository}`;
 async function bounded(fn){
  const controller=new AbortController();let timer;
  try{return await Promise.race([Promise.resolve().then(()=>fn(controller.signal)),new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(Error('Integration capability timeout'));},timeoutMS);})]);}finally{clearTimeout(timer);}
 }
 async function request(path,body,absent=false){
  try{return await bounded(async signal=>{
  const credential=await token({signal});signal.throwIfAborted();if(typeof credential!=='string'||!credential||credential.length>16000||/[\r\n]/.test(credential))throw Error('Invalid integration credential');
  const response=await fetcher(root+path,{method:body?'POST':'GET',redirect:'manual',signal,headers:{Accept:'application/vnd.github+json',Authorization:`Bearer ${credential}`,'Content-Type':'application/json','User-Agent':'repoctl-integration-generation','X-GitHub-Api-Version':'2026-03-10'},...(body?{body:JSON.stringify(body)}:{})});
  if(absent&&response.status===404)return null;if(!response.ok)throw Error('GitHub integration observation/mutation failed');
  const reader=response.body?.getReader();if(!reader)throw Error('Empty GitHub integration response');let size=0;const chunks=[];
  while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>65536){await reader.cancel();throw Error('Oversized GitHub integration response');}chunks.push(value);}
  const bytes=new Uint8Array(size);let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.length;}return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
  });}catch{throw Error('GitHub integration request failed or timed out');}
 }
 async function identity(){const r=await request('');if(r.id!==repositoryID||r.full_name?.toLowerCase()!==repository.toLowerCase()||r.fork!==false||r.archived!==false)throw Error('Integration repository identity changed');}
 return {async publish(intent){
  if(!intent||Object.getPrototypeOf(intent)!==Object.prototype||Object.keys(intent).sort().join()!==['generationID','baseSHA','commitSHA','treeSHA'].sort().join())throw Error('Invalid integration generation intent');
  // Validate one private snapshot. Caller edits during awaited capabilities must
  // never change the objects checked, durable reservation or eventual ref write.
  intent=Object.freeze({...intent});
  if(typeof intent.generationID!=='string'||!hash.test(intent.generationID)||![intent.baseSHA,intent.commitSHA,intent.treeSHA].every(v=>typeof v==='string'&&sha.test(v)))throw Error('Invalid integration generation intent');
  const ref='refs/heads/int/'+intent.generationID,binding={repositoryID,ref,...intent};
  async function validate(){
   await identity();const tip=await request('/git/ref/heads/'+branch),commit=await request('/git/commits/'+intent.commitSHA);
   if(tip.ref!=='refs/heads/'+branch||tip.object?.type!=='commit'||tip.object.sha!==intent.baseSHA||commit.sha!==intent.commitSHA||commit.parents?.length!==1||commit.parents[0].sha!==intent.baseSHA||commit.tree?.sha!==intent.treeSHA||commit.verification?.verified!==true||commit.verification.reason!=='valid')throw Error('Integration base/tree/signed history rejected');
   const candidateBinding={repositoryID,baseSHA:intent.baseSHA,commitSHA:intent.commitSHA,treeSHA:intent.treeSHA};
   let designated;try{designated=await bounded(signal=>verifyCandidate(candidateBinding,{signal}));}catch{throw Error('Designated candidate verification unavailable');}
   if(designated?.verified!==true||Object.entries(candidateBinding).some(([k,v])=>designated[k]!==v))throw Error('Designated candidate signer not confirmed');
   let proof;try{proof=await bounded(signal=>verifyNamespace({repositoryID,ref},{signal}));}catch{throw Error('Integration namespace verification unavailable');}if(proof?.verified!==true||proof.immutable!==true||proof.repositoryID!==repositoryID||proof.ref!==ref)throw Error('Immutable integration namespace not confirmed');
  }
  const target='/git/ref/heads/int/'+intent.generationID;
  const matches=r=>r?.ref===ref&&r.object?.type==='commit'&&r.object.sha===intent.commitSHA;
  await validate();const created=await records.reserve(binding),record=await records.read(intent.generationID);
  if(typeof created!=='boolean')throw Error('Invalid generation reservation result');
  if(!record||Object.entries(binding).some(([k,v])=>record[k]!==v)||!['reserved','creating','uncertain','confirmed'].includes(record.phase))throw Error('Generation journal binding differs');
  const existing=await request(target,undefined,true);
  if(!created){
   if(!matches(existing)||!['creating','uncertain','confirmed'].includes(record.phase))throw Error('Generation collision or unresolved publication; no write retried');
  }else{
   if(existing)throw Error('Generation ref already exists; never adopt or replace it');
   await validate();
   if(await records.transition(intent.generationID,'reserved','creating')!==true)throw Error('Generation publication already claimed');
   try{const result=await request('/git/refs',{ref,sha:intent.commitSHA});if(!matches(result))throw Error('Created generation response differs');}
   catch{await records.transition(intent.generationID,'creating','uncertain');throw Error('Generation creation outcome uncertain; read back before proceeding');}
  }
  await validate();if(!matches(await request(target)))throw Error('Integration generation readback differs');
  const current=await records.read(intent.generationID);
  if(!current||Object.entries(binding).some(([k,v])=>current[k]!==v)||!['creating','uncertain','confirmed'].includes(current.phase))throw Error('Generation journal changed during publication');
  const phase=current.phase;
  if(phase!=='confirmed'&&await records.transition(intent.generationID,phase,'confirmed')!==true)throw Error('Generation confirmation not retained');
  return {protocol:'repoctl-integration-generation-v1',...binding,published:true};
 }};
}
