import {createHash} from 'node:crypto';
const SHA=/^[a-f0-9]{40}$/;
const LIMIT=8*1024*1024;
const fail=()=>{throw Error('Deployment journal unavailable or conflicted; reconcile before retrying');};
const copy=structuredClone;
const oid=(type,bytes)=>createHash('sha1').update(`${type} ${Buffer.byteLength(bytes)}\0`).update(bytes).digest('hex');
// This adapter writes data only to one dedicated ref, never main or workflows.
// Concurrent updates have the same parent; force:false permits only one winner.
export function createGitHubJournal({api,repository,repositoryID,anchorSHA,branch='deployment-state'}) {
  if(!api?.request||!/^susanbeasles\/[A-Za-z0-9_.-]+$/.test(repository)||repositoryID!==1405415291||!SHA.test(anchorSHA??'')||branch!=='deployment-state') fail();
  const root=`/repos/${repository}`,ref=`${root}/git/ref/heads/${branch}`;
  let queue=Promise.resolve();
  async function read() {
    const repo=await api.request(root);
    if(repo?.id!==repositoryID||repo.owner?.id!==215839550||repo.fork||repo.archived) fail();
    const rules=await api.request(`${root}/rules/branches/${branch}`);
    if(!Array.isArray(rules)||!['deletion','non_fast_forward'].every(type=>rules.some(rule=>rule.type===type))) fail();
    const head=await api.request(ref);
    // Initial creation is an explicit commissioning action. A deleted journal
    // must never look like a fresh install and reopen consumed operations.
    if(!SHA.test(head?.object?.sha??'')) fail();
    const sha=head.object.sha;
    const ancestry=await api.request(`${root}/compare/${anchorSHA}...${sha}`);
    if(!['identical','ahead'].includes(ancestry?.status)) fail();
    const commit=await api.request(`${root}/git/commits/${sha}`);
    if(commit?.sha!==sha||!SHA.test(commit.tree?.sha??'')) fail();
    const tree=await api.request(`${root}/git/trees/${commit.tree.sha}`);
    if(tree?.truncated||tree?.tree?.length!==1||tree.tree[0].path!=='journal.json'||tree.tree[0].mode!=='100644'||tree.tree[0].type!=='blob'||!SHA.test(tree.tree[0].sha)) fail();
    const blob=await api.request(`${root}/git/blobs/${tree.tree[0].sha}`);
    if(blob?.encoding!=='base64'||!Number.isSafeInteger(blob.size)||blob.size>LIMIT||typeof blob.content!=='string'||blob.content.length>LIMIT*1.5) fail();
    const bytes=Buffer.from(blob.content.replaceAll('\n',''),'base64');
    if(bytes.length!==blob.size||oid('blob',bytes)!==tree.tree[0].sha) fail();
    const state=JSON.parse(bytes.toString('utf8'));
    if(state.schema!=='deployment-journal/v1'||state.repositoryID!==repositoryID||!Number.isSafeInteger(state.sequence)||state.sequence<0||!state.entries||Object.getPrototypeOf(state.entries)!==Object.prototype) fail();
    return {sha,state};
  }
  function key(value){if(typeof value!=='string'||!value.length||value.length>300||! /^[A-Za-z0-9:._/-]+$/.test(value)||['__proto__','constructor','prototype'].includes(value))fail();return value;}
  async function transaction(fn) {
    const next=queue.then(async()=>{
      const {sha,state}=await read(),entries=copy(state.entries);
      const tx={get:async k=>copy(Object.hasOwn(entries,key(k))?entries[k]:undefined),put:async(k,value)=>{entries[key(k)]=copy(value);}};
      const result=await fn(tx);
      const text=JSON.stringify({...state,sequence:state.sequence+1,entries});
      if(Buffer.byteLength(text)>LIMIT) fail();
      const blob=await api.request(`${root}/git/blobs`,'POST',{content:text,encoding:'utf-8'});
      if(blob?.sha!==oid('blob',text)) fail();
      const tree=await api.request(`${root}/git/trees`,'POST',{tree:[{path:'journal.json',mode:'100644',type:'blob',sha:blob.sha}]});
      if(!SHA.test(tree?.sha??'')) fail();
      const commit=await api.request(`${root}/git/commits`,'POST',{message:`Deployment journal sequence ${state.sequence+1}`,tree:tree.sha,parents:[sha]});
      if(!SHA.test(commit?.sha??'')||commit.parents?.length!==1||commit.parents[0].sha!==sha) fail();
      // Never retry a write whose result is ambiguous. The retained ref is the
      // authority; provider calls occur only after this write and readback return.
      try {
        const updated=await api.request(`${root}/git/refs/heads/${branch}`,'PATCH',{sha:commit.sha,force:false});
        if(updated?.object?.sha!==commit.sha) fail();
        if((await api.request(ref))?.object?.sha!==commit.sha) fail();
      } catch {fail();}
      return result;
    });
    queue=next.catch(()=>{});return next;
  }
  return Object.freeze({get:async k=>{const {state}=await read();return copy(Object.hasOwn(state.entries,key(k))?state.entries[k]:undefined);},put:(k,value)=>transaction(tx=>tx.put(k,value)),transaction});
}
