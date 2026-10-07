import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdtemp,writeFile,rm,realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {generationRequest,generationResult} from '../src/candidate/wire.ts';
import {generationUpload} from '../src/candidate/upload.ts';
import {generationHTTP} from '../src/candidate/http.ts';

test('native receive-pack creates exact objects once and rejects existing generation without replacement',async()=>{
 const root=await realpath(await mkdtemp(join(tmpdir(),'repoctl-wire-')));
 const env={PATH:'/usr/bin:/bin',HOME:root,GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',GIT_TERMINAL_PROMPT:'0',GIT_AUTHOR_NAME:'fixture',GIT_AUTHOR_EMAIL:'fixture@example.invalid',GIT_COMMITTER_NAME:'fixture',GIT_COMMITTER_EMAIL:'fixture@example.invalid'};
 const git=(...args)=>execFileSync('/usr/bin/git',['-c','core.hooksPath=/dev/null',...args],{cwd:root,env});
 try{
  git('init','--bare','-q','source.git');git('init','--bare','-q','remote.git');
  const source=join(root,'source.git'),remote=join(root,'remote.git');
  const tree=git('--git-dir='+source,'mktree').toString().trim();
  const first=git('--git-dir='+source,'commit-tree',tree,'-m','first').toString().trim();
  const second=git('--git-dir='+source,'commit-tree',tree,'-p',first,'-m','second').toString().trim();
  const pack=id=>execFileSync('/usr/bin/git',['--git-dir='+source,'pack-objects','--revs','--stdout','--threads=1'],{env,input:id+'\n'});
  const intent={generationID:'a'.repeat(64),commitSHA:first};
  const send=body=>execFileSync('/usr/bin/git',['-c','core.hooksPath=/dev/null','receive-pack','--stateless-rpc',remote],{env,input:body,stdio:['pipe','pipe','ignore']});
  const binding={repositoryID:7,ref:'refs/heads/int/'+intent.generationID,...intent,baseSHA:first,treeSHA:tree};
  let transfers=0;
  let releases=0;
  const transport=generationHTTP({repository:'owner/fixture',repositoryID:7,ownerID:9,
   credentials:{acquire:async binding=>({...binding,id:'fixture',token:'fixture_token',expiresAt:Math.floor(Date.now()/1000)+60}),release:async()=>{releases++;}},
   fetcher:async(url,options)=>{
    assert.equal(options.redirect,'manual');
    if(url==='https://api.github.com/repos/owner/fixture')return Response.json({id:7,full_name:'owner/fixture',owner:{id:9,type:'User'},archived:false,fork:false});
    if(options.method==='GET'){
     const refs=execFileSync('/usr/bin/git',['receive-pack','--advertise-refs',remote],{env});
     return new Response(Buffer.concat([Buffer.from('001f# service=git-receive-pack\n0000'),refs]),{headers:{'content-type':'application/x-git-receive-pack-advertisement'}});
    }
    transfers++;return new Response(send(options.body),{headers:{'content-type':'application/x-git-receive-pack-result'}});
   }});
  const upload=generationUpload({repositoryID:7,store:{pack:async candidate=>pack(candidate.commitSHA)},transport});
  const controller=new AbortController();
  assert.equal((await upload.create(binding,{signal:controller.signal})).object.sha,first);
  await assert.rejects(upload.create({...binding,repositoryID:8},{signal:controller.signal}),/Invalid/);
  controller.abort();await assert.rejects(upload.create(binding,{signal:controller.signal}),/uncertain/);
  assert.equal(transfers,1);assert.equal(releases,1);
  const ref='refs/heads/int/'+intent.generationID;
  const initial=git('--git-dir='+remote,'cat-file','commit',first);
  assert.deepEqual(initial,git('--git-dir='+source,'cat-file','commit',first));
  assert.equal(generationResult(send(generationRequest({...intent,commitSHA:second},pack(second))),intent),false);
  assert.equal(git('--git-dir='+remote,'rev-parse',ref).toString().trim(),first);
  assert.equal(generationResult(send(generationRequest(intent,pack(first))),intent),false);
  assert.equal(git('--git-dir='+remote,'for-each-ref','--format=%(refname)').toString().trim(),ref);
 }finally{await rm(root,{recursive:true,force:true});}
});

test('wire rejects malformed intent, pack and response instead of asserting publication',()=>{
 const intent={generationID:'a'.repeat(64),commitSHA:'b'.repeat(40)};
 const pack=new Uint8Array(32);pack.set([80,65,67,75,0,0,0,2]);
 for(const value of [{...intent,generationID:'../main'},{...intent,commitSHA:'0'.repeat(40)},{...intent,commitSHA:{toString:()=>intent.commitSHA}},{...intent,extra:true}])assert.throws(()=>generationRequest(value,pack),/Invalid/);
 assert.throws(()=>generationRequest(intent,new Uint8Array(32)),/pack/);
 for(const bytes of [new TextEncoder().encode('0000'),new TextEncoder().encode('zzzz'),new TextEncoder().encode('0008oops'),new Uint8Array(65537)])assert.throws(()=>generationResult(bytes,intent),/report/);
});
