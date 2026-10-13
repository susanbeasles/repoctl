import test from 'node:test';import assert from 'node:assert/strict';
import {mkdtemp,realpath,writeFile,readFile,rm,access} from 'node:fs/promises';
import {tmpdir} from 'node:os';import {join} from 'node:path';import {execFileSync,spawnSync} from 'node:child_process';
import {signedCandidateVerifier} from '../src/candidate/verifier.mjs';
import {candidatePreparation} from '../src/candidate/preparation.mjs';import {candidateSigning} from '../src/candidate/signing.mjs';
async function fixture(){
 const root=await realpath(await mkdtemp(join(tmpdir(),'repoctl-signing-'))),repo=join(root,'repo');
 const env={PATH:'/usr/bin:/bin',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',GIT_AUTHOR_NAME:'fixture',GIT_AUTHOR_EMAIL:'fixture@example.com',GIT_COMMITTER_NAME:'fixture',GIT_COMMITTER_EMAIL:'fixture@example.com'};
 execFileSync('/bin/mkdir',[repo]);const git=(...args)=>execFileSync('/usr/bin/git',args,{cwd:repo,env}).toString().trim();
 git('init','-q','-b','main');await writeFile(join(repo,'base'),'base\n');git('add','.');git('commit','-qm','base');const base=git('rev-parse','HEAD');
 git('checkout','-qb','work/source');await writeFile(join(repo,'submitted'),'feature\n');git('add','.');git('commit','-qm','feat: source');const source=git('rev-parse','HEAD');
 const prep=join(root,'prepared'),builder=await candidatePreparation({sourceGitDirectory:join(repo,'.git'),gitExecutable:'/usr/bin/git',repositoryID:7});
 const prepared=await builder.prepare({repositoryID:7,baseSHA:base,sourceSHA:source},prep);
 const key=join(root,'fixture-key');execFileSync('/usr/bin/ssh-keygen',['-q','-t','ed25519','-N','','-f',key],{env});
 const publicKey=(await readFile(key+'.pub','utf8')).trim().split(' ').slice(0,2).join(' ');let signs=0;
 const config={repositoryID:7,gitExecutable:'/usr/bin/git',sshKeygenExecutable:'/usr/bin/ssh-keygen',publicKey,authorName:'Fixture Candidate',authorEmail:'candidate@example.com',clock:()=>1791370000000,verifySnapshot:async b=>({...b,verified:true,immutable:true}),signer:{async signGit(request){signs++;assert.equal(request.namespace,'git');return execFileSync('/usr/bin/ssh-keygen',['-Y','sign','-n','git','-f',key],{input:request.bytes,env,stdio:['pipe','pipe','ignore'],timeout:10000}).toString();}}};
 return {root,repo,git,prep,prepared,config,signs:()=>signs};
}
test('actual SSH signed candidate is a complete single-parent commit with pinned identity and no source ref mutation',async()=>{
 const f=await fixture();try{
  await writeFile(join(f.repo,'base'),'uncommitted\n');f.git('add','base');const before=f.git('status','--porcelain'),head=f.git('rev-parse','HEAD');
  const out=join(f.root,'signed'),r=await candidateSigning(f.config).finalize(f.prep,out,'feat: qualified candidate');
  const git=(...args)=>execFileSync('/usr/bin/git',['--git-dir='+join(out,'rebuilt/objects.git'),...args]).toString().trim();
  assert.equal(r.state,'signed-awaiting-integration-generation');assert.equal(f.signs(),1);
  const verifier=await signedCandidateVerifier({repositoryID:7,objectDirectory:join(out,'rebuilt/objects.git'),gitExecutable:'/usr/bin/git',sshKeygenExecutable:'/usr/bin/ssh-keygen',publicKey:f.config.publicKey});
  const binding={repositoryID:7,baseSHA:r.baseSHA,commitSHA:r.commitSHA,treeSHA:r.treeSHA};assert.deepEqual(await verifier.verify(binding),{...binding,verified:true});
  await assert.rejects(verifier.verify({...binding,treeSHA:'d'.repeat(40)}),/rejected/);
  await assert.rejects(verifier.verify({...binding,repositoryID:8}),/binding/);
  const otherKey=join(f.root,'other-verifier-key');execFileSync('/usr/bin/ssh-keygen',['-q','-t','ed25519','-N','','-f',otherKey]);const otherPublic=(await readFile(otherKey+'.pub','utf8')).trim().split(' ').slice(0,2).join(' ');
  const foreign=await signedCandidateVerifier({repositoryID:7,objectDirectory:join(out,'rebuilt/objects.git'),gitExecutable:'/usr/bin/git',sshKeygenExecutable:'/usr/bin/ssh-keygen',publicKey:otherPublic});await assert.rejects(foreign.verify(binding));
  const raw=git('cat-file','commit',r.commitSHA);assert.equal(raw.split('\n').filter(v=>v.startsWith('parent ')).join(),'parent '+f.prepared.baseSHA);assert.ok(raw.startsWith('tree '+f.prepared.treeSHA+'\n'));assert.match(raw,/gpgsig -----BEGIN SSH SIGNATURE-----/);
  assert.equal(git('show',r.commitSHA+':submitted'),'feature');git('fsck','--full');const refs=spawnSync('/usr/bin/git',['--git-dir='+join(out,'rebuilt/objects.git'),'show-ref']);assert.equal(refs.status,1);assert.equal(refs.stdout.length,0);
  assert.equal(f.git('rev-parse','HEAD'),head);assert.equal(f.git('status','--porcelain'),before);
  await assert.rejects(candidateSigning(f.config).finalize(f.prep,out,'feat: retry'),/EEXIST/);assert.equal(f.signs(),1);
 }finally{await rm(f.root,{recursive:true,force:true});}
});
test('unconfirmed immutable snapshot and altered prepared tree cannot reach signer',async()=>{
 const f=await fixture();try{
  await assert.rejects(candidateSigning({...f.config,verifySnapshot:async b=>({...b,verified:true,immutable:false})}).finalize(f.prep,join(f.root,'unretained'),'fix: rejected'),/snapshot/);
  const p=JSON.parse(await readFile(join(f.prep,'preparation.json')));p.treeSHA=f.git('rev-parse',f.prepared.baseSHA+'^{tree}');await writeFile(join(f.prep,'preparation.json'),JSON.stringify(p));
  const out=join(f.root,'tampered');await assert.rejects(candidateSigning(f.config).finalize(f.prep,out,'fix: tampered'),/signing failed/);assert.equal(f.signs(),0);
  assert.equal(JSON.parse(await readFile(join(out,'failed.json'))).state,'failed-before-signing');await assert.rejects(access(join(out,'candidate.json')));
 }finally{await rm(f.root,{recursive:true,force:true});}
});
test('wrong pinned public key and uncertain signer response retain failure without retries or secret errors',async()=>{
 const f=await fixture();try{
  const other=join(f.root,'other-fixture-key');execFileSync('/usr/bin/ssh-keygen',['-q','-t','ed25519','-N','','-f',other]);const publicKey=(await readFile(other+'.pub','utf8')).trim().split(' ').slice(0,2).join(' ');
  const out=join(f.root,'wrong-key');await assert.rejects(candidateSigning({...f.config,publicKey}).finalize(f.prep,out,'fix: wrong key'),/signing failed/);assert.equal(f.signs(),1);await assert.rejects(access(join(out,'candidate.json')));
  let attempts=0;const failed=join(f.root,'uncertain');await assert.rejects(candidateSigning({...f.config,signer:{async signGit(){attempts++;throw Error('SECRET-FIXTURE-MARKER');}}}).finalize(f.prep,failed,'fix: unavailable'),error=>!error.message.includes('SECRET-FIXTURE-MARKER')&&error.message.includes('signing failed'));
  assert.equal(attempts,1);assert.equal(JSON.parse(await readFile(join(failed,'failed.json'))).state,'signing-or-verification-uncertain');
 }finally{await rm(f.root,{recursive:true,force:true});}
});

test('unresponsive signing capability times out once and retains uncertain job',async()=>{
 const f=await fixture();try{
  let attempts=0,signal;const out=join(f.root,'timeout'),start=Date.now();
  await assert.rejects(candidateSigning({...f.config,capabilityTimeoutMS:100,signer:{signGit(_request,options){attempts++;signal=options.signal;return new Promise(()=>{});}}}).finalize(f.prep,out,'fix: timeout'),/signing failed/);
  assert.equal(attempts,1);assert.equal(signal.aborted,true);assert.ok(Date.now()-start<3000);
  assert.equal(JSON.parse(await readFile(join(out,'failed.json'))).state,'signing-or-verification-uncertain');await assert.rejects(access(join(out,'candidate.json')));
 }finally{await rm(f.root,{recursive:true,force:true});}
});

test('signer cannot mutate the prepared commit payload through shared request bytes',async()=>{
 const f=await fixture();try{
  const signer={async signGit(request){request.bytes.fill(65);return f.config.signer.signGit(request);}};
  const out=join(f.root,'payload-tamper');await assert.rejects(candidateSigning({...f.config,signer}).finalize(f.prep,out,'feat: preserved payload'),/signing failed/);
  assert.equal(f.signs(),1);assert.match(await readFile(join(out,'unsigned.commit'),'utf8'),/^tree [a-f0-9]{40}\nparent [a-f0-9]{40}\n/);await assert.rejects(access(join(out,'candidate.json')));
 }finally{await rm(f.root,{recursive:true,force:true});}
});
