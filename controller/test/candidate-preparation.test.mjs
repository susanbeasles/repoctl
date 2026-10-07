import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,realpath,rm,writeFile,readFile,access,stat,rename,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {candidatePreparation} from '../src/candidate/preparation.mjs';
async function fixture(){
 const root=await realpath(await mkdtemp(join(tmpdir(),'repoctl-candidate-'))),source=join(root,'source');
 execFileSync('/bin/mkdir',[source]);
 const git=(...args)=>execFileSync('/usr/bin/git',args,{cwd:source,env:{PATH:'/usr/bin:/bin',HOME:root,GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',GIT_AUTHOR_NAME:'fixture',GIT_AUTHOR_EMAIL:'fixture@example.com',GIT_COMMITTER_NAME:'fixture',GIT_COMMITTER_EMAIL:'fixture@example.com'}}).toString().trim();
 git('init','-q','-b','main');await writeFile(join(source,'shared'),'base\n');git('add','.');git('commit','-qm','base');const ancestor=git('rev-parse','HEAD');
 git('checkout','-qb','work/fixture');await writeFile(join(source,'submitted'),'source\n');await writeFile(join(source,'binary'),Buffer.from([0,255,17,0]));git('add','.');git('commit','-qm','submission');const sourceSHA=git('rev-parse','HEAD');
 git('checkout','-q','main');await writeFile(join(source,'main-only'),'protected\n');git('add','.');git('commit','-qm','main advance');const baseSHA=git('rev-parse','HEAD');
 const builder=await candidatePreparation({sourceGitDirectory:join(source,'.git'),gitExecutable:'/usr/bin/git',repositoryID:7});
 return {root,source,git,ancestor,sourceSHA,baseSHA,builder,intent:{repositoryID:7,baseSHA,sourceSHA}};
}
test('actual Git candidate preparation preserves submission and main without executing project code',async()=>{
 const f=await fixture();try{
  await writeFile(join(f.source,'shared'),'existing uncommitted work\n');f.git('add','shared');const before=f.git('status','--porcelain'),head=f.git('rev-parse','HEAD');
  const output=join(f.root,'prepared'),r=await f.builder.prepare(f.intent,output);
  assert.equal((await stat(output)).mode&0o777,0o700);
  assert.equal(r.state,'prepared-awaiting-signature');assert.equal(r.signingRequired,true);assert.equal(r.mergeBaseSHA,f.ancestor);
  const git=(...args)=>execFileSync('/usr/bin/git',['--git-dir='+join(output,'objects.git'),...args],{env:{PATH:'/usr/bin:/bin',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null'}});
  assert.equal(git('show',r.treeSHA+':main-only').toString(),'protected\n');assert.equal(git('show',r.treeSHA+':submitted').toString(),'source\n');assert.deepEqual(git('show',r.treeSHA+':binary'),Buffer.from([0,255,17,0]));assert.equal(git('show',r.treeSHA+':shared').toString(),'base\n');
  assert.equal(r.snapshotDigest,createHash('sha256').update(await readFile(join(output,'submission.pack'))).digest('hex'));
  assert.equal(git('cat-file','-t',f.sourceSHA).toString().trim(),'commit');assert.equal(f.git('rev-parse','HEAD'),head);assert.equal(f.git('status','--porcelain'),before);
  await assert.rejects(f.builder.prepare(f.intent,output),/EEXIST/);
  await assert.rejects(f.builder.prepare({...f.intent,repositoryID:8},join(f.root,'foreign')),/Invalid/);
 }finally{await rm(f.root,{recursive:true,force:true});}
});
test('conflicts retain failed preparation and cannot silently create a candidate',async()=>{
 const f=await fixture();try{
  f.git('checkout','-q','work/fixture');await writeFile(join(f.source,'shared'),'submission conflict\n');f.git('add','shared');f.git('commit','-qm','source conflict');const sourceSHA=f.git('rev-parse','HEAD');
  f.git('checkout','-q','main');await writeFile(join(f.source,'shared'),'main conflict\n');f.git('add','shared');f.git('commit','-qm','main conflict');const baseSHA=f.git('rev-parse','HEAD');
  const output=join(f.root,'conflict');await assert.rejects(f.builder.prepare({repositoryID:7,baseSHA,sourceSHA},output),/conflict/);
  assert.equal(JSON.parse(await readFile(join(output,'failed.json'),'utf8')).requiresNewPreparation,true);await assert.rejects(access(join(output,'preparation.json')));
  assert.equal(f.git('rev-parse','HEAD'),baseSHA);
 }finally{await rm(f.root,{recursive:true,force:true});}
});
test('candidate-controlled attributes and configured filters cannot execute during preparation',async()=>{
 const f=await fixture();try{
  f.git('checkout','-q','work/fixture');await writeFile(join(f.source,'.gitattributes'),'* diff=malicious filter=malicious\n');f.git('add','.gitattributes');f.git('commit','-qm','attributes');const sourceSHA=f.git('rev-parse','HEAD');
  const marker=join(f.root,'executed');const command='/bin/sh -c "echo executed > '+marker+'; cat"';
  f.git('config','diff.malicious.command',command);f.git('config','diff.malicious.textconv',command);f.git('config','filter.malicious.clean',command);f.git('config','filter.malicious.smudge',command);
  const result=await f.builder.prepare({...f.intent,sourceSHA},join(f.root,'attributes'));
  assert.equal(result.state,'prepared-awaiting-signature');await assert.rejects(access(marker));assert.equal(f.git('rev-parse','HEAD'),sourceSHA);
 }finally{await rm(f.root,{recursive:true,force:true});}
});

test('incomplete or externally linked source stores cannot enter candidate preparation',async()=>{
 const f=await fixture();try{
  await writeFile(join(f.source,'.git/objects/info/alternates'),'/external/object/store\n');
  await assert.rejects(candidatePreparation({sourceGitDirectory:join(f.source,'.git'),gitExecutable:'/usr/bin/git',repositoryID:7}),/complete independent/);
 }finally{await rm(f.root,{recursive:true,force:true});}
});

test('source storage drift after configuration rejects before creating preparation',async()=>{
 const f=await fixture();try{
  await writeFile(join(f.source,'.git/objects/info/alternates'),'/external/object/store\n');
  const output=join(f.root,'drift');
  await assert.rejects(f.builder.prepare(f.intent,output),/complete independent/);
  await assert.rejects(access(output));
 }finally{await rm(f.root,{recursive:true,force:true});}
});
test('linked common directories and symlinked object stores cannot supply source evidence',async()=>{
 const f=await fixture();try{
  await writeFile(join(f.source,'.git/commondir'),'../../external\n');
  await assert.rejects(candidatePreparation({sourceGitDirectory:join(f.source,'.git'),gitExecutable:'/usr/bin/git',repositoryID:7}),/complete independent/);
  await rm(join(f.source,'.git/commondir'));
  await rename(join(f.source,'.git/objects'),join(f.root,'external-objects'));
  await symlink(join(f.root,'external-objects'),join(f.source,'.git/objects'));
  await assert.rejects(candidatePreparation({sourceGitDirectory:join(f.source,'.git'),gitExecutable:'/usr/bin/git',repositoryID:7}),/complete independent/);
 }finally{await rm(f.root,{recursive:true,force:true});}
});
