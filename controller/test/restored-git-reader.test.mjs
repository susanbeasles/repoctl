import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,realpath,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {restoredGitReader} from '../src/archive/restored-git-reader.mjs';
import {gitRecoveryVerifier} from '../src/archive/git-recovery.mjs';
test('recovery reads actual packed Git history without replacement refs or external stores',async()=>{
 const dir=await realpath(await mkdtemp(join(tmpdir(),'repoctl-recovery-')));try{
 const git=(...args)=>execFileSync('/usr/bin/git',args,{cwd:dir,env:{PATH:'/usr/bin:/bin',HOME:dir,GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',GIT_AUTHOR_NAME:'test',GIT_AUTHOR_EMAIL:'test@example.com',GIT_COMMITTER_NAME:'test',GIT_COMMITTER_EMAIL:'test@example.com'}}).toString().trim();
 git('init','-q');await writeFile(join(dir,'file'),'base');git('add','file');git('commit','-qm','base');const source=git('rev-parse','HEAD');await writeFile(join(dir,'file'),'child');git('add','file');git('commit','-qm','child');const candidate=git('rev-parse','HEAD'),tree=git('rev-parse','HEAD^{tree}');git('gc','--prune=now');
 const archiveDigest='a'.repeat(64),reader=await restoredGitReader({directory:join(dir,'.git'),gitExecutable:'/usr/bin/git',repositoryID:1,archiveDigest});
 const report=await gitRecoveryVerifier({reader}).verify({repositoryID:1,commitSHA:candidate,sourceSHA:source,treeSHA:tree,archiveDigests:[archiveDigest]});assert.equal(report.recoveryVerified,true);assert.equal(report.objects.length,6);
 await assert.rejects(reader.object({repositoryID:2,objectID:candidate,archiveDigests:[archiveDigest]}));
 await writeFile(join(dir,'.git','objects','info','alternates'),'/somewhere');await assert.rejects(restoredGitReader({directory:join(dir,'.git'),gitExecutable:'/usr/bin/git',repositoryID:1,archiveDigest}),/externally linked/);
 }finally{await rm(dir,{recursive:true,force:true});}
});
