import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {profile,candidate} from '../ci/project-profile.mjs';
function fixture(fn){const p=mkdtempSync(join(tmpdir(),'quality-'));try{fn(p);}finally{rmSync(p,{recursive:true,force:true});}}
test('preserves existing Node runner and requires every quality command',()=>fixture(p=>{
 writeFileSync(join(p,'package-lock.json'),'{}');
 const scripts={lint:'eslint .',typecheck:'tsc --noEmit',test:'node --test',build:'node build.mjs'};
 writeFileSync(join(p,'package.json'),JSON.stringify({scripts}));
 assert.deepEqual(profile(p).slice(1),['lint','typecheck','test','build'].map(n=>['npm','run',n]));
 delete scripts.typecheck;writeFileSync(join(p,'package.json'),JSON.stringify({scripts}));assert.throws(()=>profile(p),/typecheck/);
}));
test('Python runner selection must be explicit and valid',()=>fixture(p=>{
 writeFileSync(join(p,'pyproject.toml'),'');assert.throws(()=>profile(p));
 const policy={pythonInstall:['python','-m','pip','install','--require-hashes','-r','requirements-ci.txt'],pythonLint:['ruff','check','.'],pythonTypes:['mypy','.'],pythonTests:['python','-m','unittest'],pythonBuild:['python','-m','build']};
 writeFileSync(join(p,'.workflow-depot-quality.json'),JSON.stringify(policy));assert.deepEqual(profile(p)[3],policy.pythonTests);
 policy.pythonBuild=[];writeFileSync(join(p,'.workflow-depot-quality.json'),JSON.stringify(policy));assert.throws(()=>profile(p),/pythonBuild/);
}));
test('main, PR events and malformed identities cannot execute project tooling',()=>{
 const env={GITHUB_EVENT_NAME:'push',GITHUB_REF:'refs/heads/int/feature',GITHUB_SHA:'a'.repeat(40)};candidate(env);
 for(const patch of [{GITHUB_REF:'refs/heads/main'},{GITHUB_EVENT_NAME:'pull_request'},{GITHUB_SHA:'latest'}]) assert.throws(()=>candidate({...env,...patch}));
});
