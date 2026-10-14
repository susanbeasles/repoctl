import test from 'node:test';import assert from 'node:assert/strict';import {acceptedRun} from '../ci/main-source-run.mjs';
test('main consumes only successful same-SHA integration run; current main drift and PR runs fail',async()=>{
 const env={GITHUB_EVENT_NAME:'push',GITHUB_REF:'refs/heads/main',GITHUB_SHA:'a'.repeat(40),GITHUB_REPOSITORY:'o/r',GITHUB_REPOSITORY_ID:'7',INTEGRATION_RUN_ID:'9'};
 const run={head_sha:env.GITHUB_SHA,event:'push',head_branch:'int/feature',status:'completed',conclusion:'success',repository:{id:7,full_name:'o/r'}};const read=async p=>p.includes('/actions/')?run:{object:{sha:env.GITHUB_SHA}};
 assert.equal(await acceptedRun(env,read),run);
 for(const patch of [{event:'pull_request'},{head_branch:'main'},{conclusion:'failure'},{head_sha:'b'.repeat(40)}])await assert.rejects(acceptedRun(env,async p=>p.includes('/actions/')?{...run,...patch}:{object:{sha:env.GITHUB_SHA}}));
 await assert.rejects(acceptedRun(env,async p=>p.includes('/actions/')?run:{object:{sha:'b'.repeat(40)}}));
});
