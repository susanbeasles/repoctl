import test from 'node:test';import assert from 'node:assert/strict';import {previewTarget} from '../ci/preview-guard.mjs';
test('private synthetic target requires approval and never falls back to public ingress',()=>{
 assert.equal(previewTarget('https://10.1.2.3:8443','approved/isolation'),'https://10.1.2.3:8443/');
 for(const [target,approval] of [['https://10.1.2.3',''],['https://example.com','approved'],['https://127.0.0.1','approved'],['http://10.1.2.3','approved'],['https://user:pass@10.1.2.3','approved'],['https://172.32.0.1','approved']])assert.throws(()=>previewTarget(target,approval));
});
