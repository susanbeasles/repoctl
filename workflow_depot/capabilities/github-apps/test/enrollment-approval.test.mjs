import {test} from 'node:test';import assert from 'node:assert/strict';
import {enrollmentApprovalService} from '../src/enrollment-authority/service.mjs';
async function fixture(){
 const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),raw=new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey)),keyID=Buffer.from(await crypto.subtle.digest('SHA-256',raw)).toString('hex');let revoked=false,now=1000;const records=new Map();
 const trust={current:async()=>({keyID,ownerID:34,publicKeyX963:Buffer.from(raw).toString('base64'),revoked})},hardware={verify:async()=>({keyID,hardwareVerified:!revoked,revoked,proofDigest:'c'.repeat(64),validUntil:2000})};
 const service=enrollmentApprovalService({storage:{get:async k=>records.get(k),transaction:async fn=>fn({get:async k=>records.get(k),put:async(k,v)=>records.set(k,v)})},trust,hardware,clock:()=>now});
 async function envelope(extra={}){const payload=Buffer.from(JSON.stringify({operationID:'a'.repeat(64),ownerID:34,role:'writer',manifestDigest:'b'.repeat(64),expiresAt:1200,...extra}));return {protocol:'repoctl-app-enrollment-owner-v1',keyID,encoding:'p1363',payload:payload.toString('base64'),signature:Buffer.from(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},pair.privateKey,Buffer.concat([Buffer.from('repoctl-app-enrollment-owner-v1\n'),payload]))).toString('base64')};}
 return {service,envelope,revoke:()=>{revoked=true;},expire:()=>{now=1201;},records};
}
test('enrollment approval verifies exact signed owner intent and returns matching signer session',async()=>{const f=await fixture(),e=await f.envelope(),r=await f.service.admit(e);assert.deepEqual(await f.service.admit(e),r);const out=await f.service.authorize({operationID:r.operationID,approvalReference:r.approvalReference,action:'exchange'});assert.equal(out.session.ownerID,34);assert.equal(out.session.expiresAt,1200000);await assert.rejects(f.service.admit(await f.envelope({role:'release'})));});
test('enrollment approval rejects altered signatures, owner, expiry and current revocation',async()=>{const f=await fixture(),e=await f.envelope();await assert.rejects(f.service.admit({...e,payload:Buffer.from('{}').toString('base64')}));await assert.rejects(f.service.admit(await f.envelope({ownerID:35})));await assert.rejects(f.service.admit(await f.envelope({expiresAt:1600})));const r=await f.service.admit(e),input={operationID:r.operationID,approvalReference:r.approvalReference,action:'reconcile'};f.expire();await assert.rejects(f.service.authorize(input));const g=await fixture(),a=await g.service.admit(await g.envelope());g.revoke();await assert.rejects(g.service.authorize({operationID:a.operationID,approvalReference:a.approvalReference,action:'exchange'}));});

test('fresh signed renewal recovers identical enrollment without reopening conversion',async()=>{
 const f=await fixture(),first=await f.service.admit(await f.envelope());f.expire();
 const envelope=await f.envelope({expiresAt:1400}),request={previousReference:first.approvalReference,envelope},renewed=await f.service.renew(request);
 const base={operationID:first.operationID,approvalReference:renewed.approvalReference};
 assert.equal((await f.service.authorize({...base,action:'reconcile'})).session.expiresAt,1400000);
 await assert.rejects(f.service.authorize({...base,action:'exchange'}));await assert.rejects(f.service.authorize({...base,action:'create'}));
 await assert.rejects(f.service.authorize({...base,approvalReference:first.approvalReference,action:'status'}));
 assert.equal((await f.service.renew(request)).approvalReference,renewed.approvalReference);
 assert.ok(f.records.has(`enrollment-approval-retired:${first.approvalReference}`));
});
test('renewal rejects changed role, stale parent, excessive lifetime and revoked owner',async()=>{
 const f=await fixture(),first=await f.service.admit(await f.envelope());f.expire();
 await assert.rejects(f.service.renew({previousReference:first.approvalReference,envelope:await f.envelope({role:'release',expiresAt:1400})}));
 await assert.rejects(f.service.renew({previousReference:'d'.repeat(64),envelope:await f.envelope({expiresAt:1400})}));
 await assert.rejects(f.service.renew({previousReference:first.approvalReference,envelope:await f.envelope({expiresAt:1600})}));
 f.revoke();await assert.rejects(f.service.renew({previousReference:first.approvalReference,envelope:await f.envelope({expiresAt:1400})}));
});
