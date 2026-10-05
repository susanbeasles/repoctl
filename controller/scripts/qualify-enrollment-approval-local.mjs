import {Miniflare,convertV4MiniflareOptions} from 'miniflare';import {readFile} from 'node:fs/promises';import {generateKeyPairSync,createHash,sign} from 'node:crypto';import assert from 'node:assert/strict';
const bundle=process.argv[2];if(!bundle)throw Error('Usage: node scripts/qualify-enrollment-approval-local.mjs BUNDLE');
const pair=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),jwk=pair.publicKey.export({format:'jwk'}),raw=Buffer.concat([Buffer.from([4]),Buffer.from(jwk.x,'base64url'),Buffer.from(jwk.y,'base64url')]),keyID=createHash('sha256').update(raw).digest('hex');
const intent={operationID:'a'.repeat(64),ownerID:34,role:'writer',manifestDigest:'b'.repeat(64),expiresAt:Math.floor(Date.now()/1000)+240};
const payload=Buffer.from(JSON.stringify(intent,null,2)+'\n'),envelope={protocol:'repoctl-app-enrollment-owner-v1',keyID,encoding:'der',payload:payload.toString('base64'),signature:sign('sha256',Buffer.concat([Buffer.from('repoctl-app-enrollment-owner-v1\n'),payload]),pair.privateKey).toString('base64')};let revoked=false;
const mf=new Miniflare(convertV4MiniflareOptions({workers:[
 {name:'approval',modules:true,script:await readFile(bundle,'utf8'),compatibilityDate:'2026-10-04',bindings:{ENROLLMENT_APPROVAL_ENABLED:'true'},durableObjects:{ENROLLMENT_APPROVAL_COORDINATOR:{className:'EnrollmentApprovalCoordinator',useSQLite:true}},serviceBindings:{ENROLLMENT_TRUST:async()=>Response.json({keyID,ownerID:34,publicKeyX963:raw.toString('base64'),revoked}),ENROLLMENT_HARDWARE:async()=>Response.json({keyID,hardwareVerified:!revoked,revoked,proofDigest:'c'.repeat(64),validUntil:intent.expiresAt})}},
 {name:'caller',modules:true,script:`export default {fetch(r,e){return e.APPROVAL.fetch(r);}}`,compatibilityDate:'2026-10-04',serviceBindings:{APPROVAL:{name:'approval',entrypoint:'EnrollmentApprovalService'}}}
]}));
try{
 const pub=await mf.getWorker('approval');assert.equal((await pub.fetch('https://local/v1/enrollment/admit',{method:'POST',body:JSON.stringify(envelope)})).status,404);
 const caller=await mf.getWorker('caller'),call=(path,body)=>caller.fetch(`https://internal/v1/enrollment/${path}`,{method:'POST',body:JSON.stringify(body)});
 const admitted=await call('admit',envelope);assert.equal(admitted.status,200);const admission=await admitted.json(),input={operationID:intent.operationID,approvalReference:admission.approvalReference,action:'exchange'};
 const authorized=await call('authorize',input);assert.equal(authorized.status,200);assert.equal((await authorized.json()).session.manifestDigest,intent.manifestDigest);
 assert.equal((await call('admit',{...envelope,signature:Buffer.alloc(70).toString('base64')})).status,403);
 revoked=true;assert.equal((await call('authorize',input)).status,403);
 console.log('PASS: real workerd private enrollment authority verifies DER exact bytes and blocks current revocation');
}finally{await mf.dispose();}
