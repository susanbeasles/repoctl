import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import {readFile} from 'node:fs/promises';
import assert from 'node:assert/strict';
const path=process.argv[2];if(!path)throw Error('Bundle path required');
let calls=0;
const mf=new Miniflare(convertV4MiniflareOptions({workers:[
 {name:'evidence',modules:true,script:await readFile(path,'utf8'),compatibilityDate:'2026-10-04',bindings:{EVIDENCE_ENABLED:'true',EVIDENCE_CONFIG_JSON:'[]'},serviceBindings:{EVIDENCE_POLICY:async()=>{calls++;return Response.json({});},EVIDENCE_HISTORY:async()=>{calls++;return Response.json({});},EVIDENCE_ARCHIVES:async()=>{calls++;return Response.json({});},EVIDENCE_SIGNATURES:async()=>{calls++;return Response.json({});},EVIDENCE_BASELINE:async()=>{calls++;return Response.json({});}}},
 {name:'caller',modules:true,script:'export default {fetch(r,e){return e.VERIFIER.fetch(r);}}',compatibilityDate:'2026-10-04',serviceBindings:{VERIFIER:{name:'evidence',entrypoint:'AdmissionEvidenceService'}}},
 {name:'disabled',modules:true,script:await readFile(path,'utf8'),compatibilityDate:'2026-10-04'},
 {name:'disabled-caller',modules:true,script:'export default {fetch(r,e){return e.VERIFIER.fetch(r);}}',compatibilityDate:'2026-10-04',serviceBindings:{VERIFIER:{name:'disabled',entrypoint:'AdmissionEvidenceService'}}}
 ,{name:'missing-signature',modules:true,script:await readFile(path,'utf8'),compatibilityDate:'2026-10-04',bindings:{EVIDENCE_ENABLED:'true',EVIDENCE_CONFIG_JSON:'[]'},serviceBindings:{EVIDENCE_POLICY:async()=>{calls++;return Response.json({});},EVIDENCE_HISTORY:async()=>{calls++;return Response.json({});},EVIDENCE_ARCHIVES:async()=>{calls++;return Response.json({});},EVIDENCE_BASELINE:async()=>{calls++;return Response.json({});}}}
 ,{name:'missing-signature-caller',modules:true,script:'export default {fetch(r,e){return e.VERIFIER.fetch(r);}}',compatibilityDate:'2026-10-04',serviceBindings:{VERIFIER:{name:'missing-signature',entrypoint:'AdmissionEvidenceService'}}}
 ,{name:'missing-baseline',modules:true,script:await readFile(path,'utf8'),compatibilityDate:'2026-10-04',bindings:{EVIDENCE_ENABLED:'true',EVIDENCE_CONFIG_JSON:'[]'},serviceBindings:{EVIDENCE_POLICY:async()=>{calls++;return Response.json({});},EVIDENCE_HISTORY:async()=>{calls++;return Response.json({});},EVIDENCE_ARCHIVES:async()=>{calls++;return Response.json({});},EVIDENCE_SIGNATURES:async()=>{calls++;return Response.json({});}}}
 ,{name:'missing-baseline-caller',modules:true,script:'export default {fetch(r,e){return e.VERIFIER.fetch(r);}}',compatibilityDate:'2026-10-04',serviceBindings:{VERIFIER:{name:'missing-baseline',entrypoint:'AdmissionEvidenceService'}}}
]}));
try{
 const pub=await mf.getWorker('evidence'),caller=await mf.getWorker('caller'),disabled=await mf.getWorker('disabled-caller');
 assert.equal((await pub.fetch('https://local/v1/evidence/admission',{method:'POST',body:'{}'})).status,404);
 assert.equal((await disabled.fetch('https://internal/v1/evidence/admission',{method:'POST',body:'{}'})).status,503);
 const missingBaseline=await mf.getWorker('missing-baseline-caller');
 assert.equal((await missingBaseline.fetch('https://internal/v1/evidence/admission',{method:'POST',body:'{"repositoryID":1}'})).status,503);
 const missing=await mf.getWorker('missing-signature-caller');
 assert.equal((await missing.fetch('https://internal/v1/evidence/admission',{method:'POST',body:'{"repositoryID":1}'})).status,503);
 assert.equal((await caller.fetch('https://internal/v1/evidence/admission',{method:'POST',body:'{"repositoryID":1}'})).status,403);
 assert.equal((await caller.fetch('https://internal/v1/evidence/completion',{method:'POST',body:'{}'})).status,404);
 assert.equal(calls,0);
 console.log('PASS: real workerd private entrypoint, public ingress closed, missing bindings and unconfigured repositories denied without downstream calls');
}finally{await mf.dispose();}
