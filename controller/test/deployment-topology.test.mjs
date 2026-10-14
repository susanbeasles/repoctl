import {test} from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';import {configFiles,deploymentTopology} from '../src/deployment/topology.mjs';
test('deployment topology isolates public exposure and binds narrow named services without activation',async()=>{
 const templates={};for(const [role,file]of Object.entries(configFiles))templates[role]=JSON.parse(await readFile(new URL('../'+file,import.meta.url),'utf8'));
 const options={prefix:'repoctl-personal',receiptBucket:'repoctl-receipts',recoveryBucket:'repoctl-recovery'},p=deploymentTopology(templates,options);
 assert.equal(p.activated,false);for(const c of Object.values(p.configurations)){assert.equal(c.workers_dev,false);assert.equal(c.preview_urls,false);for(const [k,v]of Object.entries(c.vars))if(k.endsWith('_ENABLED'))assert.equal(v,'false');}
 assert.deepEqual(p.configurations.upload.services,[{binding:'RECOVERY_PUBLISHER',service:'repoctl-personal-archive',entrypoint:'RecoveryPublicationService'}]);assert.equal(p.configurations.archive.services.length,0);assert.equal(p.configurations.signer.services.some(x=>x.binding==='BROKER_AUTHORITY'),false);
 assert.deepEqual(p.configurations.operator.services,[{binding:'OPERATOR_APPROVAL',service:'repoctl-personal-enrollment',entrypoint:'EnrollmentApprovalService'},{binding:'OPERATOR_REGISTRATION',service:'repoctl-personal-registration',entrypoint:'RegistrationControlService'}]);
 assert.deepEqual(p.configurations['operator-ingress'].services,[{binding:'OPERATOR_SERVICE',service:'repoctl-personal-operator',entrypoint:'OperatorService'}]);
 assert.deepEqual(p.configurations.registration.services,[{binding:'APP_ENROLLMENT',service:'repoctl-personal-signer',entrypoint:'AppEnrollmentService'},{binding:'APP_ENROLLMENT_APPROVAL',service:'repoctl-personal-enrollment',entrypoint:'EnrollmentApprovalService'}]);
 assert.equal(p.configurations.operator.services.some(x=>x.binding==='OPERATOR_SESSIONS'),false);
 assert.ok(p.unresolved.some(x=>x.includes('Access session')));
 for(const config of Object.values(p.configurations))for(const link of config.services){
  const target=Object.entries(p.configurations).find(([,value])=>value.name===link.service);
  assert.ok(target, 'Binding target must be an included deployment');
  const source=await readFile(new URL('../'+target[1].main,import.meta.url),'utf8');
  assert.ok(source.includes('export class '+link.entrypoint+' '), 'Binding must select an exported named entrypoint');
 }
 assert.throws(()=>deploymentTopology(templates,{...options,recoveryBucket:options.receiptBucket}));assert.throws(()=>deploymentTopology({...templates,upload:{...templates.upload,routes:['*']}},options));assert.equal(templates.controller.services,undefined);
});
