import {canonical} from '../ledger.mjs';
const hash=/^[a-f0-9]{64}$/,sha=/^[a-f0-9]{40}$/;
const fail=message=>{throw Error(message);};
const exact=(v,fields)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join()===fields.slice().sort().join();
const uniqueStrings=v=>Array.isArray(v)&&v.every(x=>typeof x==='string'&&x.length>0&&x.length<=500)&&new Set(v).size===v.length;
const same=(a,b)=>canonical(a.slice().sort())===canonical(b.slice().sort());
export const mandatoryScanCategories=Object.freeze(['dependency-integrity','inventory','vulnerability','sast','dast','pentest','malware','quality']);

// The authenticated adapter proves provenance. This function proves exact
// coverage against independently retained inventory and accepted depot policy.
export function validateScanEvidence(receipt,expected,policy,inventory,now){
 if(!exact(receipt,['schema','repositoryID','commitSHA','treeSHA','policyDigest','inventoryDigest','tools'])||receipt.schema!=='repoctl-source-scans/v1'||receipt.repositoryID!==expected.repositoryID||receipt.commitSHA!==expected.commitSHA||receipt.treeSHA!==expected.treeSHA||receipt.policyDigest!==expected.policyDigest||!sha.test(receipt.commitSHA)||!hash.test(receipt.inventoryDigest))fail('Scan generation differs');
 if(!exact(inventory,['digest','complete','paths','languages','frameworks','manifests'])||inventory.complete!==true||receipt.inventoryDigest!==inventory.digest||!hash.test(inventory.digest)||!['paths','languages','frameworks','manifests'].every(k=>uniqueStrings(inventory[k]))||inventory.manifests.some(p=>!inventory.paths.includes(p)))fail('Full source inventory unavailable');
 if(!policy||!uniqueStrings(policy.supportedLanguages)||!uniqueStrings(policy.supportedFrameworks)||inventory.languages.some(x=>!policy.supportedLanguages.includes(x))||inventory.frameworks.some(x=>!policy.supportedFrameworks.includes(x))||!Array.isArray(policy.requiredTools)||!policy.requiredTools.length||!uniqueStrings(policy.requiredCategories)||!policy.requiredCategories.length||!Array.isArray(policy.exemptions))fail('Unsupported or unqualified source stack');
 if(mandatoryScanCategories.some(category=>!policy.requiredCategories.includes(category))||!hash.test(policy.sonarqubeStandardRulesetDigest??'')||!policy.requiredTools.some(tool=>tool.id==='sonarqube'&&tool.category==='quality'&&tool.rulesetDigest===policy.sonarqubeStandardRulesetDigest))fail('Mandatory scanner categories and SonarQube standard rules required');
 const expectedIDs=new Set(),categories=new Set();
 for(const required of policy.requiredTools){
  if(!exact(required,['id','category','version','rulesetDigest','databaseMaxAgeSeconds'])||!uniqueStrings([required.id])||!uniqueStrings([required.version])||!hash.test(required.rulesetDigest)||!Number.isSafeInteger(required.databaseMaxAgeSeconds)||required.databaseMaxAgeSeconds<0||expectedIDs.has(required.id))fail('Invalid required scanner policy');
  expectedIDs.add(required.id);categories.add(required.category);
 }
 if(!Array.isArray(receipt.tools)||receipt.tools.length!==expectedIDs.size||new Set(receipt.tools.map(x=>x?.id)).size!==expectedIDs.size)fail('Missing or duplicate scanner evidence');
 for(const tool of receipt.tools){
  const required=policy.requiredTools.find(x=>x.id===tool.id);
  if(!required||!exact(tool,['id','category','version','rulesetDigest','status','commitSHA','inventoryDigest','coveredPaths','databaseUpdatedAt','completedAt','evidenceDigest'])||tool.category!==required.category||tool.version!==required.version||tool.rulesetDigest!==required.rulesetDigest||tool.status!=='passed'||tool.commitSHA!==expected.commitSHA||tool.inventoryDigest!==inventory.digest||!hash.test(tool.evidenceDigest)||!uniqueStrings(tool.coveredPaths)||!Number.isSafeInteger(tool.completedAt)||tool.completedAt>now||tool.completedAt<now-3600)fail('Scanner failed, skipped, stale or untrusted');
  if(required.databaseMaxAgeSeconds>0&&(!Number.isSafeInteger(tool.databaseUpdatedAt)||tool.databaseUpdatedAt>now||tool.databaseUpdatedAt<now-required.databaseMaxAgeSeconds))fail('Scanner vulnerability database stale');
  if(required.databaseMaxAgeSeconds===0&&tool.databaseUpdatedAt!==null)fail('Unexpected scanner database metadata');
  const exempt=policy.exemptions.filter(x=>x.toolID===tool.id);
  for(const item of exempt)if(!exact(item,['toolID','path','reason'])||!inventory.paths.includes(item.path)||typeof item.reason!=='string'||!item.reason.length)fail('Invalid policy scanner exemption');
  if(!same(tool.coveredPaths,inventory.paths.filter(path=>!exempt.some(x=>x.path===path))))fail('Scanner coverage gap or caller exemption');
 }
 if(policy.exemptions.some(x=>!expectedIDs.has(x.toolID))||policy.requiredCategories.some(c=>!categories.has(c)))fail('Required scanner category missing');
 return receipt;
}
