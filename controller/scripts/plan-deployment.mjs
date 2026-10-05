import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';import {resolve,dirname} from 'node:path';
import {configFiles,deploymentTopology} from '../src/deployment/topology.mjs';
try{
 if(process.argv.length!==3)throw Error();const root=resolve(dirname(fileURLToPath(import.meta.url)),'..'),input=JSON.parse(await readFile(process.argv[2],'utf8'));
 if(Object.keys(input).sort().join()!=='prefix,receiptBucket,recoveryBucket')throw Error();
 const templates={};for(const [role,file]of Object.entries(configFiles))templates[role]=JSON.parse(await readFile(resolve(root,file),'utf8'));
 console.log(JSON.stringify(deploymentTopology(templates,input),null,2));
}catch{console.error('Deployment plan rejected. Supply JSON with prefix, receiptBucket and recoveryBucket. No deployment performed.');process.exitCode=1;}
