import {derToRaw} from '../promotion.mjs';
const domain='repoctl-execution-owner-v1\n',encoder=new TextEncoder();
const decode=value=>Uint8Array.from(atob(value),c=>c.charCodeAt(0));
export async function verifyExecutionApproval(envelope,keys){
 if(!envelope||Object.keys(envelope).sort().join()!==['protocol','keyID','encoding','payload','signature'].sort().join()||envelope.protocol!==domain.trim()||!['der','p1363'].includes(envelope.encoding)||typeof envelope.payload!=='string'||envelope.payload.length>24000)throw Error('Invalid execution approval');
 const key=keys.get(envelope.keyID);if(!key)throw Error('Unknown execution approver');
 const payload=decode(envelope.payload),message=new Uint8Array(encoder.encode(domain).length+payload.length);message.set(encoder.encode(domain));message.set(payload,encoder.encode(domain).length);
 if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,envelope.encoding==='der'?derToRaw(envelope.signature):decode(envelope.signature),message))throw Error('Invalid execution signature');
 return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(payload));
}
