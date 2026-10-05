import {canonical} from '../ledger.mjs';
const keyPattern=/^recovery\/v1\/[1-9][0-9]*\/[a-f0-9]{64}\.json$/;
export function recoveryR2Publisher({bucket,maxBytes=4*1024*1024}){
 if(typeof bucket?.get!=='function'||typeof bucket?.put!=='function'||!Number.isSafeInteger(maxBytes)||maxBytes<1||maxBytes>4*1024*1024)throw Error('Invalid recovery publisher');
 function key(value){if(!keyPattern.test(value??''))throw Error('Invalid recovery publication key');return value;}
 async function read(value){const object=await bucket.get(key(value));if(!object)return null;if(!Number.isSafeInteger(object.size)||object.size<1||object.size>maxBytes)throw Error('Recovery publication size denied');const bytes=await object.arrayBuffer();if(bytes.byteLength!==object.size)throw Error('Recovery publication size differs');return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}
 return {get:read,async create(value,envelope){
  key(value);const encoded=canonical(envelope),bytes=new TextEncoder().encode(encoded);if(bytes.length>maxBytes)throw Error('Recovery envelope too large');
  const current=await read(value);if(current!==null){if(canonical(current)!==encoded)throw Error('Recovery publication collision');return;}
  // A lost response is surfaced; rerun reconciliation reads the exact envelope.
  await bucket.put(value,bytes,{onlyIf:{etagDoesNotMatch:'*'},httpMetadata:{contentType:'application/json'}});
  const retained=await read(value);if(retained===null||canonical(retained)!==encoded)throw Error('Recovery publication collision or missing readback');
 }};
}
