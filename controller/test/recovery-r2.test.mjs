import test from 'node:test';import assert from 'node:assert/strict';import {recoveryR2Publisher} from '../src/archive/r2-publisher.mjs';
test('R2 recovery publication creates conditionally and reconciles identical retry',async()=>{
 let bytes,writes=0;const bucket={get:async()=>bytes?{size:bytes.length,arrayBuffer:async()=>bytes.buffer.slice(bytes.byteOffset,bytes.byteOffset+bytes.byteLength)}:null,put:async(k,b,options)=>{assert.deepEqual(options.onlyIf,{etagDoesNotMatch:'*'});writes++;if(bytes)return null;bytes=b;return {};}};
 const p=recoveryR2Publisher({bucket}),key='recovery/v1/1/'+'a'.repeat(64)+'.json',entry={signature:'example',payload:{value:1}};
 await p.create(key,entry);await p.create(key,entry);assert.equal(writes,1);assert.deepEqual(await p.get(key),entry);
 await assert.rejects(p.create(key,{...entry,signature:'different'}),/collision/);await assert.rejects(p.create('../bad',entry),/key/);
});
test('R2 recovery publication rejects concurrent replacement and reconciles lost response',async()=>{
 const key='recovery/v1/1/'+'b'.repeat(64)+'.json';let bytes;const read=async()=>bytes?{size:bytes.length,arrayBuffer:async()=>bytes.buffer.slice(bytes.byteOffset,bytes.byteOffset+bytes.byteLength)}:null;
 const p=recoveryR2Publisher({bucket:{get:read,put:async()=>{bytes=new TextEncoder().encode('{"foreign":true}');return null;}}});await assert.rejects(p.create(key,{approved:true}),/collision/);
 bytes=undefined;const q=recoveryR2Publisher({bucket:{get:read,put:async(k,b)=>{bytes=b;throw Error('lost response');}}});await assert.rejects(q.create(key,{approved:true}),/lost response/);await q.create(key,{approved:true});
});
