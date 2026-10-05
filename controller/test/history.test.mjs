import test from 'node:test';
import assert from 'node:assert/strict';
import {verifyHistory} from '../scripts/verify-history.mjs';
const before='a'.repeat(40),after='b'.repeat(40);
test('history gate accepts one child and rejects rewrite, merge, batching, and missing anchor',()=>{
  assert.equal(verifyHistory(before,after,(...args)=>args[0]==='show'?before:'').appendOnly,true);
  for(const parents of ['c'.repeat(40),`${before} ${after}`,'']) assert.throws(()=>verifyHistory(before,after,()=>parents));
  assert.throws(()=>verifyHistory('0'.repeat(40),after,()=>before));
});
