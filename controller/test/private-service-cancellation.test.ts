import test from 'node:test';
import assert from 'node:assert/strict';
import {boundJSON} from '../src/runtime/services.mjs';
test('private service calls propagate cancellation and cancel a stalled response reader', async () => {
 const controller = new AbortController(); let canceled = false, called = false;
 let ready!: () => void; const entered = new Promise<void>(resolve => {ready = resolve;});
 const binding = {fetch: async (_url: string, options: {signal: AbortSignal}) => {
  called = true; assert.equal(options.signal.aborted, false);
  return new Response(new ReadableStream({pull() {ready();}, cancel() {canceled = true;}}));
 }};
 const pending = boundJSON(binding, '/fixed', {}, {signal: controller.signal});
 await entered; controller.abort(); await assert.rejects(pending); assert.equal(canceled, true);
 called = false; await assert.rejects(boundJSON(binding, '/fixed', {}, {signal: controller.signal})); assert.equal(called, false);
});
