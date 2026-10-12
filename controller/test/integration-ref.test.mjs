import test from 'node:test';
import assert from 'node:assert/strict';
import {integrationRef,isIntegrationRef} from '../src/source-signing/integration-ref.mjs';
test('fixed ref mapping rejects URL fragments and ambiguous encoded path names',()=>{
 for(const name of ['feature/ticket#fragment','feature/%2fmain','feature/ticket?query','feature/../main','feature/.hidden','feature/end.lock','feature//double','int/feature/ticket','main'])assert.throws(()=>integrationRef('refs/heads/'+name),name);
 assert.equal(integrationRef('refs/heads/feature/ticket.0123'),'refs/heads/int/feature/ticket.0123');assert.equal(isIntegrationRef('refs/heads/int/int/foo'),false);
});
