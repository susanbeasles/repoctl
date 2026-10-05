#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
swift build
bin="$(swift build --show-bin-path)/repoctl"
scratch=$(mktemp -d)
printf '{"repository":"example/demo","revision":1}\n' > "$scratch/policy.json"
"$bin" policy seal "$scratch/policy.json" --provider keychain --approve
"$bin" approval key "$scratch/policy.json" > "$scratch/public.json"
node --input-type=module - "$scratch" <<'JS'
import {writeFileSync,readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
const dir=process.argv[2];
const body={operationID:'a'.repeat(64),approvalDigest:'b'.repeat(64),repositoryID:7,repository:'example/demo',targetRef:'refs/heads/main',policyRevision:1,policyDigest:createHash('sha256').update(readFileSync(dir+'/policy.json')).digest('hex'),executorTrustDigest:'c'.repeat(64),runID:60,runAttempt:1,expiresAt:Math.floor(Date.now()/1000)+200};
writeFileSync(dir+'/run.json',JSON.stringify(body,null,2)+'\n');
writeFileSync(dir+'/expired.json',JSON.stringify({...body,expiresAt:1}));
JS
"$bin" approval sign-run "$scratch/run.json" --policy "$scratch/policy.json" --approve
node --input-type=module - "$scratch" <<'JS'
import {readFileSync} from 'node:fs';
import {createPublicKey,verify} from 'node:crypto';
import assert from 'node:assert/strict';
const dir=process.argv[2],info=JSON.parse(readFileSync(dir+'/public.json')),envelope=JSON.parse(readFileSync(dir+'/run.json.execution-approval.json'));
const raw=Buffer.from(info.publicKeyX963,'base64');assert.equal(raw.length,65);assert.equal(raw[0],4);
const key=createPublicKey({key:{kty:'EC',crv:'P-256',x:raw.subarray(1,33).toString('base64url'),y:raw.subarray(33).toString('base64url')},format:'jwk'});
const payload=Buffer.from(envelope.payload,'base64');assert.deepEqual(payload,readFileSync(dir+'/run.json'));assert.equal(envelope.protocol,'repoctl-execution-owner-v1');assert.equal(envelope.keyID,info.keyID);assert.equal(envelope.encoding,'der');
const signature=Buffer.from(envelope.signature,'base64');assert.equal(verify('sha256',Buffer.concat([Buffer.from('repoctl-execution-owner-v1\n'),payload]),key,signature),true);
assert.equal(verify('sha256',Buffer.concat([Buffer.from('repoctl-promotion-owner-v1\n'),payload]),key,signature),false);
console.log('PASS: macOS DER execution signature verifies independently and preserves exact bytes');
JS
if "$bin" approval sign-run "$scratch/expired.json" --policy "$scratch/policy.json" --approve; then
 echo 'Expired run approval accepted' >&2; exit 1
fi
test ! -e "$scratch/expired.json.execution-approval.json"
printf 'Test software enrollment retained at %s; no remote action performed\n' "$scratch"
