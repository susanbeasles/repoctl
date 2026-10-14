import test from 'node:test';
import assert from 'node:assert/strict';
import {accessIdentity} from '../src/operator/identity.ts';
const key = await crypto.subtle.generateKey({name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1])}, true, ['sign', 'verify']);
const publicKey = {...await crypto.subtle.exportKey('jwk', key.publicKey), kid: 'access-key', alg: 'RS256', use: 'sig'};
const configuration = {issuer: 'https://personal-fixture.cloudflareaccess.com', audience: 'a'.repeat(64), subject: '12345678-1234-1234-1234-123456789abc', ownerID: 7};
const claims = {iss: configuration.issuer, aud: [configuration.audience], sub: configuration.subject, type: 'app', iat: 990, nbf: 990, exp: 1100};
const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
async function token(payload = claims, header: unknown = {alg: 'RS256', kid: 'access-key', typ: 'JWT'}) {
 const value = encode(header)+'.'+encode(payload);
 return value+'.'+Buffer.from(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key.privateKey, new TextEncoder().encode(value))).toString('base64url');
}
test('Access identity verifies actual RSA signature and exact independent session proof without exporting token', async () => {
 let reads = 0, proofs = 0;
 const verifier = accessIdentity({...configuration, clock: () => 1000, fetcher: async (url, options) => {reads++; assert.equal(url, configuration.issuer+'/cdn-cgi/access/certs'); assert.equal(options?.redirect, 'manual'); assert.ok(!new Headers(options?.headers).has('Authorization')); return Response.json({keys: [publicKey]});}, sessions: {verify: async binding => {proofs++; assert.equal(binding.tokenDigest.length, 64); return {...binding, active: true, revoked: false, validUntil: 1020};}}});
 assert.deepEqual(await verifier.verify(await token()), {ownerID: 7, authorized: true}); assert.equal(reads, 1); assert.equal(proofs, 1);
});
test('wrong issuer audience subject type lifetime and attacker key headers cannot select trust', async () => {
 let reads = 0;
 const verifier = accessIdentity({...configuration, clock: () => 1000, fetcher: async () => {reads++; return Response.json({keys: [publicKey]});}, sessions: {verify: async binding => ({...binding, active: true, revoked: false, validUntil: 1020})}});
 for (const changes of [{iss: 'https://foreign.cloudflareaccess.com'}, {aud: ['b'.repeat(64)]}, {aud: [configuration.audience, 'b'.repeat(64)]}, {sub: ''}, {sub: 'foreign'}, {type: 'org'}, {exp: 999}, {iat: 1001}, {nbf: 1001}, {exp: 5000}]) await assert.rejects(verifier.verify(await token({...claims, ...changes})), /^Error: Operator identity denied$/);
 await assert.rejects(verifier.verify(await token(claims, {alg: 'RS256', kid: 'access-key', jku: 'https://attacker.example'})), /identity denied/);
 assert.equal(reads, 0);
});
test('ambiguous keys invalid signature revoked and foreign session proofs deny', async () => {
 for (const keys of [[publicKey, publicKey], [{...publicKey, alg: 'HS256'}], [{...publicKey, d: 'private'}]]) {
  let proofs = 0;
  const verifier = accessIdentity({...configuration, clock: () => 1000, fetcher: async () => Response.json({keys}), sessions: {verify: async binding => {proofs++; return {...binding, active: true, revoked: false, validUntil: 1020};}}});
  await assert.rejects(verifier.verify(await token()), /identity denied/); assert.equal(proofs, 0);
 }
 for (const change of [{revoked: true}, {active: false}, {ownerID: 8}, {tokenDigest: 'b'.repeat(64)}, {validUntil: 1000}, {validUntil: 1031}]) {
  const verifier = accessIdentity({...configuration, clock: () => 1000, fetcher: async () => Response.json({keys: [publicKey]}), sessions: {verify: async binding => ({...binding, active: true, revoked: false, validUntil: 1020, ...change})}});
  await assert.rejects(verifier.verify(await token()), /identity denied/);
 }
 const verifier = accessIdentity({...configuration, clock: () => 1000, fetcher: async () => Response.json({keys: [publicKey]}), sessions: {verify: async binding => ({...binding, active: true, revoked: false, validUntil: 1020})}});
 const signed = await token(); const pieces = signed.split('.'); pieces[1] = encode({...claims, email: 'tampered@example.com'});
 await assert.rejects(verifier.verify(pieces.join('.')), /identity denied/);
});

test('redirect oversized trust stalled reads and expiry during verification deny without session authority', async () => {
 let proofs = 0;
 const sessions = {verify: async (binding: {issuer: string; audience: string; subject: string; ownerID: number; tokenDigest: string; expiresAt: number}) => {proofs++; return {...binding, active: true, revoked: false, validUntil: 1020};}};
 for (const response of [new Response(null, {status: 302, headers: {Location: 'https://attacker.example'}}), new Response('x'.repeat(65537))]) {
  const verifier = accessIdentity({...configuration, clock: () => 1000, fetcher: async () => response, sessions});
  await assert.rejects(verifier.verify(await token()), /identity denied/);
 }
 let signal: AbortSignal | undefined;
 const stalled = accessIdentity({...configuration, clock: () => 1000, timeoutMS: 100, fetcher: async (_url, options) => {signal = options?.signal as AbortSignal; return await new Promise(() => {});}, sessions});
 await assert.rejects(stalled.verify(await token()), /identity denied/); assert.equal(signal?.aborted, true); assert.equal(proofs, 0);
 let now = 1000;
 const expired = accessIdentity({...configuration, clock: () => now, fetcher: async () => Response.json({keys: [publicKey]}), sessions: {verify: async binding => {now = 1100; return {...binding, active: true, revoked: false, validUntil: 1120};}}});
 await assert.rejects(expired.verify(await token()), /identity denied/);
});
