interface SessionBinding {
 readonly issuer: string; readonly audience: string; readonly subject: string;
 readonly ownerID: number; readonly tokenDigest: string; readonly expiresAt: number;
}
interface Options {
 readonly issuer: string; readonly audience: string; readonly subject: string; readonly ownerID: number;
 readonly sessions: {verify(binding: SessionBinding, options: {signal: AbortSignal}): Promise<SessionBinding & {active: boolean; revoked: boolean; validUntil: number}>};
 readonly fetcher?: typeof fetch; readonly clock?: () => number; readonly lifetime?: number; readonly timeoutMS?: number;
}
const encoder = new TextEncoder();
function decode(value: string): Uint8Array<ArrayBuffer> {
 if (!/^[A-Za-z0-9_-]+$/.test(value)) throw Error('Invalid identity encoding');
 const bytes = Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')+'='.repeat((4-value.length%4)%4)), c => c.charCodeAt(0));
 const canonical = btoa(String.fromCharCode(...bytes)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
 if (canonical !== value) throw Error('Invalid identity encoding');
 return bytes;
}
function json(value: string): Record<string, unknown> {
 const result: unknown = JSON.parse(new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(decode(value)));
 if (!result || typeof result !== 'object' || Array.isArray(result)) throw Error('Invalid identity claims');
 return result as Record<string, unknown>;
}
// Fixed Access issuer/application/user mapping; no JWT-selected trust URL or email mapping.
// Signed application JWTs establish identity only after independent session revocation proof.
export function accessIdentity({issuer, audience, subject, ownerID, sessions, fetcher = fetch, clock = () => Math.floor(Date.now()/1000), lifetime = 3600, timeoutMS = 10000}: Options) {
 if (!/^https:\/\/[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.cloudflareaccess\.com$/.test(issuer) || !/^[a-f0-9]{64}$/.test(audience) || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(subject) || !Number.isSafeInteger(ownerID) || ownerID < 1 || typeof sessions?.verify !== 'function' || !Number.isSafeInteger(lifetime) || lifetime < 60 || lifetime > 86400 || !Number.isSafeInteger(timeoutMS) || timeoutMS < 100 || timeoutMS > 10000) throw Error('Invalid Access identity configuration');
 return {async verify(assertion: unknown, options: {signal?: AbortSignal} = {}) {
  const controller = new AbortController(), external = options.signal;
  const cancel = () => controller.abort();
  if (external?.aborted) controller.abort(); else external?.addEventListener('abort', cancel, {once: true});
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
   const job = async () => {
    controller.signal.throwIfAborted();
    if (typeof assertion !== 'string' || assertion.length > 16000) throw Error('Invalid assertion');
    const parts = assertion.split('.'); if (parts.length !== 3) throw Error('Invalid assertion');
    const header = json(parts[0]), claims = json(parts[1]);
    if (header.alg !== 'RS256' || typeof header.kid !== 'string' || header.kid.length < 1 || header.kid.length > 256 || Object.keys(header).some(k => !['alg', 'kid', 'typ'].includes(k)) || (header.typ !== undefined && header.typ !== 'JWT')) throw Error('Invalid identity algorithm');
    const now = clock(); if (!Number.isSafeInteger(now)) throw Error('Invalid identity time');
    if (claims.iss !== issuer || !Array.isArray(claims.aud) || claims.aud.length !== 1 || claims.aud[0] !== audience || claims.sub !== subject || claims.type !== 'app' || ![claims.iat, claims.nbf, claims.exp].every(Number.isSafeInteger) || (claims.iat as number) > now || (claims.nbf as number) > now || (claims.exp as number) <= now || (claims.exp as number) <= (claims.iat as number) || (claims.exp as number)-(claims.iat as number) > lifetime) throw Error('Invalid Access identity claims');
    const response = await fetcher(issuer+'/cdn-cgi/access/certs', {redirect: 'manual', headers: {'Cache-Control': 'no-cache'}, signal: controller.signal});
    if (response.status !== 200 || !response.body) throw Error('Identity trust unavailable');
    const reader = response.body.getReader(), chunks: Uint8Array[] = []; let size = 0;
    try {for (;;) {const r = await reader.read(); controller.signal.throwIfAborted(); if (r.done) break; size += r.value.length; if (size > 65536) throw Error('Oversized identity trust'); chunks.push(r.value);}} finally {void reader.cancel().catch(() => {});}
    const raw = new Uint8Array(size); let offset = 0; for (const chunk of chunks) {raw.set(chunk, offset); offset += chunk.length;}
    const inventory = JSON.parse(new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(raw));
    if (!Array.isArray(inventory.keys) || inventory.keys.length > 32) throw Error('Invalid identity trust');
    const matches = inventory.keys.filter((k: Record<string, unknown>) => k && k.kid === header.kid);
    if (matches.length !== 1) throw Error('Ambiguous identity key');
    const jwk = matches[0];
    if (jwk.kty !== 'RSA' || jwk.alg !== 'RS256' || jwk.use !== 'sig' || ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'].some(k => k in jwk)) throw Error('Invalid identity key');
    const key = await crypto.subtle.importKey('jwk', jwk, {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256'}, false, ['verify']);
    if ((key.algorithm as {modulusLength: number}).modulusLength < 2048 || !await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, decode(parts[2]), encoder.encode(parts[0]+'.'+parts[1]))) throw Error('Invalid identity signature');
    controller.signal.throwIfAborted();
    const tokenDigest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(assertion))), b => b.toString(16).padStart(2, '0')).join('');
    const binding = Object.freeze({issuer, audience, subject, ownerID, tokenDigest, expiresAt: claims.exp as number});
    const proof = await sessions.verify(binding, {signal: controller.signal});
    controller.signal.throwIfAborted(); const final = clock();
    if (!Number.isSafeInteger(final) || final >= binding.expiresAt || proof.active !== true || proof.revoked !== false || Object.entries(binding).some(([k, v]) => proof[k as keyof typeof proof] !== v) || !Number.isSafeInteger(proof.validUntil) || proof.validUntil <= final || proof.validUntil > final+30 || proof.validUntil > binding.expiresAt) throw Error('Current operator session unavailable');
    return Object.freeze({ownerID, authorized: true});
   };
   return await Promise.race([job(), new Promise<never>((_, reject) => {timer = setTimeout(() => {controller.abort(); reject(Error('Identity timeout'));}, timeoutMS);})]);
  } catch {throw Error('Operator identity denied');}
  finally {clearTimeout(timer); controller.abort(); external?.removeEventListener('abort', cancel);}
 }};
}
