export async function verifyWebhook(raw, header, secret) {
  if (!secret || !/^sha256=[a-f0-9]{64}$/.test(header ?? '')) return false;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), {name:'HMAC',hash:'SHA-256'}, false, ['verify']);
  const signature = Uint8Array.from(header.slice(7).match(/../g), v => parseInt(v,16));
  return crypto.subtle.verify('HMAC', key, signature, raw);
}
export function authorizeEvent(event, body, policy) {
  if (body.repository?.id !== policy.repositoryID || body.repository?.owner?.id !== policy.ownerID) return false;
  if (!policy.actorIDs.includes(body.sender?.id)) return false;
  if (body.repository?.fork === true) return false;
  if (['pull_request','pull_request_review'].includes(event)) {
    const pr = body.pull_request;
    if (!pr || pr.head?.repo?.id !== policy.repositoryID || pr.head?.repo?.fork === true) return false;
  }
  return ['push','pull_request','pull_request_review','check_run','check_suite'].includes(event);
}
