const encoder = new TextEncoder();
export function canonical(value) {
  // Protocol-specific encoding, not a claim of RFC 8785 compliance.
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype)
    return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  throw new Error('Unsupported ledger value');
}
export async function digest(value) {
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(canonical(value))))].map(b => b.toString(16).padStart(2, '0')).join('');
}
export function base64(bytes) { return btoa(String.fromCharCode(...new Uint8Array(bytes))); }
function bytes(value) { return Uint8Array.from(atob(value), c => c.charCodeAt(0)); }
export async function signEntry(payload, keyID, privateKey) {
  const body = {protocol: 'repoctl-ledger-v1', algorithm: 'ECDSA-P256-SHA256', keyID, payload};
  const signature = base64(await crypto.subtle.sign({name:'ECDSA', hash:'SHA-256'}, privateKey, encoder.encode(canonical(body))));
  const envelope = {...body, signature};
  return {envelope, digest: await digest(envelope)};
}
export async function verifyEntry(entry, trustedKeys) {
  if (entry.protocol !== 'repoctl-ledger-v1' || entry.algorithm !== 'ECDSA-P256-SHA256') throw new Error('Unsupported ledger protocol');
  const key = trustedKeys.get(entry.keyID);
  if (!key) throw new Error('Unknown ledger signer');
  const {signature, ...body} = entry;
  if (!await crypto.subtle.verify({name:'ECDSA', hash:'SHA-256'}, key, bytes(signature), encoder.encode(canonical(body)))) throw new Error('Invalid ledger signature');
  return digest(entry);
}
export function promotionPayload({repositoryID, sequence, previousDigest, baseSHA, commitSHA, sourceSHA, policyDigest, evidenceDigest, archiveDigests}) {
  const sha = /^[a-f0-9]{40}$|^[a-f0-9]{64}$/;
  if (!Number.isSafeInteger(repositoryID) || repositoryID <= 0 || !Number.isSafeInteger(sequence) || sequence < 1) throw new Error('Invalid repository/sequence');
  for (const value of [baseSHA, commitSHA, sourceSHA]) if (!sha.test(value)) throw new Error('Invalid Git object ID');
  for (const value of [previousDigest, policyDigest, evidenceDigest, ...archiveDigests]) if (!/^[a-f0-9]{64}$/.test(value)) throw new Error('Invalid archive/evidence digest');
  return {kind:'promotion', repositoryID, sequence, previousDigest, baseSHA, commitSHA, sourceSHA, policyDigest, evidenceDigest, archiveDigests};
}
export async function verifyChain(entries, trustedKeys, anchor) {
  // Anchor is independently retained, not supplied by the untrusted archive.
  let sequence = anchor.startSequence ?? 0, previous = anchor.startDigest;
  let tip = anchor.startCommit;
  for (const entry of entries) {
    const hash = await verifyEntry(entry, trustedKeys);
    const p = entry.payload;
    if (p.kind !== 'promotion' || p.repositoryID !== anchor.repositoryID || p.sequence !== sequence + 1 || p.previousDigest !== previous || p.baseSHA !== tip) throw new Error('Broken ledger continuity');
    promotionPayload(p);
    sequence = p.sequence; previous = hash; tip = p.commitSHA;
  }
  if (sequence !== anchor.endSequence || previous !== anchor.endDigest || tip !== anchor.endCommit) throw new Error('Ledger does not match trusted checkpoint');
  return {sequence, digest:previous, commitSHA:tip};
}
export async function putArchive(bucket, key, value) {
  const data = encoder.encode(canonical(value));
  const existing = await bucket.get(key);
  if (existing) {
    if (await existing.text() !== new TextDecoder().decode(data)) throw new Error('Archive key collision');
    return;
  }
  const result = await bucket.put(key, data, {onlyIf:{etagDoesNotMatch:'*'}, httpMetadata:{contentType:'application/json'}});
  if (!result) throw new Error('Concurrent archive creation; retry reconciliation');
  const stored = await bucket.get(key);
  if (!stored || await stored.text() !== new TextDecoder().decode(data)) throw new Error('Archive verification failed');
}
