import {canonical, digest, base64, putArchive, promotionPayload} from './ledger.mjs';
const utf8 = new TextEncoder();
const sha = /^[a-f0-9]{40}$/;
const hash = /^[a-f0-9]{64}$/;
const fail = message => { throw new Error(message); };
const bytes = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
const domains = {owner:'repoctl-promotion-owner-v1\n', validator:'repoctl-promotion-validator-v1\n'};
export function validateIntent(p, policy, now = Date.now()) {
  const fields = ['repositoryID','sequence','previousDigest','baseSHA','commitSHA','sourceSHA','treeSHA','policyDigest','evidenceDigest','archiveDigests','nonce','expiresAt'];
  if (!p || Object.keys(p).sort().join() !== fields.sort().join()) fail('Invalid intent schema');
  promotionPayload(p);
  if (!sha.test(p.treeSHA) || !/^[a-f0-9]{64}$/.test(p.nonce) || !Number.isSafeInteger(p.expiresAt)) fail('Invalid tree, nonce or expiry');
  if (p.repositoryID !== policy.repositoryID || p.policyDigest !== policy.policyDigest) fail('Wrong repository/policy');
  if (p.baseSHA === p.commitSHA || !p.archiveDigests.length || new Set(p.archiveDigests).size !== p.archiveDigests.length) fail('Missing archive or unchanged candidate');
  if (p.expiresAt <= now || p.expiresAt > now + policy.maxIntentTTL * 1000) fail('Expired or excessive intent lifetime');
  return p;
}
// Apple Security produces ASN.1 DER ECDSA signatures; WebCrypto expects r||s.
export function derToRaw(signature) {
  const d = bytes(signature); let i = 0;
  if (d[i++] !== 0x30 || d[i++] !== d.length - 2) fail('Invalid DER sequence');
  const out = new Uint8Array(64);
  for (let n=0;n<2;n++) {
    if (d[i++] !== 0x02) fail('Invalid DER integer');
    const length = d[i++]; let value = d.slice(i,i+length); i += length;
    if (!length || length>33 || value.length !== length || (value[0]&128)) fail('Invalid DER integer size/sign');
    if (length>1 && value[0]===0) { if (!(value[1]&128)) fail('Noncanonical DER integer'); value=value.slice(1); }
    if (value.length>32) fail('Oversized DER integer');
    out.set(value, n*32 + 32-value.length);
  }
  if (i!==d.length) fail('Trailing DER data');
  return out;
}
export async function verifyApproval(envelope, role, trustedKeys) {
  if (!envelope || Object.keys(envelope).sort().join() !== ['protocol','keyID','encoding','payload','signature'].sort().join()) fail('Invalid approval schema');
  if (!domains[role] || envelope?.protocol !== domains[role].trim() || !['p1363','der'].includes(envelope.encoding)) fail('Wrong approval domain/encoding');
  const key = trustedKeys.get(envelope.keyID);
  if (!key || typeof envelope.payload !== 'string' || envelope.payload.length>24000) fail('Unknown signer or oversized approval');
  const payload = bytes(envelope.payload);
  const signed = new Uint8Array(utf8.encode(domains[role]).length + payload.length);
  signed.set(utf8.encode(domains[role])); signed.set(payload,utf8.encode(domains[role]).length);
  const signature = envelope.encoding === 'der' ? derToRaw(envelope.signature) : bytes(envelope.signature);
  if (!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,signature,signed)) fail('Invalid approval signature');
  return {intent:JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(payload)),payload:envelope.payload};
}
export async function signApprovalPayload(payload, role, keyID, key) {
  if (!domains[role] || typeof payload!=='string' || payload.length>24000) fail('Unknown role or oversized payload');
  const raw=bytes(payload);
  JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
  const message=new Uint8Array(utf8.encode(domains[role]).length+raw.length);
  message.set(utf8.encode(domains[role]));message.set(raw,utf8.encode(domains[role]).length);
  const signature=base64(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,message));
  return {protocol:domains[role].trim(),keyID,encoding:'p1363',payload,signature};
}
export async function signApproval(intent, role, keyID, key) {
  return signApprovalPayload(base64(utf8.encode(canonical(intent))),role,keyID,key);
}
export async function checkCandidate(github, p) {
  const candidate=await github.commit(p.commitSHA);
  if (candidate.sha !== p.commitSHA || candidate.parents?.length !== 1 || candidate.parents[0].sha !== p.baseSHA || candidate.tree?.sha !== p.treeSHA || candidate.verification?.verified !== true) fail('Candidate is not a verified, signed, single-child commit with approved tree');
  const source=await github.commit(p.sourceSHA);
  if (source.sha !== p.sourceSHA) fail('Source commit unavailable');
}
// Call only inside one repository's serialized Durable Object. Adapters are
// installed trusted code, never supplied by request/candidate data.
export async function promote({owner,validator}, services, policy, now=Date.now()) {
  if ([...policy.ownerKeys.keys()].some(k=>policy.validatorKeys.has(k))) fail('Owner and validator key identities must be distinct');
  const ownerPublic=await Promise.all([...policy.ownerKeys.values()].map(async k=>base64(await crypto.subtle.exportKey('raw',k))));
  for (const key of policy.validatorKeys.values()) if(ownerPublic.includes(base64(await crypto.subtle.exportKey('raw',key)))) fail('Owner and validator cannot share a public key');
  const a=await verifyApproval(owner,'owner',policy.ownerKeys);
  const b=await verifyApproval(validator,'validator',policy.validatorKeys);
  if (a.payload!==b.payload) fail('Approvals bind different intent bytes');
  const p=a.intent;
  const id=await digest({owner,validator});
  const previous=await services.state.get('pending');
  if (previous && previous.id!==id) fail('Unreconciled promotion blocks new requests');
  // A completed exact request is idempotent, even after its authorization expires.
  const complete=await services.state.get(`complete:${id}`);
  if (complete) return complete;
  if (!previous) validateIntent(p,policy,now);
  else {
    // Keep schema/policy binding, but permit finalization after a prior ref write.
    validateIntent(p,policy,Math.min(now,p.expiresAt-1));
  }
  const checkpoint=await services.checkpoint.read();
  const anchored=checkpoint.repositoryID===p.repositoryID && checkpoint.sequence+1===p.sequence && checkpoint.digest===p.previousDigest && checkpoint.commitSHA===p.baseSHA;
  const finalized=previous && checkpoint.repositoryID===p.repositoryID && checkpoint.sequence===p.sequence && checkpoint.commitSHA===p.commitSHA && checkpoint.intentID===id;
  if (!anchored && !finalized) fail('Ledger checkpoint mismatch');
  const used=await services.state.get(`nonce:${p.nonce}`);
  if (used && used!==id) fail('Intent nonce already used');
  await checkCandidate(services.github,p);
  const tip=await services.github.tip();
  if (tip!==p.baseSHA && !(previous && tip===p.commitSHA)) fail('Main changed; create and approve a new generation');
  // Independent archive verifier must read and verify reconstructable Git objects,
  // not merely accept a list of hashes. No adapter => no promotion.
  await services.archive.verifyObjects(p);
  await services.evidence.verify(p);
  if (!previous) {
    await services.state.put('pending',{id,intent:p,owner,validator});
  }
  await services.state.put(`nonce:${p.nonce}`,id);
  await putArchive(services.receipts,`promotion-intents/${p.repositoryID}/${id}.json`,{owner,validator});
  if (tip===p.baseSHA) {
    if (p.expiresAt<=now) fail('Expired before ref update');
    // Exactly one write operation; never force, never create a tree/commit here.
    await services.github.advance(p.commitSHA);
  }
  if (await services.github.tip()!==p.commitSHA) fail('Ref update did not reconcile to approved candidate');
  const receipt=await services.ledger.append(promotionPayload(p),id);
  const result={state:'promoted',intentID:id,commitSHA:p.commitSHA,receipt};
  // Checkpoint/ledger adapter must commit idempotently; storage transaction makes
  // completed + cleared-pending atomic. Interrupted writes leave recoverable intent.
  await services.state.transaction(async tx=>{await tx.put(`complete:${id}`,result);await tx.delete('pending');});
  return result;
}
