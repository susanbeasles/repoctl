// Extracted public verification primitives; source lineage in CENTRAL-DEPLOYMENT.md.
const utf8=new TextEncoder();const fail=message=>{throw Error(message);};const bytes=value=>Uint8Array.from(atob(value),c=>c.charCodeAt(0));const domains={owner:'repoctl-promotion-owner-v1\n',validator:'repoctl-promotion-validator-v1\n'};
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
