// Used only by an isolated remote signer service after verified remote enrollment.
// CryptoKey stays non-extractable. This is not a public general-purpose signing API.
const encoder=new TextEncoder();
const concat=(...parts)=>{const r=new Uint8Array(parts.reduce((n,p)=>n+p.length,0));let i=0;for(const p of parts){r.set(p,i);i+=p.length;}return r;};
const derLength=n=>n<128?new Uint8Array([n]):n<256?new Uint8Array([0x81,n]):new Uint8Array([0x82,n>>8,n&255]);
const der=(tag,value)=>concat(new Uint8Array([tag]),derLength(value.length),value);
const url64=bytes=>btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
export async function importAppPrivateKey(pem) {
 if(typeof pem!=='string'||pem.length>12000)throw Error('Invalid remote App key');
 const match=pem.match(/^-----BEGIN (RSA PRIVATE KEY|PRIVATE KEY)-----\s+([A-Za-z0-9+/=\s]+)-----END \1-----\s*$/);
 if(!match)throw Error('Unsupported App key encoding');
 let raw=Uint8Array.from(atob(match[2].replace(/\s/g,'')),c=>c.charCodeAt(0));
 // GitHub manifest PEM is commonly PKCS#1; WebCrypto imports PKCS#8.
 if(match[1]==='RSA PRIVATE KEY'){
  const rsaIdentifier=new Uint8Array([0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00]);
  raw=der(0x30,concat(new Uint8Array([0x02,0x01,0x00]),rsaIdentifier,der(0x04,raw)));
 }
 const key=await crypto.subtle.importKey('pkcs8',raw,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['sign']);
 if(key.algorithm.modulusLength<2048)throw Error('Weak App key');return key;
}
export function appJWTSigner({appID,key,clock=()=>Math.floor(Date.now()/1000)}) {
 if(!Number.isSafeInteger(appID)||appID<=0||key?.type!=='private'||key.extractable||key.algorithm?.name!=='RSASSA-PKCS1-v1_5'||key.algorithm?.hash?.name!=='SHA-256'||!Number.isSafeInteger(key.algorithm?.modulusLength)||key.algorithm.modulusLength<2048)throw Error('Invalid enrolled remote signer');
 return async function sign(claims){
  const now=clock();
  if(!claims||Object.keys(claims).sort().join()!==['appID','issuedAt','expiresAt'].sort().join()||claims.appID!==appID||![claims.issuedAt,claims.expiresAt].every(Number.isSafeInteger)||Math.abs(claims.issuedAt-(now-60))>30||Math.abs(claims.expiresAt-(now+300))>30)throw Error('Signing request outside fixed App JWT policy');
  const header=url64(encoder.encode(JSON.stringify({alg:'RS256',typ:'JWT'})));
  // Ignore caller timing values after checking freshness; construct actual claims.
  const body=url64(encoder.encode(JSON.stringify({iss:String(appID),iat:now-60,exp:now+300})));
  const message=`${header}.${body}`;
  return `${message}.${url64(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',key,encoder.encode(message)))}`;
 };
}
