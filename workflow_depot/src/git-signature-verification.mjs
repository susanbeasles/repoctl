import {createHash} from 'node:crypto';
function fingerprint(blob){return 'SHA256:'+createHash('sha256').update(blob).digest('base64').replace(/=+$/,'');}
function sshString(raw,offset){if(offset+4>raw.length)throw Error('Malformed SSH signature');const size=raw.readUInt32BE(offset);if(size>16384||offset+4+size>raw.length)throw Error('Malformed SSH signature');return {value:raw.subarray(offset+4,offset+4+size),next:offset+4+size};}
export function signatureKeyID(signature){
 if(typeof signature!=='string'||signature.length>16384||!/^-----BEGIN SSH SIGNATURE-----\n(?:[A-Za-z0-9+/=]+\n)+-----END SSH SIGNATURE-----\n?$/.test(signature))throw Error('Invalid SSH signature armor');
 const encoded=signature.split('\n').slice(1,-(signature.endsWith('\n')?2:1)).join(''),raw=Buffer.from(encoded,'base64');
 if(raw.toString('base64')!==encoded||raw.subarray(0,6).toString()!=='SSHSIG'||raw.readUInt32BE(6)!==1)throw Error('Invalid SSH signature wire data');
 let field=sshString(raw,10);const key=field.value;field=sshString(raw,field.next);if(field.value.toString()!=='git')throw Error('Wrong SSH signing namespace');field=sshString(raw,field.next);if(field.value.length)throw Error('Unsupported SSH signature reserved data');field=sshString(raw,field.next);if(!['sha256','sha512'].includes(field.value.toString()))throw Error('Unsupported SSH signature hash');field=sshString(raw,field.next);if(field.next!==raw.length)throw Error('Trailing SSH signature data');return fingerprint(key);
}

import {execFile} from 'node:child_process';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';import {join} from 'node:path';
export async function verifyGitSignature({payload,signature,keyID,verifierSHA256}) {
  if(typeof payload!=='string'||Buffer.byteLength(payload)>32768||signatureKeyID(signature)!==keyID||!/^[a-f0-9]{64}$/.test(verifierSHA256??'')) throw Error('Git proof denied');
  const executable='/usr/bin/ssh-keygen';
  if(createHash('sha256').update(await readFile(executable)).digest('hex')!==verifierSHA256) throw Error('Git verifier executable pin mismatch');
  const dir=await mkdtemp(join(tmpdir(),'deployment-git-proof-'));
  try {
    const path=join(dir,'signature');await writeFile(path,signature,{mode:0o600});
    // check-novalidate verifies the exact embedded public key; signatureKeyID
    // above separately enforces the independently approved fingerprint.
    await new Promise((resolve,reject)=>{const child=execFile(executable,['-Y','check-novalidate','-n','git','-s',path],{env:{PATH:'/usr/bin:/bin',LANG:'C'},timeout:10000,maxBuffer:16384},error=>error?reject(Error('Git proof denied')):resolve());child.stdin.end(payload);});
    return true;
  } finally {await rm(dir,{recursive:true,force:true});}
}
