// Internal effect adapter only. The isolated signer host owns all configuration
// and independently authorizes each fixed object from its durable journal.
import {mkdtemp,readFile,writeFile,rm,realpath,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,isAbsolute} from 'node:path';
import {pinnedExecutable,runFixed} from './process.mjs';
import {sha256} from './core.mjs';
import {createHash} from 'node:crypto';

function fingerprint(blob){return 'SHA256:'+createHash('sha256').update(blob).digest('base64').replace(/=+$/,'');}
function sshString(raw,offset){if(offset+4>raw.length)throw Error('Malformed SSH signature');const size=raw.readUInt32BE(offset);if(size>16384||offset+4+size>raw.length)throw Error('Malformed SSH signature');return {value:raw.subarray(offset+4,offset+4+size),next:offset+4+size};}
export function signatureKeyID(signature){
 if(typeof signature!=='string'||signature.length>16384||!/^-----BEGIN SSH SIGNATURE-----\n(?:[A-Za-z0-9+/=]+\n)+-----END SSH SIGNATURE-----\n?$/.test(signature))throw Error('Invalid SSH signature armor');
 const encoded=signature.split('\n').slice(1,-(signature.endsWith('\n')?2:1)).join(''),raw=Buffer.from(encoded,'base64');
 if(raw.toString('base64')!==encoded||raw.subarray(0,6).toString()!=='SSHSIG'||raw.readUInt32BE(6)!==1)throw Error('Invalid SSH signature wire data');
 let field=sshString(raw,10);const key=field.value;field=sshString(raw,field.next);if(field.value.toString()!=='git')throw Error('Wrong SSH signing namespace');field=sshString(raw,field.next);if(field.value.length)throw Error('Unsupported SSH signature reserved data');field=sshString(raw,field.next);if(!['sha256','sha512'].includes(field.value.toString()))throw Error('Unsupported SSH signature hash');field=sshString(raw,field.next);if(field.next!==raw.length)throw Error('Trailing SSH signature data');return fingerprint(key);
}
export async function createInstalledGitSigner({program,programSHA256,verifierProgram,verifierSHA256,publicKeyPath,keyID,agentSocket,authorize}){
 if(typeof authorize!=='function'||!isAbsolute(publicKeyPath??'')||!isAbsolute(agentSocket??'')||/[\0\r\n]/.test(publicKeyPath+agentSocket))throw Error('Fixed existing signer and authority required');
 const signingProgram=await pinnedExecutable(program,programSHA256),verificationProgram=await pinnedExecutable(verifierProgram,verifierSHA256);
 const keyPath=await realpath(publicKeyPath),initial=await readFile(keyPath,'utf8');
 const parts=initial.trim().split(/\s+/);if(parts.length<2||parts.length>3||!parts[0].startsWith('ssh-')&&!parts[0].startsWith('ecdsa-')&&!parts[0].startsWith('sk-')||fingerprint(Buffer.from(parts[1],'base64'))!==keyID)throw Error('Existing public signer key differs');
 const info=await stat(keyPath);if(!info.isFile()||(info.mode&0o022)||initial.includes('PRIVATE KEY'))throw Error('Only a pinned public signing key is permitted');
 async function verifyGit({payload,signature}){
  if(signatureKeyID(signature)!==keyID)return false;
  await pinnedExecutable(verifierProgram,verifierSHA256);const directory=await mkdtemp(join(tmpdir(),'repoctl-git-verify-'));
  try{const path=join(directory,'signature');await writeFile(path,signature,{mode:0o600});await runFixed(verificationProgram,['-Y','check-novalidate','-n','git','-s',path],{input:payload,limit:8192});return true;}catch{return false;}finally{await rm(directory,{recursive:true,force:true});}
 }
 return Object.freeze({keyID,verifyGit,async signGit(input){
  if(!input||Object.keys(input).sort().join()!==['type','payload','authorization'].sort().join()||!['commit','tag'].includes(input.type)||typeof input.payload!=='string'||Buffer.byteLength(input.payload)>24000)throw Error('Invalid fixed Git object request');
  const auth=await authorize(structuredClone(input));if(auth?.authorized!==true||auth.keyID!==keyID||auth.objectDigest!==sha256(input.payload))throw Error('Independent signer authorization denied');
  await pinnedExecutable(program,programSHA256);if(await readFile(keyPath,'utf8')!==initial)throw Error('Pinned public signing key changed');
  const output=await runFixed(signingProgram,['-Y','sign','-U','-n','git','-f',keyPath],{input:input.payload,env:{SSH_AUTH_SOCK:agentSocket},limit:16384,timeoutMs:120000});
  const signature=output.toString('utf8');if(!await verifyGit({payload:input.payload,signature}))throw Error('Installed signer returned an unverified signature');return signature;
 }});
}
