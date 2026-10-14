import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const execute=promisify(execFile);
export const qualifiedCLI={version:'2.41.0',url:'https://downloads.1password.com/linux/debian/amd64/pool/main/1/1password-cli/1password-cli-2.41.0-1.amd64.deb',sha256:'0b7b215d46d7b425582e061a75f9e29a55e67bc04fe57a23deb33f5d20e8b99a'};
export function verifyPackage(bytes){if(!bytes.length||bytes.length>67108864||createHash('sha256').update(bytes).digest('hex')!==qualifiedCLI.sha256)throw Error('Qualified official CLI package digest differs');}
export async function installCLI({fetcher=fetch,runner=execute}={}) {
 if(process.platform!=='linux'||process.arch!=='x64')throw Error('Qualified CLI runtime requires Linux amd64');
 const response=await fetcher(qualifiedCLI.url,{redirect:'error',signal:AbortSignal.timeout(30000)});
 if(!response.ok)throw Error('Official CLI download failed');
 const reader=response.body.getReader(),chunks=[];let size=0;
 try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>67108864)throw Error('Official CLI download exceeds limit');chunks.push(value);}}finally{await reader.cancel().catch(()=>{});}
 const bytes=Buffer.concat(chunks);verifyPackage(bytes);
 const directory=await mkdtemp(join(tmpdir(),'qualified-op-'));const archive=join(directory,'op.deb');
 try{
  await writeFile(archive,bytes,{mode:0o600});
  const clean={PATH:process.env.PATH,LANG:'C.UTF-8'};
  await runner('dpkg-deb',['--extract',archive,directory],{env:clean,timeout:10000,maxBuffer:32768});
  const binary=join(directory,'usr/bin/op');const version=await runner(binary,['--version'],{env:clean,encoding:'utf8',timeout:10000,maxBuffer:32768});
  if(version.stdout.trim()!==qualifiedCLI.version)throw Error('Official CLI version differs');
  return {binary,config:join(directory,'config'),cleanup:()=>rm(directory,{recursive:true,force:true})};
 }catch(error){await rm(directory,{recursive:true,force:true});throw error;}
}
