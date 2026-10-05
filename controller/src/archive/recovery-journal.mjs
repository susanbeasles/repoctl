import {realpath,lstat,open,link,unlink} from 'node:fs/promises';
import {join,isAbsolute} from 'node:path';
import {constants} from 'node:fs';
import {canonical} from '../ledger.mjs';
// Public signed evidence only. Signing keys and plaintext archives never enter.
export async function recoveryJournal(directory){
 if(!isAbsolute(directory??'')||await realpath(directory)!==directory)throw Error('Invalid journal directory');
 const st=await lstat(directory);if(!st.isDirectory()||(st.mode&0o077)!==0||st.uid!==process.getuid())throw Error('Recovery journal must be private and owned');
 const path=id=>{if(!/^[a-f0-9]{64}$/.test(id??''))throw Error('Invalid journal identity');return join(directory,id+'.json');};
 async function get(id){let f;try{f=await open(path(id),constants.O_RDONLY|constants.O_NOFOLLOW);const s=await f.stat();if(!s.isFile()||s.size>4*1024*1024||s.uid!==st.uid||(s.mode&0o077)!==0)throw Error('Invalid journal record');return JSON.parse(await f.readFile('utf8'));}catch(e){if(e.code==='ENOENT')return null;throw e;}finally{await f?.close();}}
 return {get,async retain(id,envelope){const target=path(id),temp=join(directory,crypto.randomUUID()+'.pending'),bytes=canonical(envelope);if(Buffer.byteLength(bytes)>4*1024*1024)throw Error('Journal record too large');let f;try{f=await open(temp,'wx',0o600);await f.writeFile(bytes);await f.sync();await f.close();f=null;try{await link(temp,target);}catch(e){if(e.code!=='EEXIST')throw e;}const dir=await open(directory,'r');try{await dir.sync();}finally{await dir.close();}return await get(id);}finally{await f?.close();await unlink(temp).catch(()=>{});}}};
}
