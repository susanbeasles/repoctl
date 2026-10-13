import {inflateRawSync} from 'node:zlib';
import {createHash} from 'node:crypto';
const limit=7*1024*1024;
const fail=()=>{throw Error('Deployment artifact unavailable or invalid');};
const need=v=>{if(!v)fail();};
const crc32=bytes=>{let crc=0xffffffff;for(const byte of bytes){crc^=byte;for(let i=0;i<8;i++)crc=(crc>>>1)^((crc&1)?0xedb88320:0);}return (crc^0xffffffff)>>>0;};
export function decodeBundleArchive(input) {
  const b=Buffer.from(input);need(b.length>=22&&b.length<=limit);
  // GitHub artifacts are ordinary ZIPs. Reject ZIP64, split archives, additional
  // files, traversal, links, encrypted members and decompression bombs.
  let end=-1;for(let i=b.length-22;i>=Math.max(0,b.length-65557);i--)if(b.readUInt32LE(i)===0x06054b50&&i+22+b.readUInt16LE(i+20)===b.length){end=i;break;}
  need(end>=0&&b.readUInt16LE(end+4)===0&&b.readUInt16LE(end+6)===0&&b.readUInt16LE(end+8)===1&&b.readUInt16LE(end+10)===1);
  const offset=b.readUInt32LE(end+16),size=b.readUInt32LE(end+12);need(offset+size===end&&offset+46<=end&&b.readUInt32LE(offset)===0x02014b50);
  const flags=b.readUInt16LE(offset+8),method=b.readUInt16LE(offset+10),crc=b.readUInt32LE(offset+16),packed=b.readUInt32LE(offset+20),unpacked=b.readUInt32LE(offset+24),names=b.readUInt16LE(offset+28),extras=b.readUInt16LE(offset+30),comments=b.readUInt16LE(offset+32),local=b.readUInt32LE(offset+42),mode=b.readUInt32LE(offset+38)>>>16;
  need((flags&~0x808)===0&&[0,8].includes(method)&&unpacked>0&&unpacked<=limit&&packed<=limit&&offset+46+names+extras+comments===end&&[0,0x8000].includes(mode&0xf000));
  const name=b.subarray(offset+46,offset+46+names).toString('utf8');need(name==='deployment-bundle.json'&&local+30<=offset&&b.readUInt32LE(local)===0x04034b50&&b.readUInt16LE(local+6)===flags&&b.readUInt16LE(local+8)===method);
  const localNames=b.readUInt16LE(local+26),localExtra=b.readUInt16LE(local+28),start=local+30+localNames+localExtra;
  need(localNames===names&&b.subarray(local+30,local+30+names).toString('utf8')===name&&start+packed<=offset);
  const bytes=method===0?b.subarray(start,start+packed):inflateRawSync(b.subarray(start,start+packed),{maxOutputLength:limit});
  need(bytes.length===unpacked&&crc32(bytes)===crc);
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
}
async function bounded(response){need(response.ok&&response.body);const reader=response.body.getReader(),chunks=[];let total=0;try{for(;;){const {value,done}=await reader.read();if(done)break;total+=value.length;need(total<=limit);chunks.push(value);}}finally{await reader.cancel().catch(()=>{});reader.releaseLock();}return Buffer.concat(chunks);}
export async function loadGitHubBundle({source,api,token,fetcher=fetch}) {
  need(typeof token==='string'&&token.length&&/^[a-z0-9-]+$/.test(source.target));
  const name=`deployment-${source.sha}-${source.target}`;
  const result=await api.request(`/repos/${source.repository}/actions/artifacts?name=${name}&per_page=100`);
  need(result?.total_count===1&&result.artifacts?.length===1);
  const a=result.artifacts[0];
  need(a.name===name&&a.expired===false&&Number.isSafeInteger(a.id)&&a.id>0&&a.size_in_bytes>0&&a.size_in_bytes<=limit&&/^sha256:[a-f0-9]{64}$/.test(a.digest??'')&&a.workflow_run?.head_sha===source.sha&&a.workflow_run.repository_id===source.repositoryID&&a.workflow_run.head_repository_id===source.repositoryID);
  const response=await fetcher(`https://api.github.com/repos/${source.repository}/actions/artifacts/${a.id}/zip`,{redirect:'manual',signal:AbortSignal.timeout(30000),headers:{Authorization:`Bearer ${token}`,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2026-03-10'}});
  need(response.status===302);
  const location=new URL(response.headers.get('location'));await response.body?.cancel();
  need(location.protocol==='https:'&&!location.username&&!location.password&&!location.hash&&(location.hostname.endsWith('.blob.core.windows.net')||location.hostname.endsWith('.githubusercontent.com')));
  // Signed download URL receives no GitHub or Cloudflare Authorization header.
  const bytes=await bounded(await fetcher(location.href,{redirect:'error',signal:AbortSignal.timeout(30000)}));
  need(`sha256:${createHash('sha256').update(bytes).digest('hex')}`===a.digest);
  const bundle=decodeBundleArchive(bytes);
  need(bundle?.schema==='deployment-workflow-bundle/v1'&&bundle.provenance?.runID===a.workflow_run.id);
  return bundle;
}
