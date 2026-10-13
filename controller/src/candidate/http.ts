interface Context {signal: AbortSignal}
interface Binding {repositoryID: number; ownerID: number}
interface Lease extends Binding {id: string; token: string; expiresAt: number}
interface Credentials {acquire(binding: Readonly<Binding>,context: Context): Promise<Lease>; release(id: string,context: Context): Promise<void>}
interface Config extends Binding {repository: string; credentials: Credentials; fetcher?: typeof fetch; timeoutMS?: number}
const decode=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true});
function packet(bytes: Uint8Array,offset: number) {
 if(offset+4>bytes.length)throw Error('Invalid Git packet');
 const header=decode.decode(bytes.subarray(offset,offset+4));if(!/^[a-f0-9]{4}$/.test(header))throw Error('Invalid Git packet');
 const size=parseInt(header,16);if(size===0)return {text:'',next:offset+4,flush:true};
 if(size<5||offset+size>bytes.length)throw Error('Invalid Git packet');
 return {text:decode.decode(bytes.subarray(offset+4,offset+size)),next:offset+size,flush:false};
}
function discovery(bytes: Uint8Array,target: string) {
 let item=packet(bytes,0);if(item.text!=='# service=git-receive-pack\n')throw Error('Invalid Git service');
 item=packet(bytes,item.next);if(!item.flush)throw Error('Invalid Git discovery');
 item=packet(bytes,item.next);const split=item.text.indexOf('\0');
 if(item.flush||split<0||!/^[a-f0-9]{40} [^\s\0]+$/.test(item.text.slice(0,split)))throw Error('Invalid Git capabilities');
 const caps=item.text.slice(split+1).trimEnd().split(' ');
 if(!caps.includes('report-status')||caps.some(c=>c.startsWith('object-format=')&&c!=='object-format=sha1'))throw Error('Unsupported Git capabilities');
 if(item.text.slice(41,split)===target)throw Error('Generation exists');
 let offset=item.next;
 while(offset<bytes.length){item=packet(bytes,offset);offset=item.next;if(item.flush){if(offset!==bytes.length)throw Error('Invalid Git discovery');return;}
 const line=item.text.trimEnd();if(!/^[a-f0-9]{40} [^\s\0]+$/.test(line))throw Error('Invalid Git reference');if(line.slice(41)===target)throw Error('Generation exists');}
 throw Error('Incomplete Git discovery');
}
async function read(response: Response) {
 const reader=response.body?.getReader();if(!reader)throw Error('Missing Git response');
 const chunks: Uint8Array[]=[];let size=0;
 while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>65536){await reader.cancel();throw Error('Oversized Git response');}chunks.push(value);}
 const bytes=new Uint8Array(size);let offset=0;for(const value of chunks){bytes.set(value,offset);offset+=value.length;}return bytes;
}
// Installed scoped installation-token authority must retain leases before return
// and recover uncertain acquisition/cleanup independently. No caller URLs/tokens.
export function generationHTTP({repository,repositoryID,ownerID,credentials,fetcher=fetch,timeoutMS=10000}: Config) {
 if(!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)||repository.split('/').some(v=>v==='.'||v==='..')||![repositoryID,ownerID].every(v=>Number.isSafeInteger(v)&&v>0)||typeof credentials?.acquire!=='function'||typeof credentials?.release!=='function'||!Number.isSafeInteger(timeoutMS)||timeoutMS<100||timeoutMS>10000)throw Error('Invalid Git transport configuration');
 const root='https://github.com/'+repository+'.git';
 return {async send(input: Uint8Array,{signal}: Context): Promise<Uint8Array> {
 if(!(input instanceof Uint8Array)||input.length>256*1024*1024+1024)throw Error('Invalid Git transfer');
 const body=new Uint8Array(input),command=packet(body,0),flush=packet(body,command.next);
 const match=/^0{40} [a-f0-9]{40} (refs\/heads\/int\/[a-f0-9]{64})\0report-status\n$/.exec(command.text);
 if(!match||!flush.flush||decode.decode(body.subarray(flush.next,flush.next+4))!=='PACK')throw Error('Invalid Git create-only transfer');
 const control=new AbortController(),abort=()=>control.abort();signal.addEventListener('abort',abort,{once:true});if(signal.aborted)control.abort();
 let lease: Lease|undefined;const timer=setTimeout(abort,timeoutMS);
 async function bounded<T>(job: Promise<T>): Promise<T> {
 if(control.signal.aborted){void job.catch(()=>{});throw Error('Git transport cancelled');}let cancel=()=>{};
 try{return await Promise.race([job,new Promise<T>((_,reject)=>{cancel=()=>reject(Error('Git transport cancelled'));control.signal.addEventListener('abort',cancel,{once:true});})]);}
 finally{control.signal.removeEventListener('abort',cancel);}}
 try {
 control.signal.throwIfAborted();lease=await bounded(credentials.acquire(Object.freeze({repositoryID,ownerID}),{signal:control.signal}));
 const now=Math.floor(Date.now()/1000);
 if(lease.repositoryID!==repositoryID||lease.ownerID!==ownerID||typeof lease.id!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(lease.id)||typeof lease.token!=='string'||!/^[A-Za-z0-9_]{1,16000}$/.test(lease.token)||!Number.isSafeInteger(lease.expiresAt)||lease.expiresAt<=now||lease.expiresAt>now+3600)throw Error('Invalid Git credential lease');
 const authorization='Basic '+btoa('x-access-token:'+lease.token);
 async function request(url: string,type: string,body?: Uint8Array) {
 control.signal.throwIfAborted();const options: RequestInit & {credentials: 'omit'}={method:body?'POST':'GET',redirect:'manual',credentials:'omit',cache:'no-store',signal:control.signal,headers:{Authorization:authorization,Accept:type,...(body?{'Content-Type':'application/x-git-receive-pack-request'}:{})},...(body?{body}:{})};const response=await bounded(fetcher(url,options));
 if(response.status!==200||response.headers.get('content-type')?.split(';')[0]!==type)throw Error('Git request rejected');return await bounded(read(response));}
 const identity=JSON.parse(decode.decode(await request('https://api.github.com/repos/'+repository,'application/json')));
 if(identity.id!==repositoryID||identity.owner?.id!==ownerID||identity.owner?.type!=='User'||identity.full_name?.toLowerCase()!==repository.toLowerCase()||identity.archived!==false||identity.fork!==false)throw Error('Git identity changed');
 discovery(await request(root+'/info/refs?service=git-receive-pack','application/x-git-receive-pack-advertisement'),match[1]);
 return await request(root+'/git-receive-pack','application/x-git-receive-pack-result',body);
 }catch{throw Error('Git transfer failed or uncertain; reconcile without retry');}
 finally {
 clearTimeout(timer);signal.removeEventListener('abort',abort);
 if(lease){const cleanup=new AbortController();let rejectDeadline: ()=>void=()=>{};
 const deadline=new Promise<void>((_,reject)=>{rejectDeadline=()=>{cleanup.abort();reject(Error('Git cleanup requires reconciliation'));};});const cleanupTimer=setTimeout(rejectDeadline,5000);
 try{await Promise.race([credentials.release(lease.id,{signal:cleanup.signal}),deadline]);}catch{throw Error('Git cleanup requires reconciliation');}finally{clearTimeout(cleanupTimer);}}
 }
 }};
}
