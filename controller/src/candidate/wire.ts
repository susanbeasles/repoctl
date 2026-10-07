export interface GenerationIntent {
 readonly generationID: string;
 readonly commitSHA: string;
}
const encode = new TextEncoder();
const decode = new TextDecoder('utf-8', {fatal: true, ignoreBOM: true});
function binding(value: unknown): Readonly<{ref: string; commitSHA: string}> {
 if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype ||
     Object.keys(value).sort().join() !== 'commitSHA,generationID') throw Error('Invalid generation intent');
 const {generationID,commitSHA} = value as Record<string,unknown>;
 if (typeof generationID !== 'string' || !/^[a-f0-9]{64}$/.test(generationID) ||
     typeof commitSHA !== 'string' || !/^[a-f0-9]{40}$/.test(commitSHA) || /^0+$/.test(commitSHA)) throw Error('Invalid generation intent');
 return Object.freeze({ref: 'refs/heads/int/'+generationID, commitSHA});
}

// Private job codec. Authentication, capability discovery, candidate verification
// and the single durable publication claim belong to the installed coordinator.
// The sole command uses zero old-ID: receive-pack must reject an existing ref.
export function generationRequest(intent: GenerationIntent, pack: Uint8Array): Uint8Array {
 const candidate=binding(intent);
 const target=candidate.ref;
 if (!(pack instanceof Uint8Array) || pack.length<32 || pack.length>256*1024*1024 ||
     pack[0]!==80 || pack[1]!==65 || pack[2]!==67 || pack[3]!==75 ||
     pack[4]!==0 || pack[5]!==0 || pack[6]!==0 || ![2,3].includes(pack[7])) throw Error('Invalid generation pack');
 const command=encode.encode('0'.repeat(40)+' '+candidate.commitSHA+' '+target+'\0report-status\n');
 const prefix=encode.encode((command.length+4).toString(16).padStart(4,'0'));
 const body=new Uint8Array(prefix.length+command.length+4+pack.length);
 body.set(prefix);body.set(command,prefix.length);body.set(encode.encode('0000'),prefix.length+command.length);
 body.set(pack,prefix.length+command.length+4);
 return body;
}

// A positive server report is an acknowledgement, not independent confirmation.
// Missing/truncated/ambiguous reports must leave journal state uncertain.
export function generationResult(bytes: Uint8Array, intent: GenerationIntent): boolean {
 const target=binding(intent).ref;
 if (!(bytes instanceof Uint8Array) || bytes.length>65536) throw Error('Invalid generation report');
 const lines: string[]=[];let offset=0,flushed=false;
 while(offset<bytes.length){
  if(offset+4>bytes.length)throw Error('Invalid generation report');
  const header=decode.decode(bytes.subarray(offset,offset+4));
  if(!/^[a-f0-9]{4}$/.test(header))throw Error('Invalid generation report');
  const size=parseInt(header,16);offset+=4;
  if(size===0){flushed=true;break;}
  if(size<5 || offset+size-4>bytes.length || lines.length>=2)throw Error('Invalid generation report');
  let line: string;try{line=decode.decode(bytes.subarray(offset,offset+size-4));}catch{throw Error('Invalid generation report');}
  if(!line.endsWith('\n') || line.slice(0,-1).includes('\n') || line.includes('\0'))throw Error('Invalid generation report');
  lines.push(line.slice(0,-1));offset+=size-4;
 }
 if(!flushed || offset!==bytes.length || lines.length!==2 || !lines[0].startsWith('unpack ') ||
    !(lines[1]==='ok '+target || lines[1].startsWith('ng '+target+' '))) throw Error('Invalid generation report');
 return lines[0]==='unpack ok' && lines[1]==='ok '+target;
}
