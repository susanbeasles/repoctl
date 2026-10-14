import {isIP} from 'node:net';
export function previewTarget(target,approval) {
 if(!target)return;
 if(typeof approval!=='string'||!approval.trim())throw Error('Isolated synthetic preview requires explicit authorization');
 const url=new URL(target);if(url.protocol!=='https:'||url.username||url.password||url.hash)throw Error('Preview must use HTTPS without credentials or fragments');
 const h=url.hostname;
 // Literal private targets avoid DNS rebinding and accidental public/third-party scans.
 const parts=h.split('.').map(Number);
 const privateIPv4=isIP(h)===4&&(parts[0]===10||(parts[0]===172&&parts[1]>=16&&parts[1]<=31)||(parts[0]===192&&parts[1]===168));
 if(!privateIPv4)throw Error('Only the explicitly authorized private IPv4 preview is accepted; no public fallback');
 return url.href;
}
