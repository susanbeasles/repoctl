import {appManifest} from './manifest.mjs';
import {canonical} from '../ledger.mjs';
export async function verifyAppPlan(plan){
 const fields=['protocol','owner','role','repositories','manifest','manifestBytes','manifestDigest','registrationState','installationState'];
 if(!plan||Object.keys(plan).sort().join()!==fields.sort().join()||plan.protocol!=='repoctl-app-plan-v1'||plan.registrationState!=='not_registered'||plan.installationState!=='not_installed'||typeof plan.owner!=='string'||! /^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/.test(plan.owner)||!Array.isArray(plan.repositories)||plan.repositories.length<1||plan.repositories.length>100||new Set(plan.repositories).size!==plan.repositories.length||!plan.repositories.every(r=>typeof r==='string'&&r.startsWith(plan.owner+'/')&&/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(r)))throw Error('Invalid App plan');
 if(typeof plan.manifestBytes!=='string'||plan.manifestBytes.length>8192||typeof plan.manifestDigest!=='string'||! /^[a-f0-9]{64}$/.test(plan.manifestDigest))throw Error('Invalid manifest bytes');
 const bytes=Uint8Array.from(atob(plan.manifestBytes),c=>c.charCodeAt(0)),text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
 const fingerprint=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),b=>b.toString(16).padStart(2,'0')).join('');
 const m=plan.manifest;
 if(!m||!['url','redirect_url'].every(k=>typeof m[k]==='string'&&[...m[k]].every(c=>c.charCodeAt(0)>=33&&c.charCodeAt(0)<=126)&&!new URL(m[k]).search))throw Error('Invalid manifest endpoints');
 const expected=appManifest({name:m.name,role:plan.role,homepage:m.url,callback:m.redirect_url});
 if(fingerprint!==plan.manifestDigest||canonical(JSON.parse(text))!==canonical(m)||canonical(m)!==canonical(expected))throw Error('Manifest differs from reviewed role/bytes');
 return {owner:plan.owner,role:plan.role,repositories:[...plan.repositories],manifest:expected,manifestDigest:fingerprint,manifestBytes:plan.manifestBytes};
}
