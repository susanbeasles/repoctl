import {canonical,digest} from './ledger.mjs';
export const defaultProfiles=Object.freeze({writer:{permissions:{contents:'write'},events:[]},validator:{permissions:{contents:'read',checks:'read',actions:'read',security_events:'read'},events:[]},builder:{permissions:{contents:'write',pull_requests:'write'},events:[]},release:{permissions:{contents:'write'},events:[]}});
export function profileFor(role,profiles=defaultProfiles){
 const p=profiles?.[role];
 if(typeof role!=='string'||!/^[a-z][a-z0-9-]{0,63}$/.test(role)||!Object.hasOwn(profiles??{},role)||!p||Object.keys(p).sort().join()!=='events,permissions'||!p.permissions||Object.getPrototypeOf(p.permissions)!==Object.prototype||Object.keys(p.permissions).length<1||Object.keys(p.permissions).length>100||!Object.entries(p.permissions).every(([k,v])=>/^[a-z][a-z0-9_]{0,79}$/.test(k)&&['read','write'].includes(v))||!Array.isArray(p.events)||p.events.length>100||!p.events.every(e=>typeof e==='string'&&/^[a-z][a-z0-9_]{0,79}$/.test(e))||new Set(p.events).size!==p.events.length)throw Error('Unknown or invalid reviewed App profile');
 return structuredClone(p);
}
export const profileDigest=(role,profiles)=>digest(profileFor(role,profiles));
