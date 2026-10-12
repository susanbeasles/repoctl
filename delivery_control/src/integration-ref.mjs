// Ref names are validated before they reach Git or provider URLs.
export function validHeadRef(value) {
 if(typeof value!=='string'||!value.startsWith('refs/heads/')||value.length>240)return false;
 const name=value.slice(11);
 return /^[A-Za-z0-9_./-]+$/.test(name)&&!!name&&!/[\x00-\x20\x7f~^:?*\[\\]/.test(name)&&!name.includes('..')&&!name.includes('@{')&&!name.endsWith('.')&&name.split('/').every(part=>part&&!part.startsWith('.')&&!part.endsWith('.lock'));
}
export function integrationRef(sourceRef) {
 if(!validHeadRef(sourceRef)||sourceRef==='refs/heads/main'||sourceRef.startsWith('refs/heads/int/'))throw Error('Invalid integration source ref');
 return 'refs/heads/int/'+sourceRef.slice(11);
}
export function isIntegrationRef(value) {
 if(typeof value!=='string'||!value.startsWith('refs/heads/int/'))return false;
 try{return integrationRef('refs/heads/'+value.slice(15))===value;}catch{return false;}
}
