const roles={writer:{contents:'write'},validator:{contents:'read',checks:'read',actions:'read',security_events:'read'},builder:{contents:'write',pull_requests:'write'},release:{contents:'write'}};
export function appManifest({name,role,homepage,callback,webhook}){
 if(!/^[A-Za-z0-9][A-Za-z0-9 -]{0,80}$/.test(name)||!roles[role])throw new Error('Invalid App name/role');
 for(const value of [homepage,callback,...(webhook?[webhook]:[])]){const url=new URL(value);if(url.protocol!=='https:'||url.username||url.password||url.hash)throw new Error('HTTPS public deployment endpoints required');}
 return {name,url:homepage,redirect_url:callback,public:false,default_permissions:roles[role],default_events:webhook?['push']:[],hook_attributes:webhook?{url:webhook,active:true}:{active:false}};
}
// Callback code never travels through CLI or clipboard. It is exchanged by the
// remote callback, then private values flow directly into remote secret storage.
export async function enrollApp({state,code},services,now=Date.now()){
 if(typeof state!=='string'||!/^[a-f0-9]{64}$/.test(state)||typeof code!=='string'||!/^[A-Za-z0-9_-]{1,200}$/.test(code))throw new Error('Invalid enrollment callback');
 const session=await services.sessions.consume(state,now); // atomic, expiring, one use
 if(!session||session.expiresAt<=now||!session.role)throw new Error('Expired or unrecognized enrollment');
 let app;
 try{
  app=await services.github.exchangeManifestCode(code);
  if(!Number.isSafeInteger(app?.id)||app.id<=0||typeof app.pem!=='string'||!app.pem.includes('PRIVATE KEY')||typeof app.webhook_secret!=='string')throw Error('Incomplete provider response');
  await services.github.verifyAppIdentity(app,session); // selected owner, exact permissions
  const reference=await services.secrets.stage({operationID:session.operationID,appID:app.id,role:session.role,privateKey:app.pem,webhookSecret:app.webhook_secret,clientSecret:app.client_secret});
  await services.secrets.verify(reference,app.id);
  await services.enrollment.commit({operationID:session.operationID,appID:app.id,role:session.role,credentialReference:reference});
  return {state:'enrolled',appID:app.id,role:session.role,operationID:session.operationID};
 }catch{
  await services.enrollment.degraded(session.operationID);
  throw new Error('Remote App enrollment incomplete; reconcile server-side');
 }
}
