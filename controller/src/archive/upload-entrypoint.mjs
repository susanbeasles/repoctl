import {recoveryUploadGateway} from './upload-gateway.mjs';
export default {async fetch(request,env){
 if(env.RECOVERY_UPLOAD_ENABLED!=='true'||typeof env.RECOVERY_UPLOAD_TRUST_JSON!=='string'||typeof env.RECOVERY_PUBLISHER?.fetch!=='function')return Response.json({error:'upload_not_configured'},{status:503,headers:{'Cache-Control':'no-store'}});
 try{return await recoveryUploadGateway({trust:JSON.parse(env.RECOVERY_UPLOAD_TRUST_JSON),publisher:env.RECOVERY_PUBLISHER}).fetch(request);}catch{return Response.json({error:'upload_not_configured'},{status:503,headers:{'Cache-Control':'no-store'}});}
}};
