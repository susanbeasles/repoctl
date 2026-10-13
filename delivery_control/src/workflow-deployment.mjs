// Composition belongs to the trusted delivery_control workflow, never an app caller.
// The independently testable authorizer is supplied by the reviewed depot checkout.
export async function authorizeAndExecute({source,operation,policy,createAuthority,authorityStorage,executionStorage,evidence,identity,artifacts,loadCredentials,createProvider,createExecutor,now}) {
  if(source.repository!==operation?.source?.repository || source.repositoryID!==operation.source.repositoryID || source.sha!==operation.source.commitSHA || !source.service.workers.includes(operation.scriptName) || source.service.state==='retired') throw Error('Operation does not match admitted source and target');
  if(!policy?.enabled) throw Error('Deployment policy is disabled; reviewed policy, evidence and durable workflow ledger are required');
  // No Cloudflare credential exists until all source/evidence checks authorize.
  const authority=createAuthority({storage:authorityStorage,policy:()=>policy,evidence,...identity.verifier,...(now?{now}: {})});
  const authorization=await authority.authorize({operation,oidcToken:identity.authorizerToken,authorizerRunID:identity.runID,authorizerRunAttempt:identity.runAttempt});
  if(authorization?.operationID!==operation.operationID || authorization.state!=='authorized') throw Error('Authorization receipt mismatch');
  // Reserve replay identity and the global target lock before retrieving secrets.
  const consumeInput={operationID:operation.operationID,oidcToken:identity.executorToken};
  const grant=await authority.consume(consumeInput);let handedOff=false;
  const executionAuthority={...authority,consume:async input=>{
    if(handedOff||input.operationID!==consumeInput.operationID||input.oidcToken!==consumeInput.oidcToken) throw Error('Execution grant already used or mismatched');
    handedOff=true;return grant;
  }};
  try {
    const credentials=await loadCredentials();
    const provider=createProvider({token:credentials.CLOUDFLARE_API_TOKEN,githubToken:identity.sourceReadToken});
    const executor=createExecutor({storage:executionStorage,authority:executionAuthority,artifacts,provider,policy,...(now?{clock:now}: {})});
    return await executor.execute(consumeInput);
  } catch(error) {
    // Never release a claim automatically after a partial/ambiguous failure.
    try {await authority.complete({operationID:operation.operationID,leaseID:grant.leaseID,outcome:'uncertain',receipt:{versionID:null,deploymentID:null}});} catch { /* Retained claim remains closed. */ }
    throw error;
  }
}
