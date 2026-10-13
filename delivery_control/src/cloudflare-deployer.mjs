import { canonical, validatePolicy, validateOperation, validateArtifact } from './shared/contract.mjs';
import { boundedBytes } from './cloudflare-provider.mjs';

const hex = /^[a-f0-9]{64}$/;
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype && Object.keys(value).sort().join() === [...keys].sort().join();
const failure = () => { throw Error('Deployment failed; reconciliation may be required'); };
const headers = { 'Cache-Control': 'no-store', 'Content-Type': 'application/json' };

function validateRequest(input) {
  if (!exact(input, ['operationID', 'oidcToken']) || !hex.test(input.operationID) || typeof input.oidcToken !== 'string' || !input.oidcToken.length || input.oidcToken.length > 16000) failure();
}

export function createCloudflareDeployer({ storage, authority, artifacts, provider, policy, clock = () => Math.floor(Date.now() / 1000) }) {
  if (!storage?.transaction || !storage.get || !storage.put || !authority?.consume || !authority.check || !authority.complete || !artifacts?.get || !['preflight', 'baseline', 'upload', 'activate', 'verify'].every(name => typeof provider?.[name] === 'function')) failure();
  const trustedPolicy = structuredClone(validatePolicy(policy));
  return {
    async execute(input) {
      let grant, operation, record, key, claimed = false;
      let receipt = { versionID: null, deploymentID: null };
      try {
        validateRequest(input);
        key = `deployment:${input.operationID}`;
        if (await storage.get(key)) failure();
        // Authentication precedes local reservation; invalid callers cannot poison a job.
        grant = await authority.consume({ operationID: input.operationID, oidcToken: input.oidcToken });
        if (!exact(grant, ['operation', 'leaseID', 'identityExpiresAt']) || !hex.test(grant.leaseID) || !Number.isSafeInteger(grant.identityExpiresAt) || grant.identityExpiresAt <= clock()) failure();
        operation = structuredClone(grant.operation);
        await validateOperation(operation, trustedPolicy, clock());
        if (operation.operationID !== input.operationID) failure();
        record = { operationID: input.operationID, leaseID: grant.leaseID, state: 'reserved', receipt };
        await storage.transaction(async transaction => {
          if (await transaction.get(key)) failure();
          await transaction.put(key, record);
        });
        claimed = true;
        const save = async state => { record = { ...record, state, receipt: { ...receipt } }; await storage.put(key, record); };
        const check = async stage => {
          if (operation.expiresAt <= clock() || grant.identityExpiresAt <= clock()) failure();
          const confirmation = await authority.check({ operationID: operation.operationID, leaseID: grant.leaseID, stage });
          if (!exact(confirmation, ['operation', 'leaseID', 'identityExpiresAt']) || confirmation.leaseID !== grant.leaseID || confirmation.identityExpiresAt !== grant.identityExpiresAt || confirmation.identityExpiresAt <= clock() || canonical(confirmation.operation) !== canonical(operation)) failure();
          await validateOperation(confirmation.operation, trustedPolicy, clock());
        };
        const object = await artifacts.get(`artifacts/sha256/${operation.artifactDigest}.json`);
        if (!object || !Number.isSafeInteger(object.size) || object.size <= 0 || object.size > trustedPolicy.maxArtifactBytes) failure();
        const bytes = await boundedBytes(object.body, trustedPolicy.maxArtifactBytes);
        if (bytes.byteLength !== object.size) failure();
        const artifact = await validateArtifact(bytes, operation, trustedPolicy);
        await provider.preflight(operation, artifact);
        await save('upload-intent');
        await check('upload');
        const uploaded = await provider.upload(operation, artifact);
        if (!exact(uploaded, ['versionID']) || !uuid.test(uploaded.versionID)) failure();
        receipt.versionID = uploaded.versionID;
        await save('uploaded');
        await provider.baseline(operation, artifact, receipt.versionID);
        await save('activate-intent');
        await check('activate');
        const activated = await provider.activate(operation, receipt.versionID);
        if (!exact(activated, ['deploymentID']) || !uuid.test(activated.deploymentID)) failure();
        receipt.deploymentID = activated.deploymentID;
        await save('activated');
        const verified = await provider.verify(operation, receipt, artifact);
        if (!exact(verified, ['versionID', 'deploymentID']) || canonical(verified) !== canonical(receipt)) failure();
        await save('verified');
        const completed = await authority.complete({ operationID: operation.operationID, leaseID: grant.leaseID, outcome: 'completed', receipt: { ...receipt } });
        if (completed?.operationID !== operation.operationID || completed.state !== 'completed') failure();
        await save('completed');
        return { operationID: operation.operationID, state: 'completed', artifactDigest: operation.artifactDigest, ...receipt };
      } catch {
        if (claimed) {
          try { await storage.put(key, { ...record, state: 'uncertain', receipt: { ...receipt } }); } catch { /* The last durable intent still prevents replay. */ }
          try { await authority.complete({ operationID: operation.operationID, leaseID: grant.leaseID, outcome: 'uncertain', receipt: { ...receipt } }); } catch { /* Authority retains its unresolved reservation. */ }
        }
        failure();
      }
    },
  };
}

export async function handleDeploymentRequest(request, executor, { enabled = false } = {}) {
  if (new URL(request.url).pathname !== '/v1/deployments/execute' || request.method !== 'POST') return Response.json({ error: 'not_found' }, { status: 404, headers });
  if (!enabled) return Response.json({ error: 'deployer_disabled' }, { status: 503, headers });
  let input;
  try {
    const bytes = await boundedBytes(request.body, 20000);
    input = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    validateRequest(input);
  } catch { return Response.json({ error: 'invalid_deployment_request' }, { status: 400, headers }); }
  try { return Response.json(await executor.execute(input), { headers }); }
  catch { return Response.json({ error: 'deployment_failed_or_uncertain' }, { status: 409, headers }); }
}
