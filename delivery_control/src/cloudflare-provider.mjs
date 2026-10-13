// Fixed provider endpoints only. This module never executes uploaded application code.
import {canonical,validateIngress} from './shared/contract.mjs';
const cfOrigin = 'https://api.cloudflare.com/client/v4';
const githubOrigin = 'https://api.github.com';
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const denied = () => { throw Error('Provider deployment verification failed'); };

export async function boundedBytes(body, maximum) {
  if (!body || !Number.isSafeInteger(maximum) || maximum <= 0) denied();
  const reader = body.getReader(), chunks = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maximum) { await reader.cancel(); denied(); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return bytes;
}

function root(op) {
  if (!/^[a-f0-9]{32}$/.test(op?.accountID ?? '') || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(op?.scriptName ?? '')) denied();
  return `/accounts/${op.accountID}/workers/scripts/${op.scriptName}`;
}

export function createCloudflareProvider({ token, githubToken, fetcher = fetch }) {
  if (typeof token !== 'string' || !token.length || typeof fetcher !== 'function' || (githubToken!==undefined&&(typeof githubToken!=='string'||!githubToken.length))) denied();
  async function request(path, { method = 'GET', body, github = false, envelope = false } = {}) {
    const headers = { Accept: 'application/json' };
    if (github) { headers['User-Agent'] = 'delivery-control-deployer'; headers['X-GitHub-Api-Version'] = '2026-03-10'; if(githubToken)headers.Authorization=`Bearer ${githubToken}`; }
    else headers.Authorization = `Bearer ${token}`;
    if (body !== undefined && !(body instanceof FormData)) headers['Content-Type'] = 'application/json';
    try {
      const response = await fetcher((github ? githubOrigin : cfOrigin) + path, {
        method, headers, redirect: 'error', signal: AbortSignal.timeout(20000),
        ...(body === undefined ? {} : { body: body instanceof FormData ? body : JSON.stringify(body) }),
      });
      if (!response.ok) { await response.body?.cancel(); denied(); }
      const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(await boundedBytes(response.body, 1024 * 1024)));
      if (!github && (parsed?.success !== true || !Object.hasOwn(parsed, 'result'))) denied();
      return github || envelope ? parsed : parsed.result;
    } catch { denied(); }
  }
  async function current(op) {
    const data = await request(root(op) + '/deployments');
    if (!Array.isArray(data?.deployments) || !data.deployments.length || !uuid.test(data.deployments[0]?.id ?? '')) denied();
    return data.deployments[0];
  }
  async function routing(op) {
    root(op);
    const ingress=validateIngress(op);
    if(ingress.type!=='custom-domain'){
      const first=await ingressSnapshot(op,ingress),second=await ingressSnapshot(op,ingress);
      if(canonical(first)!==canonical(second))denied();
      return;
    }
    if (!/^[a-f0-9]{32}$/.test(op.zoneID ?? '') || typeof op.hostname !== 'string' || !/^[a-z0-9.-]+$/.test(op.hostname)) denied();
    const zone = await request(`/zones/${op.zoneID}`);
    if (zone?.id !== op.zoneID || zone.account?.id !== op.accountID || zone.status !== 'active' || typeof zone.name !== 'string' || !(op.hostname === zone.name || op.hostname.endsWith('.' + zone.name))) denied();
    const domains = await request(`/accounts/${op.accountID}/workers/domains?hostname=${encodeURIComponent(op.hostname)}`);
    if (!Array.isArray(domains) || domains.length !== 1) denied();
    const domain = domains[0];
    if (domain.hostname !== op.hostname || domain.service !== op.scriptName || domain.zone_id !== op.zoneID || domain.enabled !== true || domain.previews_enabled !== false) denied();
    const subdomain = await request(root(op) + '/subdomain');
    if (subdomain?.enabled !== false || subdomain.previews_enabled !== false) denied();
  }
  async function ingressSnapshot(op,ingress){
    const zones=[];let total,pages;
    for(let page=1;page<=2;page++){
      const data=await request(`/zones?account.id=${op.accountID}&type=full,partial,secondary,internal&per_page=50&page=${page}`,{envelope:true}),info=data.result_info;
      if(!Array.isArray(data.result)||!info||info.page!==page||info.per_page!==50||info.count!==data.result.length||!Number.isSafeInteger(info.total_count)||info.total_count<1||info.total_count>100||!Number.isSafeInteger(info.total_pages)||info.total_pages!==Math.ceil(info.total_count/50))denied();
      if(page===1){total=info.total_count;pages=info.total_pages;}else if(total!==info.total_count||pages!==info.total_pages)denied();
      zones.push(...data.result);if(page===pages)break;
    }
    if(zones.length!==total||new Set(zones.map(z=>z.id)).size!==zones.length||canonical(zones.map(z=>z.id).sort())!==canonical(ingress.zoneIDs))denied();
    const observed=[];
    for(const zone of zones){
      if(zone.account?.id!==op.accountID||zone.status!=='active'||typeof zone.name!=='string'||!/^[a-z0-9.-]+$/.test(zone.name))denied();
      if(zone.id===op.zoneID&&!(op.hostname===zone.name||op.hostname.endsWith('.'+zone.name)))denied();
      const routes=await request(`/zones/${zone.id}/workers/routes`);
      if(!Array.isArray(routes)||routes.length>1000||new Set(routes.map(r=>r.id)).size!==routes.length)denied();
      for(const route of routes){
        if(typeof route.id!=='string'||!/^[a-f0-9]{32}$/.test(route.id)||typeof route.pattern!=='string'||(route.script!==undefined&&route.script!==null&&typeof route.script!=='string'))denied();
        if(route.script===op.scriptName)observed.push({id:route.id,zoneID:zone.id,pattern:route.pattern});
      }
    }
    observed.sort((a,b)=>a.id.localeCompare(b.id));
    if(canonical(observed)!==canonical(ingress.type==='routes'?ingress.routes:[]))denied();
    // service= is a documented provider filter. For these two modes ANY custom
    // domain (including preview-only) is unexpected, so require complete zero.
    const domains=await request(`/accounts/${op.accountID}/workers/domains?service=${op.scriptName}`,{envelope:true}),info=domains.result_info;
    if(!Array.isArray(domains.result)||domains.result.length!==0)denied();
    // The official endpoint/SDK is a single-page list. Optional generic result
    // metadata cannot imply an omitted page; its absence is not an error.
    if(info&&(Object.hasOwn(info,'page')&&info.page!==1||Object.hasOwn(info,'count')&&info.count!==0||Object.hasOwn(info,'total_count')&&info.total_count!==0||Object.hasOwn(info,'total_pages')&&![0,1].includes(info.total_pages)))denied();
    const subdomain=await request(root(op)+'/subdomain');if(subdomain?.enabled!==false||subdomain.previews_enabled!==false)denied();
    // Zone visibility is token-filtered: commissioning must establish read
    // access to every account zone. Matching this approved inventory alone is
    // not evidence that an under-scoped credential can see hidden zones.
    return {zones:zones.map(z=>({id:z.id,name:z.name})).sort((a,b)=>a.id.localeCompare(b.id)),routes:observed};
  }
  return {
    async preflight(op, artifact) {
      await routing(op);
      const source = op.source;
      if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(source?.repository ?? '') || !/^[a-f0-9]{40}$/.test(source?.commitSHA ?? '') || !Number.isSafeInteger(source.repositoryID) || source.repositoryID <= 0) denied();
      const repository = await request(`/repos/${source.repository}`, { github: true });
      if (repository?.id !== source.repositoryID || repository.archived !== false || repository.fork !== false) denied();
      const commit = await request(`/repos/${source.repository}/git/commits/${source.commitSHA}`, { github: true });
      if (commit?.sha !== source.commitSHA || commit.verification?.verified !== true || commit.verification.reason !== 'valid') denied();
      await this.baseline(op, artifact);
    },
    async baseline(op, artifact, uploadedVersionID) {
      if(Object.hasOwn(op,'ingress'))await routing(op);
      const deployment = await current(op);
      if (!uuid.test(op.expectedDeploymentID ?? '') || deployment.id !== op.expectedDeploymentID) denied();
      if (deployment.strategy !== 'percentage' || deployment.versions?.length !== 1 || deployment.versions[0].percentage !== 100 || !uuid.test(deployment.versions[0].version_id ?? '')) denied();
      const activeVersionID = deployment.versions[0].version_id;
      const latest = await request(root(op) + '/versions?per_page=1');
      if (!Array.isArray(latest?.items) || latest.items[0]?.id !== (uploadedVersionID ?? activeVersionID)) denied();
      const active = await request(root(op) + `/versions/${activeVersionID}`);
      if (active?.id !== activeVersionID || !Array.isArray(active.resources?.bindings) || !Array.isArray(artifact?.metadata?.bindings)) denied();
      // Only names/types are inspected. Secret values are never requested or stored.
      const secrets = active.resources.bindings.filter(binding => ['secret_text', 'secret_key'].includes(binding.type)).map(binding => binding.name).sort();
      const inherited = artifact.metadata.bindings.filter(binding => binding.type === 'inherit').map(binding => binding.name).sort();
      if (secrets.some(name => typeof name !== 'string') || new Set(secrets).size !== secrets.length || JSON.stringify(secrets) !== JSON.stringify(inherited)) denied();
    },
    async upload(op, artifact) {
      const multipart = new FormData();
      multipart.set('metadata', new Blob([JSON.stringify(artifact.metadata)], { type: 'application/json' }));
      for (const module of artifact.modules) {
        if (module.name !== 'worker.mjs' || module.type !== 'esm' || typeof module.content !== 'string') denied();
        multipart.set(module.name, new Blob([module.content], { type: 'application/javascript+module' }), module.name);
      }
      const result = await request(root(op) + '/versions?bindings_inherit=strict', { method: 'POST', body: multipart });
      if (!uuid.test(result?.id ?? '')) denied();
      return { versionID: result.id };
    },
    async activate(op, versionID) {
      if (!uuid.test(versionID ?? '')) denied();
      const result = await request(root(op) + '/deployments', { method: 'POST', body: { strategy: 'percentage', versions: [{ version_id: versionID, percentage: 100 }] } });
      if (!uuid.test(result?.id ?? '')) denied();
      return { deploymentID: result.id };
    },
    async verify(op, receipt) {
      if (!uuid.test(receipt?.versionID ?? '') || !uuid.test(receipt?.deploymentID ?? '')) denied();
      const version = await request(root(op) + `/versions/${receipt.versionID}`);
      if (version?.id !== receipt.versionID) denied();
      const deployed = await current(op);
      if (deployed.id !== receipt.deploymentID || deployed.strategy !== 'percentage' || deployed.versions?.length !== 1 || deployed.versions[0].version_id !== receipt.versionID || deployed.versions[0].percentage !== 100) denied();
      await routing(op);
      return { versionID: receipt.versionID, deploymentID: receipt.deploymentID };
    },
  };
}
