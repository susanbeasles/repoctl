import { readFile, appendFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

export const OWNER = 'susanbeasles';
export const OWNER_ID = 215839550;
const SHA = /^[a-f0-9]{40}$/;
const VERSION = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
export function parseVersion(tag) {
  const m = VERSION.exec(tag);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (!parts.every(Number.isSafeInteger)) throw Error('Version exceeds safe integer range');
  return parts;
}
export function compareVersion(a, b) {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] > b[i] ? 1 : -1;
  return 0;
}
export function nextVersion(previous, messages) {
  const v = parseVersion(previous ?? 'v0.0.0');
  if (!v) throw Error('Invalid version baseline');
  const major = messages.some(m => /^[a-z][a-z0-9-]*(?:\([^\r\n]+\))?!: /im.test(m) || /^BREAKING[ -]CHANGE: /m.test(m));
  const minor = messages.some(m => /^feat(?:\([^\r\n]+\))?: /im.test(m));
  const result = major ? [v[0] + 1, 0, 0] : minor ? [v[0], v[1] + 1, 0] : [v[0], v[1], v[2] + 1];
  if (!result.every(Number.isSafeInteger)) throw Error('Version exceeds safe integer range');
  return `v${result.join('.')}`;
}
export function validateRequest({ repository, repositoryID, sha, runID }) {
  if (!new RegExp(`^${OWNER}/[A-Za-z0-9_.-]+$`).test(repository ?? '') || !SHA.test(sha ?? '')) throw Error('Invalid repository or SHA');
  for (const id of [repositoryID, runID]) if (!/^[1-9]\d*$/.test(String(id)) || !Number.isSafeInteger(Number(id))) throw Error('Invalid numeric identity');
  return { repository, repositoryID: Number(repositoryID), sha, runID: Number(runID) };
}
export class API {
  constructor(token, fetcher = fetch) { if (!token) throw Error('Missing release credential'); this.token = token; this.fetcher = fetcher; }
  async request(path, method = 'GET', body) {
    if (!path.startsWith('/repos/')) throw Error('Unexpected API path');
    const r = await this.fetcher(`https://api.github.com${path}`, {
      method, redirect: 'error', signal: AbortSignal.timeout(30000),
      headers: { Authorization: `Bearer ${this.token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2026-03-10', 'User-Agent': 'delivery-control-release', 'Content-Type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    if (r.status === 404 && method === 'GET') return null;
    if (!r.ok) throw Error(`GitHub ${method} failed (${r.status}); rerun after reconciliation`);
    return r.status === 204 ? null : r.json();
  }
  async pages(path, key) {
    const items = [];
    for (let page = 1; page <= 10000; page++) {
      const data = await this.request(`${path}${path.includes('?') ? '&' : '?'}per_page=100&page=${page}`);
      const batch = key ? data?.[key] : data;
      if (!Array.isArray(batch)) throw Error('Invalid paginated API response');
      items.push(...batch);
      if (batch.length < 100) return items;
    }
    throw Error('Pagination limit exceeded');
  }
}
export async function release(request, api) {
  const q = validateRequest(request);
  const root = `/repos/${q.repository}`;
  const repo = await api.request(root);
  if (repo?.id !== q.repositoryID || repo.owner?.id !== OWNER_ID || repo.owner?.login !== OWNER || repo.archived || repo.fork || repo.default_branch !== 'main') throw Error('Repository identity or main policy mismatch');
  const source = await api.request(`${root}/actions/runs/${q.runID}`);
  if (source?.event !== 'push' || source.head_branch !== 'main' || source.head_sha !== q.sha || source.repository?.id !== q.repositoryID) throw Error('Source run does not identify the requested main push');
  const workflow = await api.request(`${root}/actions/workflows/${source.workflow_id}`);
  if (workflow?.path !== '.github/workflows/auto-release.yml') throw Error('Unexpected source workflow');
  const main = await api.request(`${root}/git/ref/heads/main`);
  const ancestry = await api.request(`${root}/compare/${q.sha}...${main?.object?.sha}`);
  if (!['ahead', 'identical'].includes(ancestry?.status)) throw Error('Requested push is no longer in main history');
  const tags = (await api.pages(`${root}/tags`)).filter(t => parseVersion(t.name)).sort((a, b) => compareVersion(parseVersion(b.name), parseVersion(a.name)));
  let baseline = tags[0] ?? null;
  // Reconcile source push boundaries, not dispatch arrival order. Include failed
  // callers: their recorded push is still valid and can be recovered by a later run.
  const runs = (await api.pages(`${root}/actions/workflows/${source.workflow_id}/runs?event=push&branch=main`, 'workflow_runs'))
    .filter(r => r.event === 'push' && r.head_branch === 'main' && r.run_number <= source.run_number)
    .sort((a, b) => a.run_number - b.run_number);
  if (!runs.some(r => r.id === q.runID)) throw Error('Requested push not found in workflow history');
  // Validate historical boundaries before any write, including after a force push.
  for (const run of runs) {
    if (!SHA.test(run.head_sha) || run.repository?.id !== q.repositoryID) throw Error('Invalid recorded push identity');
    const history = await api.request(`${root}/compare/${run.head_sha}...${main.object.sha}`);
    if (!['ahead', 'identical'].includes(history?.status)) throw Error('Recorded push is no longer in main history; reconcile explicitly');
  }
  const results = [];
  async function publish(tag, targetSHA, run) {
    const ref = await api.request(`${root}/git/ref/tags/${tag}`);
    if (ref?.object?.type !== 'tag') throw Error('Release tag is not an annotated managed tag');
    const object = await api.request(`${root}/git/tags/${ref.object.sha}`);
    if (object?.object?.type !== 'commit' || object.object.sha !== targetSHA || object.tag !== tag) throw Error('Release tag target mismatch');
    let marker;
    try { marker = JSON.parse(object.message); } catch { throw Error('Unmanaged tag cannot be resumed automatically'); }
    if (marker.schema !== 'delivery-control-release/v1' || marker.repositoryID !== q.repositoryID || marker.sha !== targetSHA || marker.sourceRunID !== run.id) throw Error('Release tag identity mismatch');
    const existing = await api.request(`${root}/releases/tags/${tag}`);
    if (existing && !existing.draft) {
      if (existing.prerelease) throw Error('Expected official stable release');
      return { tag, sha: targetSHA, url: existing.html_url, resumed: true };
    }
    const body = { tag_name: tag, target_commitish: targetSHA, name: tag, draft: false, prerelease: false, make_latest: 'true', body: `Automated source release for ${q.repository}.\n\nCommit: ${targetSHA}\nSource push: https://github.com/${q.repository}/actions/runs/${run.id}\n\nThis release contains GitHub source archives. Binary packages and verified build assets are published separately.` };
    const published = existing ? await api.request(`${root}/releases/${existing.id}`, 'PATCH', body) : await api.request(`${root}/releases`, 'POST', body);
    if (published?.tag_name !== tag || published.draft || published.prerelease) throw Error('Release publication readback mismatch');
    return { tag, sha: targetSHA, url: published.html_url };
  }
  for (const run of runs) {
    if (!SHA.test(run.head_sha)) throw Error('Invalid recorded push SHA');
    if (baseline?.commit?.sha === run.head_sha) {
      // Highest tag may have been created immediately before an interrupted publish.
      const ref = await api.request(`${root}/git/ref/tags/${baseline.name}`);
      if (ref?.object?.type === 'tag') {
        const obj = await api.request(`${root}/git/tags/${ref.object.sha}`);
        let marker; try { marker = JSON.parse(obj.message); } catch { /* existing manual baseline */ }
        if (marker?.schema === 'delivery-control-release/v1') results.push(await publish(baseline.name, run.head_sha, { id: marker.sourceRunID }));
      }
      continue;
    }
    let commits;
    if (baseline) {
      const comparison = await api.request(`${root}/compare/${baseline.commit.sha}...${run.head_sha}`);
      if (['behind', 'identical'].includes(comparison?.status)) continue;
      if (comparison?.status !== 'ahead') throw Error('Version baseline and requested push have diverged');
      commits = await api.pages(`${root}/compare/${baseline.commit.sha}...${run.head_sha}`, 'commits');
      if (commits.length !== comparison.ahead_by) throw Error('Incomplete commit comparison');
    } else {
      commits = await api.pages(`${root}/commits?sha=${run.head_sha}`);
    }
    const tag = nextVersion(baseline?.name, commits.map(c => c.commit.message));
    const message = JSON.stringify({ schema: 'delivery-control-release/v1', repositoryID: q.repositoryID, sha: run.head_sha, sourceRunID: run.id });
    const obj = await api.request(`${root}/git/tags`, 'POST', { tag, message, object: run.head_sha, type: 'commit' });
    await api.request(`${root}/git/refs`, 'POST', { ref: `refs/tags/${tag}`, sha: obj.sha });
    results.push(await publish(tag, run.head_sha, run));
    baseline = { name: tag, commit: { sha: run.head_sha } };
  }
  return results;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const event = JSON.parse(await readFile(process.env.GITHUB_EVENT_PATH, 'utf8'));
    const result = await release({ repository: event.inputs.repository, repositoryID: event.inputs.repository_id, sha: event.inputs.sha, runID: event.inputs.source_run_id }, new API(process.env.RELEASE_TOKEN));
    console.log(JSON.stringify(result));
    if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY, result.length ? result.map(r => `- [${r.tag}](${r.url}) — ${r.sha}\n`).join('') : 'All requested pushes were already covered.\n');
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
