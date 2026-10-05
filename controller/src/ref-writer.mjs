// No shell execution, no repository checkout, no request-selected URLs or refs.
export function refWriter({repository,repositoryID,branch,token,fetcher=fetch}) {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository) || !['main','master'].includes(branch) || !Number.isSafeInteger(repositoryID)) throw new Error('Invalid trusted writer configuration');
  const root=`https://api.github.com/repos/${repository}`;
  async function request(path,body) {
    const response=await fetcher(root+path,{method:body?'PATCH':'GET',redirect:'error',headers:{Accept:'application/vnd.github+json',Authorization:`Bearer ${await token()}`,'X-GitHub-Api-Version':'2026-03-10','User-Agent':'repoctl-ref-writer','Content-Type':'application/json'},...(body?{body:JSON.stringify(body)}:{})});
    if (!response.ok) throw new Error(`GitHub ref writer failed (HTTP ${response.status})`);
    return response.json();
  }
  async function identity(){const r=await request('');if(r.id!==repositoryID || r.fork || r.archived)throw new Error('Repository identity mismatch');}
  return {
    async tip(){await identity();const ref=await request(`/git/ref/heads/${branch}`);if(ref.object?.type!=='commit')throw new Error('Invalid main ref');return ref.object.sha;},
    async commit(sha){if(!/^[a-f0-9]{40}$/.test(sha))throw new Error('Invalid commit SHA');await identity();return request(`/git/commits/${sha}`);},
    async advance(sha){if(!/^[a-f0-9]{40}$/.test(sha))throw new Error('Invalid commit SHA');await identity();return request(`/git/refs/heads/${branch}`,{sha,force:false});}
  };
}
