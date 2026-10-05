// Read-only GitHub observation. Deployment configuration selects the repository;
// callers cannot supply URLs, headers, credentials or alternate refs.
export function githubObserver({repository,repositoryID,branch,fetcher=fetch}){
 if(!/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(repository)||!Number.isSafeInteger(repositoryID)||repositoryID<=0||!['main','master'].includes(branch))throw Error('Invalid observer configuration');
 const sha=/^[a-f0-9]{40}$/;
 async function get(path){
  const r=await fetcher(`https://api.github.com/repos/${repository}${path}`,{redirect:'manual',signal:AbortSignal.timeout(10000),headers:{Accept:'application/vnd.github+json','User-Agent':'repoctl-evidence-observer','X-GitHub-Api-Version':'2026-03-10'}});
  if(!r.ok)throw Error('GitHub observation rejected');const reader=r.body?.getReader();if(!reader)throw Error('Empty observation');let size=0;const chunks=[];
  while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>1048576){await reader.cancel();throw Error('Oversized observation');}chunks.push(value);}
  const bytes=new Uint8Array(size);let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.length;}return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
 }
 async function identity(){if((await get('')).id!==repositoryID)throw Error('Repository identity changed');}
 return {
  async tip(){await identity();const r=await get(`/git/ref/heads/${branch}`);if(r.ref!==`refs/heads/${branch}`||r.object?.type!=='commit'||!sha.test(r.object?.sha??''))throw Error('Invalid observed ref');return r.object.sha;},
  async commit(value){if(!sha.test(value??''))throw Error('Invalid commit SHA');await identity();const r=await get(`/git/commits/${value}`);if(r.sha!==value)throw Error('Commit identity changed');return r;},
  async workflowBytes(path,commitSHA){
   if(typeof path!=='string'||!/^\.github\/workflows\/[-A-Za-z0-9_.]+\.ya?ml$/.test(path)||!sha.test(commitSHA??''))throw Error('Invalid workflow target');await identity();
   const r=await get(`/contents/${path}?ref=${commitSHA}`);
   if(r.type!=='file'||r.path!==path||r.encoding!=='base64'||typeof r.content!=='string'||r.content.length>100000||!Number.isSafeInteger(r.size)||r.size<1||r.size>65536)throw Error('Invalid workflow content');
   const bytes=Uint8Array.from(atob(r.content.replace(/\s/g,'')),c=>c.charCodeAt(0));if(bytes.length!==r.size)throw Error('Workflow content length mismatch');return bytes;
  },
  async runForSuite(suiteID){
   if(!Number.isSafeInteger(suiteID)||suiteID<=0)throw Error('Invalid check suite');await identity();
   const r=await get(`/actions/runs?check_suite_id=${suiteID}&per_page=100`);
   if(r.total_count!==1||!Array.isArray(r.workflow_runs)||r.workflow_runs.length!==1||r.workflow_runs[0].check_suite_id!==suiteID)throw Error('Ambiguous workflow run');
   const run=r.workflow_runs[0];if(run.repository?.id!==repositoryID||run.head_repository?.id!==repositoryID||run.head_repository?.fork!==false)throw Error('Foreign or fork workflow run');return run;
  },
  async checks(value){
   if(!sha.test(value??''))throw Error('Invalid checks SHA');await identity();const checks=[];
   for(let page=1;page<=20;page++){
    const r=await get(`/commits/${value}/check-runs?filter=latest&per_page=100&page=${page}`);
    if(!Array.isArray(r.check_runs)||!Number.isSafeInteger(r.total_count)||r.total_count>2000)throw Error('Invalid or excessive check inventory');checks.push(...r.check_runs);
    if(checks.length>=r.total_count){if(checks.length!==r.total_count||checks.some(c=>c.head_sha!==value))throw Error('Checks do not bind exact candidate');return checks;}
    if(!r.check_runs.length)throw Error('Incomplete checks inventory');
   }throw Error('Check inventory pagination limit');
  }
 };
}
