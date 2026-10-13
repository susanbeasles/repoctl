import {spawn} from 'node:child_process';
import {pathToFileURL} from 'node:url';
const account = '1a799c6e699d2ef7e87398692ce3ad7b';
const permitted = new Set(['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID', 'ZONE_ID']);
export async function loadEnvironment(env, factory) {
  if (!env.OP_ENVIRONMENT_ID) throw Error('Missing OP_ENVIRONMENT_ID: configure the authorized 1Password Environment ID');
  if (!env.OP_SERVICE_ACCOUNT_TOKEN) throw Error('Missing OP_SERVICE_ACCOUNT_TOKEN bootstrap');
  let response;
  try {
    const createClient = factory ?? (await import('@1password/sdk')).createClient;
    const client = await createClient({auth: env.OP_SERVICE_ACCOUNT_TOKEN, integrationName: 'delivery-control', integrationVersion: '1.0.0'});
    response = await client.environments.getVariables(env.OP_ENVIRONMENT_ID);
  } catch { throw Error('1Password Environment loading failed'); }
  const values = {};
  if (!Array.isArray(response?.variables)) throw Error('Invalid 1Password Environment response');
  for (const row of response.variables) {
    if (!permitted.has(row.name)) continue;
    if (Object.hasOwn(values, row.name) || typeof row.value !== 'string' || !row.value || /[\r\n\0]/.test(row.value)) throw Error('Invalid deployment variable');
    values[row.name] = row.value;
  }
  if (!values.CLOUDFLARE_API_TOKEN || values.CLOUDFLARE_ACCOUNT_ID !== account) throw Error('Missing Cloudflare credential or account mismatch');
  if (values.ZONE_ID && !/^[a-f0-9]{32}$/.test(values.ZONE_ID)) throw Error('Invalid zone identifier');
  const child = {...env};
  for (const name of ['OP_SERVICE_ACCOUNT_TOKEN','OP_ENVIRONMENT_ID','NODE_OPTIONS',...permitted]) delete child[name];
  return {...child,...values};
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const [command,...args] = process.argv.slice(2);
    if (!command) throw Error('Missing child command');
    const env = await loadEnvironment(process.env);
    if (process.env.GITHUB_ACTIONS === 'true') console.log('::add-mask::' + env.CLOUDFLARE_API_TOKEN.replaceAll('%','%25'));
    const child = spawn(command,args,{env,stdio:'inherit',shell:false});
    child.on('error',()=>{console.error('Deployment process failed to start');process.exitCode=1;});
    child.on('exit',code=>{process.exitCode=code ?? 1;});
  } catch (error) { console.error(error.message); process.exitCode=1; }
}
