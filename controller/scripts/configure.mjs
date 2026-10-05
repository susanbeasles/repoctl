import { readFile, writeFile } from 'node:fs/promises';

const [accountID, repositoryID, ownerID] = process.argv.slice(2);
if (!/^[a-f0-9]{32}$/.test(accountID ?? '') ||
    ![repositoryID, ownerID].every(value => /^[1-9][0-9]*$/.test(value ?? '') && Number.isSafeInteger(Number(value)))) {
  console.error('Usage: node scripts/configure.mjs CLOUDFLARE_ACCOUNT_ID GITHUB_REPOSITORY_ID GITHUB_OWNER_ID');
  process.exit(1);
}
const config = JSON.parse(await readFile(new URL('../wrangler.jsonc', import.meta.url), 'utf8'));
config.account_id = accountID;
config.workers_dev = true;
config.preview_urls = false;
config.vars = {
  REPOSITORIES_JSON: JSON.stringify([{ repositoryID: Number(repositoryID), ownerID: Number(ownerID), actorIDs: [Number(ownerID)] }]),
};
await writeFile(new URL('../wrangler.local.json', import.meta.url), JSON.stringify(config, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
console.log('Created wrangler.local.json. Owner-only webhook intake; promotion remains disabled.');
