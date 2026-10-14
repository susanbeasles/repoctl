// Runs only inside op run. Write allowed values to a private parent pipe, never
// to a log/artifact. No bootstrap token or unrelated Environment variable leaves.
const names=['CLOUDFLARE_API_TOKEN','CLOUDFLARE_ACCOUNT_ID','ZONE_ID'];
process.stdout.write(JSON.stringify({variables:names.filter(name=>process.env[name]).map(name=>({name,value:process.env[name]}))}));
