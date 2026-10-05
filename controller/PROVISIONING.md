> **Legacy intake-only instructions.** This workflow does not satisfy the production
> credential-provisioning requirements in [the governance specification](../docs/GOVERNANCE-SPEC.md).
> Do not use manual local webhook/App secret handling to provision promotion.
> The remote enrollment/broker extension is not deployed by these commands.

# Provisioning webhook intake

This stage deploys authenticated, owner-only event intake and receipt archival. Promotion, Git backups, signed ledger publication, and GitHub App writes remain disabled. R2 bucket locks are not configured by these commands.

Use Node 22 or newer. Wrangler is pinned by package.json and package-lock.json; no Homebrew or global npm installation is required.

```sh
cd ~/code/repoctl/controller
npm ci --ignore-scripts
./node_modules/.bin/wrangler login
./node_modules/.bin/wrangler whoami
```

Choose your personal Cloudflare account ID from `whoami`. Generate local configuration using that ID, your GitHub repository's numeric ID, and your personal GitHub user's numeric ID. The command refuses to overwrite an existing configuration.

```sh
node scripts/configure.mjs YOUR_CLOUDFLARE_ACCOUNT_ID 1404914851 215839550
./node_modules/.bin/wrangler deploy --config wrangler.local.json --dry-run
./node_modules/.bin/wrangler r2 bucket create repoctl-archive --config wrangler.local.json
./node_modules/.bin/wrangler secret put GITHUB_WEBHOOK_SECRET --config wrangler.local.json
./node_modules/.bin/wrangler deploy --config wrangler.local.json
```

Generate a unique webhook secret in your password manager. Paste it only at Wrangler's secret prompt and later into the GitHub App webhook-secret field. Do not put it in a command argument, committed file, or chat. Creating the bucket requires R2 to be enabled in your account; an existing bucket should be inspected and reused rather than recreated.

The deployment output provides the HTTPS workers.dev address. Append `/github/webhook` for the GitHub App webhook URL. Other routes return 404. Cloudflare account configuration may require choosing a workers.dev subdomain first.

Do not enable repository protections or install an App with write authority yet. First record the deployed URL and account ID, then prepare the App and retention policy. This intake configuration currently allows only events attributed to the repository owner; add a verified App bot user ID explicitly when implementing App-originated events. GitHub ping events are ignored with HTTP 202.

## Checks

```sh
npm test
./node_modules/.bin/wrangler tail --config wrangler.local.json
```

A request without a valid webhook HMAC must be rejected with 401. An authorized event should archive one receipt and respond with `promotion: disabled`. An identical delivery retry must not replace the object. These remain live verification steps; the unit tests use mocks.

Wrangler documentation: https://developers.cloudflare.com/workers/wrangler/commands/

R2 bucket locks: https://developers.cloudflare.com/r2/buckets/bucket-locks/
