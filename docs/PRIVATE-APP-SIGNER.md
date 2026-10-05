# Private GitHub App signer

The signer Worker has no public signing endpoint. Its default handler returns 404. The named `AppSignerService` entrypoint is intended solely for the broker's `BROKER_SIGNER` service binding. It accepts only POST `/v1/github/app-jwt`, bounds request bytes to 2 KiB, sanitizes failures and disables response caching.

`wrangler.signer.jsonc` packages a SQLite Durable Object and leaves `APP_SIGNER_ENABLED=false`. Required remote configuration is `APP_KEYRING_JSON` (remote secret binding) and `APP_CREDENTIAL_REFERENCE` (the enrolled vault reference). Neither the request nor the broker selects a credential reference or key. Active vault credentials alone can sign the fixed App JWT claims. The signer receives no repository content or arbitrary payload to sign.

No public enrollment, plaintext credential read, or key upload endpoint is provided. Enrollment must write and verify the credential within this signer custody boundary using a separately authorized isolated flow. That integration remains unfinished; deploying this disabled package alone does not enable issuance.

## Local qualification

Run from the repository root:

```bash
(cd controller && npm ci && npm test)
(cd controller && npx wrangler deploy --config wrangler.signer.jsonc --dry-run --outdir /tmp/repoctl-signer-dry-run)
node controller/scripts/qualify-signer-local.mjs /tmp/repoctl-signer-dry-run/entrypoint.js
node controller/scripts/qualify-app-vault-local.mjs
```

The first runtime test checks closed public ingress and disabled private signing in workerd. The second creates only a synthetic RSA key and checks ciphertext persistence, staged refusal, trusted activation, RSA JWT signing and revocation using actual workerd SQLite Durable Object storage. The qualification verifier is intentionally synthetic and is never deployed. These tests do not validate live GitHub credentials, remote enrollment, Cloudflare production bindings, or restart recovery of this signer.

## Remaining activation work

Implement journaled isolated manifest enrollment, exact GitHub App identity/permission verification, remote wrapping-key provisioning and recovery, then connect the broker binding. Independently qualify accepted policy, hardware enrollment, archive evidence and ledger receipts. Perform a disposable live issue/revoke/reconcile test before applying App-only protection to useful repositories.
