# Signer enrollment integration

`AppEnrollmentService` and `AppSignerService` are separate named private entrypoints. Both use the same signer Durable Object, keeping the App credentials in one custody boundary. The broker entrypoint accepts only fixed App JWT signing requests. It cannot create enrollment sessions. The enrollment entrypoint cannot request a JWT.

Enrollment requires APP_ENROLLMENT_ENABLED=true, a remote APP_KEYRING_JSON secret binding and an APP_ENROLLMENT_APPROVAL private service binding. Both enrollment and signing remain disabled in the shipped config. No public enrollment route is added.

The approval service receives POST /v1/enrollment/authorize with operationID, approvalReference and action (create, exchange, reconcile or status). It must independently authenticate the approved isolated enrollment and return accepted, the matching references, and the approved session containing ownerID, role, expiresAt and manifestDigest. The signer binds subsequent actions to the retained owner, role and manifest digest. Request data cannot supply these values. The approval service must evaluate current revocation and authorize reconciliation separately when the original session expires. This service is not yet implemented; do not substitute a permanent accepted=true response.

The isolated callback caller supplies code only to exchange. Session/code references and bodies are bounded and errors are sanitized. Credential responses remain inside the signer Worker. This transport does not by itself isolate the user's browser: the browser/session host and authenticated initiation still need implementation.

## Qualification

```bash
cd ~/code/repoctl
(cd controller && npm test && npx wrangler deploy --config wrangler.signer.jsonc --dry-run --outdir /tmp/repoctl-enrollment-dry-run)
node controller/scripts/qualify-enrollment-local.mjs /tmp/repoctl-enrollment-dry-run/entrypoint.js
```

The integration test uses actual workerd RPC, SQLite transactions and persistent storage. It checks public rejection, role separation, denied approval, concurrent callback reservation, staged retention after provider verification failure, restart recovery without re-conversion and independently verified RSA JWT signing. Provider and owner-approval services are synthetic; it does not use live GitHub credentials. All temporary persisted credentials are synthetic and deleted after qualification.

The pinned Miniflare converter drops the old durableObjectsPersist option. The test therefore sets resourcePersistencePath explicitly on the converted options. The test actually restarts workerd and reads the retained enrollment record.

## Runtime compatibility fix

workerd rejects redirect:error. Affected broker service-binding, GitHub credential, GitHub observer, enrollment and OIDC-key calls now use redirect:manual and reject non-success responses, including redirects. They never follow a Location header. A regression test confirms conversion does not follow redirects. Other clients, including the Node executor, remain separate.

## Remaining activation gates

Implement isolated authenticated session initiation and approval service, remote KEK provisioning/recovery, accepted-policy and hardware verifier services, independent archive/security/history evidence and ledger receipts. Connect production bindings and qualify a disposable live issuance, execution, revocation and reconciliation run. Main App-only protection must wait until that path works.
