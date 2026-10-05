# Private authorization service

This increment implements the broker's `BROKER_AUTHORITY` contract in a separate Worker. Its default public fetch handler always returns 404. Only the named `AuthorizationService` entrypoint, reached through an explicitly configured Cloudflare service binding, forwards requests to a SQLite Durable Object. Deployment is disabled by default.

## Approval binding

Admission accepts exactly `{owner,validator,executionOwner}`. Owner and independent validator signatures use the existing promotion domains and must bind identical intent bytes. The execution owner must be the same enrolled key as the promotion owner; its separate `repoctl-execution-owner-v1` signature binds:

- operation ID, equal to the promotion intent's nonce;
- digest of the exact owner/validator approval envelopes;
- target repository name and ID, and main/master ref;
- accepted policy revision and exact policy-file digest;
- digest of the complete accepted executor trust record;
- exact workflow run ID and attempt;
- expiry in Unix seconds, at most five minutes and no later than the promotion approval.

The promotion intent expiry remains Unix milliseconds. Existing policy seals and promotion signatures are not reinterpreted. The new signing command is `repoctl approval sign-run RUN_INTENT --policy POLICY --approve`. It preserves reviewed file bytes and writes a separate execution approval envelope. It performs one signing operation when explicitly invoked; it does not automatically invoke promotion signing. This implementation requires distinct promotion and execution approval envelopes. Combined single-signature approval would require an explicitly versioned protocol change, not an implicit migration.

The authority imports approved P-256 public keys, verifies their SHA-256 fingerprints, and rejects an owner key reused as validator. It pins the central workflow paths/revision and does not accept arbitrary workflow URLs, commands or refs.

## Private API

| POST path | Purpose |
| --- | --- |
| `/v1/authorization/admit` | Verify all approvals, current policy, live hardware enrollment and independent candidate/archive evidence; retain one pending operation per repository. |
| `/v1/authorization/load` | Return the broker's fixed operation, execution intent and executor trust record. Expired records remain readable for reconciliation; reads do not grant write authority. |
| `/v1/authorization/check` | Compare the caller's record with retained bytes, then re-check signatures, expiry, current policy, hardware revocation and evidence before issuance. |
| `/v1/authorization/reconcile` | Release the repository lock only after independently verified promoted state and matching receipt. Retain the operation tombstone permanently. |

An operation ID cannot be rebound to different approvals or another run. Concurrent generations cannot both enter the pending repository slot. A failed or abandoned run is not automatically removed: safe cancellation requires broker lease/token closure and independent reconciliation, still to be implemented. The service does not infer permission to retry from expiry.

## Required trusted bindings

`AUTHORIZATION_ENABLED=true` is insufficient by itself. The coordinator requires:

| Binding | Internal POST contract |
| --- | --- |
| `ACCEPTED_POLICY` | `/v1/policy/current` receives `{repositoryID}` and returns the remotely accepted policy and executor trust record. |
| `HARDWARE_ENROLLMENT_VERIFIER` | `/v1/enrollment/verify` receives repository/key/policy identities and returns matching `keyID`, `proofDigest`, `hardwareVerified:true`, `revoked:false` and live `validUntil`. |
| `AUTHORIZATION_EVIDENCE` | `/v1/evidence/admission` receives operation ID, signed promotion approvals and intent; independently validates anchored history, candidate, checks and reconstructable archived objects, returning matching operation/intent digests. |
| `AUTHORIZATION_RECEIPTS` | `/v1/ledger/observe` independently verifies completed promotion and signed receipt, returning matching operation ID/candidate SHA, receipt digest and verified promoted state. |

These are real verification boundaries, not success stubs. Hardware origin is not proven by a key label or a self-supplied boolean. Actual hardware attestation/enrollment verification, policy bootstrap, evidence verification and independently anchored receipt storage remain production blockers. Neither request bodies nor the authority's tests can establish hardware origin by themselves.

The accepted policy schema is enforced by `importPolicy` in `controller/src/authority/authorize.mjs`. Executor trust is restricted to the published central `promote.yml` caller and `executor.yml` reusable workflow on main, exact matching commit revisions, workflow_dispatch, enrolled actor IDs, one target repository and one installation. Public numeric IDs and workflow SHAs must be discovered and enrolled during live qualification; fixture IDs are never deployment configuration.

Broker-to-authority wiring, once all gates pass:

```json
{
  "binding": "BROKER_AUTHORITY",
  "service": "repoctl-authorization",
  "entrypoint": "AuthorizationService"
}
```

Do not enable the authority or broker using the checked-in test mocks. This service holds approvals and public trust records, not GitHub App private keys, installation tokens or archive decryption keys.

## Qualification

From controller:

```bash
npm test
WRANGLER_SEND_METRICS=false ./node_modules/.bin/wrangler deploy \
  --config wrangler.authority.jsonc --dry-run --outdir /tmp/repoctl-authority-check
node scripts/qualify-authority-local.mjs /tmp/repoctl-authority-check/entrypoint.js
```

The local workerd check verifies that public ingress is closed and the private entrypoint denies requests while verifiers are unconfigured. Unit tests verify signatures, DER interoperability, target/run binding, policy changes, hardware revocation, concurrent generations and independent completion. These tests use mock remote proof/evidence services and do not constitute live hardware or archive qualification.

On macOS, run `./Tests/mac-execution-approval.sh` to compile the native command, create a clearly synthetic software enrollment, independently verify its DER signature using Node crypto, and reject expired approval. This does not enroll a production key or invoke a remote action. Test Keychain enrollment is retained for explicit cleanup.

No production service has been deployed by this increment. Isolated GitHub App registration, credential bootstrap/rotation, actual hardware proof verification, archive/ledger services, operator admission transport and disposable live GitHub qualification remain required before locking main to the writer.
