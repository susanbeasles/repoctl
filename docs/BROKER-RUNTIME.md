# Remote broker runtime

The broker is repoctl infrastructure. FlareKit may deploy it but is not a runtime dependency. No production secret is required to build or run the local tests.

## Present behavior

The Worker forwards only POST `/v1/execution/lease` and `/v1/execution/complete` to one deployment-wide `BrokerCoordinator`. The checked-in configuration sets `BROKER_ENABLED` to `false`. Requests return HTTP 503 with `Cache-Control: no-store` until rollout is explicitly enabled and all required bindings are present. There is no public authorization-admission, key-upload, enrollment or arbitrary-signing route.

The coordinator serializes live handlers with an in-memory queue. Storage transactions separately make each operation/JTI reservation atomic and persistent. No provider network request happens inside a storage transaction. The global JTI namespace prevents reuse across operations; tombstones are not expired to enable retries.

Before issuing a token, the broker reads a trusted remote operation, validates signed executor OIDC and checks current authority and independent evidence. It reserves authority before provider I/O. The token is encrypted and journaled remotely before a successful lease response. Interrupted issuance cannot obtain another grant by retrying.

Completion authenticates fresh OIDC, independently observes the configured public GitHub repository and ref, requests completion verification and idempotent ledger finalization, and records the receipt. An executor's reported outcome is telemetry. Completion may finish a previously authorized write after approval expiry; it may not create fresh write authority.

## Required private service contracts

These bindings must refer to trusted deployed services. Do not bind them to demo implementations that return unconditional success. Service-binding identity is configured by infrastructure, not selected by a caller URL.

| Binding | Internal POST paths | Required responsibility |
| --- | --- | --- |
| `BROKER_AUTHORITY` | `/v1/authorization/load`, `/v1/authorization/check` | Verify enrollment, owner approval, policy acceptance, exact authorized run and current policy; return immutable operation/intent/trust records and independently re-check them at issuance. |
| `BROKER_VERIFIER` | `/v1/evidence/authorization`, `/v1/evidence/completion` | Independently validate candidate, signed approval bytes, anchored history, policy drift, security evidence and reconstructable archived Git objects. |
| `BROKER_SIGNER` | `/v1/github/app-jwt` | Sign only the enrolled writer App's internally constructed short-lived JWT using its remotely retained key. |
| `BROKER_RECEIPTS` | `/v1/ledger/finalize` | Independently verify completion and append an idempotent signed, linked receipt; retain an independently anchored checkpoint and recovery evidence. |

`load` receives only `{operationID}` and returns exactly `{operation,intent,trust}`. `operation` has the existing broker's strict retained-authorization schema. `intent` supplies the fixed repository/name/ID, main or master branch, base SHA, candidate SHA and tree SHA. `trust` supplies the existing exact OIDC policy plus writer `appID`. It is pinned when retained. `check` receives that retained record and returns `{operationID,accepted:true}` only after re-verification of current remote authority.

Verifier requests include `{operationID,operation,intent}`; successful responses bind `{operationID,verified:true}`. The verifier must fetch its independently retained approval/evidence records using the operation ID rather than trusting those requests as proof. Receipt finalization receives `{operationID,intent}` and returns `{operationID,digest}` only after durable, independently verified completion. A boolean response is the transport contract, not a replacement for these verification implementations.

Signer requests contain exactly `{appID,issuedAt,expiresAt}`. `app-signer.mjs` imports GitHub PKCS#1 or PKCS#8 PEM remotely into a non-extractable RSA key, constructs RS256 claims itself and rejects arbitrary fields, identities and lifetimes. Remote encrypted App-key storage and the actual isolated signer deployment remain required. Non-extractable software WebCrypto keys do not prove hardware protection.

## Token custody and recovery

`TOKEN_KEYRING_JSON` is a remote secret binding: an active key ID and a map of key IDs to base64-encoded 32-byte AES keys. Production generation and installation must happen through the isolated remote provisioning path; do not generate it locally and paste it into a CLI, chat or workflow file.

Tokens are encrypted with random 96-bit AES-GCM nonces and operation-bound authenticated data. Plaintext exists in the authorized broker/runner memory and HTTPS response; it is not persistently stored. This does not protect against compromise of the broker runtime or its remote KEKs.

Rotation is additive: install the new KEK remotely while retaining old keys, change the active ID, re-encrypt outstanding records, verify every record, then retire unused old keys. The custody primitive supports re-encryption; a journaled administrative rotation interface and independently verified recovery are still required. Do not remove a key while live records reference it.

The reservation transaction schedules an alarm at operation expiry. An alarm revokes orphaned tokens, retains encrypted values after revocation failures and retries after 60 seconds. Confirmed revocation or provider expiry removes ciphertext but retains metadata. The issuance kill switch does not stop cleanup. GitHub's HTTP 401 at its fixed revocation endpoint means that credential can no longer authenticate there.

An issuance response lost before the broker receives a token cannot be retroactively revoked by token value. Preserve its uncertain reservation, record an incident, and reconcile provider activity; do not mint again. The short operation lease does not shorten GitHub's approximately one-hour installation-token lifetime.

The first coordinator implementation scans retained lease records during recovery alarms. This is suitable for initial qualification, but a bounded due-work index and monitoring are required before substantial operation volume. Free-plan quota exhaustion can interrupt recovery; monitor alarms and credential cleanup independently.

## Local qualification

From `controller`:

```bash
npm ci
npm test
node scripts/qualify-broker-local.mjs
WRANGLER_SEND_METRICS=false ./node_modules/.bin/wrangler deploy --dry-run
```

The local qualification harness uses the Miniflare version supplied by pinned Wrangler. It validates real workerd SQLite transactions, replay rejection and atomic alarm scheduling without account credentials. Unit tests cover restart retention, concurrent reservation, ciphertext substitution, KEK rotation, orphan cleanup, constrained RSA JWT signing and Worker-to-executor transport with signed OIDC. Mock private services are test fixtures, not production adapters.

## Deployment and qualification gates

The new SQLite class is migration `v2`; preserve existing `v1` namespaces and receipt buckets. Public endpoints remain disabled by the existing `workers_dev:false` setting. Configure the desired origin explicitly at deployment; no personal domain is hardcoded.

Cloudflare supports SQLite Durable Objects on its free plan. Account limits still apply. Do not deploy service mocks, enroll production Apps, or enable App-only main protection to bypass missing infrastructure.

Before activation, implement and qualify:

1. Remote bootstrap authorization and isolated enrollment/MFA UI that does not expose manifest exchange codes, App PEMs or production credentials on the operator machine.
2. Actual hardware enrollment assurance. A client label or public key is insufficient; document what the device can and cannot attest.
3. The trusted authority, verifier, encrypted App-key custody/signer and independently anchored ledger services above.
4. Independently verified recoverable Git-object archives and recovery coverage, separate from receipt storage and without archive decryption keys in this Worker.
5. Journaled remote provisioning, rotation, incident reconciliation, monitoring and a tested recovery path.
6. Disposable live GitHub/Cloudflare qualification of exact reusable-workflow OIDC claims, single-child promotion, stale/altered/fork/outsider rejection, lost responses, revocation and rotation.

No live deployment or enrollment is implied by a successful dry-run. Finish these gates before setting `BROKER_ENABLED=true` or applying App-only main protection.

## Platform references

- [Cloudflare transaction storage API](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/)
- [Cloudflare Durable Object alarms](https://developers.cloudflare.com/durable-objects/api/alarms/)
- [Cloudflare Durable Object pricing and free-plan limits](https://developers.cloudflare.com/durable-objects/platform/pricing/)
- [GitHub App manifest enrollment](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest)
- [GitHub App private-key management](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps)

## Baseline at credential issuance

The independent broker authorization observer now requires remote baseline
verification before reading the candidate and again before confirming current
authority. The binding fixes retained repository ID, accepted policy revision and
digest, protected target and base SHA. `OBSERVATION_BASELINE` is mandatory for
`/v1/evidence/authorization`; absent binding returns503 before downstream calls.
Drift, wrong binding or unavailable verifier blocks credential issuance through
the existing `verifyAuthorization` path. Local doctor output cannot substitute.

Completion observation deliberately does not require a currently healthy baseline:
it independently proves an already performed update against retained approvals
and issued lease. Removing the baseline service or observing later drift cannot
be used to discard historical completion or prevent credential cleanup/receipts.
This observer cannot mint credentials in that recovery path.

This increment verifies the pre-issuance gate. A fresh OIDC-authenticated execution
check immediately before the executor PATCH still needs implementation; issuance
checks alone cannot guarantee controls remain unchanged afterward. Provider ref
transaction/restrictions and effective drift checks must be qualified live before
production enablement. No baseline authority is commissioned here.

## Fresh authenticated execution check

POST `/v1/execution/check` now accepts only operationID and executor OIDC token
through the same disabled-by-default broker/coordinator boundary. It requires the
exact current hardware-authorized promotion, accepted policy/ref, live issued
lease and provider lifetime, and the pinned executor run/attempt OIDC signature.
It repeats independent current authorization, baseline and fast-forward
verification; retained operation/lease and lifetime must remain unchanged after
collection. Response contains exact public intent/expiry only, with no-store.
It issues no credential, reserves no new authority and changes no Git ref.

Both executor source copies now obtain fresh OIDC and call this check after local
GitHub candidate/tip observations and immediately before the single force:false
PATCH. Denial, changed intent or mismatched/expired lease stops PATCH while
credential revocation and independent completion reporting still run. Existing
check responses cannot authorize a different candidate or extend the lease.
Repeated read-only checks are not additional token issuance; only the first lease
request can mint a token. An absent issued lease denies before JWKS/authority.

This reduces the stale-authorization window; it does not make GitHub's REST ref
update an atomic transaction with external policy observation. Effective provider
restrictions and live governance must still be qualified. Controller/Worker tests
use actual RSA OIDC verification with synthetic provider/service responses;
local workerd bundles/qualifiers pass, but production endpoint remains disabled
and uncommissioned. No live protected ref or credential was mutated.
