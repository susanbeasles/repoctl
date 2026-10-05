# Governance extension status

The accepted design is [GOVERNANCE-SPEC.md](GOVERNANCE-SPEC.md). Its command
examples and acceptance criteria are targets, not descriptions of installed
capabilities. Preserve the existing exact-byte policy signatures; a future
canonical-policy protocol must use an explicit version and authorized migration.
Do not reinterpret accepted v1 signatures.

## Present implementation

- Owner/event Actions configuration and secret scanning work on the personal repo.
- Native arm64 CLI and promotion-core tests pass on the operator's Mac.
- Receipt webhook intake exists; it remains unable to promote.
- Split protection and operation approval primitives exist, but are not a complete
  enrolled production delivery path. Software Keychain approval is available in
  the preview and does not satisfy production hardware-only authorization.
- New executor OIDC verifier checks GitHub signature, fixed issuer, per-operation
  audience, numeric executor repo/owner, actor, event, ref, caller workflow and
  reusable workflow identity/revision, hosted runner, run ID and attempt, lifetime
  and replay identity. Candidate-controlled/project workflows are not executors.
- New broker requires remotely retained authorization, accepted policy revision,
  verified hardware enrollment and exact executor run before reserving authority.
  Only one enrolled repository with Contents-write is requested. Unexpected scope
  triggers revocation and a retained uncertain state, not a broad fallback.
- New remote manifest enrollment core passes secret-bearing provider responses
  directly to remote staging/verification adapters and returns only public status.

## Credential semantics

The broker function's return value is SECRET and belongs exclusively to the
central executor HTTPS transport. It must never be sent to CLI, browsers, general
project runners, artifacts, traces, receipts or logs. The authenticated response
must use `Cache-Control: no-store`; credentials must be revoked in executor
finally paths and after uncertain/expired leases. Execution routes are now wired behind an explicit disabled-by-default rollout
gate and required private service bindings. They cannot issue authority with the
checked-in configuration. See [broker runtime](BROKER-RUNTIME.md).

GitHub installation tokens have a provider lifetime of about one hour. The
operation lease is at most five minutes, but that does NOT reduce the stolen
token's provider-enforced lifetime or make it ref-scoped. Report both lifetimes.
Contents-write is broader than the intended one ref update; isolate the executor
and revoke temporary credentials. The App JWT signer accepts only its enrolled
identity and internally generated timing claims, not arbitrary signing requests.

Hardware enrollment is trusted remote state, not a request's `provider: hardware`
label. Its verifier and enrollment proof remain to be implemented. No hardware
origin guarantee follows merely from storing a P-256 public key. SEP origin
verification/attestation limitations must be resolved and documented explicitly.

## Remote onboarding boundary

Manifest registration redirects through a temporary credential-bearing code.
Server-side exchange alone does not prove that local screen recording cannot
capture that code. Run secret-bearing registration/callback/download UI in the
isolated remote provisioning browser, with no local rendering, download or
clipboard path. Local operator interaction must be limited to sanitized consent
and supported MFA approval. The remote browser and MFA transport are not
implemented here; do not substitute local browser registration and claim the
no-local-exposure requirement has been met.

Enrollment session consume must be atomic, expiring, bound to initiating identity,
role, expected owner/manifest and one use. A remote journal must retain staged
credential references and uncertain outcomes. A lost one-shot manifest exchange
can strand an App whose key was not retained; record an incident and recover
server-side rather than blindly repeat onboarding or ask the operator to fetch
PEMs. No module promises that JavaScript can securely erase strings from memory.

## Still required before active enrollment

1. Remote infrastructure/bootstrap authorization and isolated provisioning UI.
2. Encrypted remote credential storage/signer and enrollment proof verifier.
3. Trusted accepted-policy admission and independently anchored signed receipts.
4. Live qualification of the durable broker HTTP routes and central executor.
5. Immutable candidate generation and independently verified security evidence.
6. Baseline drift evaluation, native PR/FF compatibility tests and a complete
   positive/adversarial promotion in disposable GitHub repositories.
7. Rotation, release/publishing and independent archive/restore integration.

FlareKit remains an optional archive adapter. None of these primitives require
installing fk or yk. Production hardware approval may use an optional yk adapter
once its proof/enrollment contract is validated; unavailable required hardware
blocks production instead of falling back to software.


## Central execution increment

Central dispatch and local reusable executor source now exist under
`delivery_control/`, with a read-only shared validation entry point under
`workflow_depot/`. The broker HTTP handler and executor are covered by mock
transport tests. [Central execution handoff](CENTRAL-EXECUTION.md) lists the
production adapters and GitHub OIDC qualification required before connecting the
handler to a public route. The operator has published both central repositories using the bootstrap helper.
Promotion remains inactive pending the remote trust services and live qualification.


## Durable broker runtime increment

- Worker execution routes and a deployment-wide SQLite Durable Object exist.
- Operation and JWT replay reservations commit atomically with recovery alarms.
- Provider tokens are AES-256-GCM encrypted before persistent storage, with
  operation-bound authenticated data, additive KEK rotation and cleanup alarms.
- Disabling new issuance does not disable credential cleanup.
- Current authority, independent verification, remote signer and independent
  receipt services are required private bindings; their absence blocks issuance.
- Remote RSA App-key import and constrained JWT signing primitives exist; remote
  encrypted App-key storage, isolated enrollment and signer-service deployment
  remain unimplemented. A non-extractable WebCrypto key is not hardware-backed.
- Runtime HTTP/OIDC integration is tested against mock GitHub and private services.
  Real local workerd validates the SQLite reservation transaction and alarm API.

The earlier outstanding-items list remains applicable to production. Durable
execution state and routes now have implementations, but trusted policy admission,
hardware proof verification, reconstructable archive verification, independently
anchored receipt persistence, isolated enrollment, and live qualification are still
blocking. No production credential or protection change was performed here.


## Private authorization increment

A separate private Worker entrypoint and durable admission service now implement
the broker authority contract. They verify existing owner/validator approvals, a
new exact-run owner signature, signer fingerprints, accepted executor trust, live
hardware-verifier results, independent evidence and pending-repository exclusion.
Completion releases the pending slot only through independently verified receipt
reconciliation; nonce tombstones remain. See [authorization service](AUTHORIZATION-SERVICE.md).

The native `approval sign-run` command preserves exact reviewed bytes in a new
domain. Its macOS compile/signature smoke test is supplied but was not run in the
Linux development environment. Existing v1 approval protocols remain unchanged.
Hardware verifier, accepted-policy bootstrap, evidence/archive verifier and
independent receipt implementations remain required bindings, not implemented
production assurances. The private service and broker remain disabled.
