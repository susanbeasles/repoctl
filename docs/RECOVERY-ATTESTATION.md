# Authenticated recovery evidence

`attestedRecovery` adapts installed evidence storage and an installed P-256
recovery signer inventory to the admission archive interface. Lookup is by the
canonical intent digest. Requests cannot choose keys, endpoints or policy roots.

A dedicated trusted recovery job signs a ledger envelope whose payload is:

```json
{"kind":"archive-recovery","policyDigest":"64 lowercase hex","verifiedAt":0,"expiresAt":1,"report":{"protocol":"repoctl-archive-evidence-v1","intent":{},"objects":[],"recovery":{}}}
```

The report is the exact body emitted by the Git recovery verifier, without its
computed digest or success flags. Maximum lifetime is five minutes. The verifier
checks the envelope signature, installed policy digest, freshness, exact intent,
object inventory, approved archive membership and recovery summary, then computes
the report digest itself. Revocation is enforced by removing the signer from the
installed trusted inventory. Retain historical public keys separately for audit;
historical validity does not confer current admission authority.

This authenticates a trusted recovery job's assertion. It does not independently
re-execute decryption inside a Worker or provide hardware execution attestation.
The job must fetch the approved FlareKit manifest, authenticate/decrypt and
restore it, verify Git closure, and only then sign. Signing keys must be separate
from promotion writer credentials. No caller-provided report or success boolean
is accepted without a trusted signature.

The store and remote job transport are not provisioned by this module. Existing
remote services remain disabled until those bindings and signer custody are
configured and live qualification succeeds.

## Private Worker adapter

Deploy `wrangler.archive-evidence.jsonc` with a `RECOVERY_REPORTS` R2 binding
and `ARCHIVE_EVIDENCE_CONFIG_JSON` installed configuration. Each repository entry
contains `repositoryID`, `policyDigest`, and `keys` (public `keyID` SHA-256
fingerprint and base64 `publicKeyX963`). No private signing or age key belongs in
this Worker. Set `ARCHIVE_EVIDENCE_ENABLED=true` only after qualification.

Bind admission's `EVIDENCE_ARCHIVES` to the named `ArchiveEvidenceService`
entrypoint. Default public fetch always returns 404. The private entrypoint
accepts only POST `/v1/evidence/archive` with `{ "intent": ... }` and returns
sanitized errors with no-store headers.

The trusted recovery publisher stores signed envelopes at
`recovery/v1/<repositoryID>/<canonical-intent-sha256>.json`. Reports are limited
to 4 MiB and intents to 16 KiB. The reader has no upload, delete, signing,
decryption or promotion API. Grant the dedicated publisher separate bucket
credentials; publication and encryption recovery are still separate work.
