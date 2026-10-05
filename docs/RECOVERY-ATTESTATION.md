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
