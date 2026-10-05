# Enrollment approval renewal

An expired registration approval must not reopen a one-shot manifest conversion. The private enrollment authority accepts `POST /v1/enrollment/renew` with exactly:

```json
{
  "previousReference": "current approval reference",
  "envelope": "new signed enrollment approval envelope object"
}
```

`envelope` is an object, not the explanatory string shown above. Use the existing `repoctl approval sign-enrollment INTENT --policy POLICY --approve` command to sign a new intent. Preserve the original operation ID, owner ID, role and manifest digest. Change only `expiresAt` to a later timestamp, no more than five minutes into the future. The same currently trusted, non-revoked hardware approver must sign. The private transport must not expose App credentials.

The authority atomically replaces the approval reference and records the retired reference as a tombstone. Requests must use the new reference. Exact retries are idempotent while the fresh approval remains valid. A stale parent reference, altered role or manifest, different owner or signer, excessive lifetime or current hardware revocation is rejected.

A renewed approval authorizes only `status` and `reconcile`. It never authorizes `create` or `exchange`. The registration service accepts the new reference for recovery only after independent authority readback binds it to the retained manifest and configured owner. Custody performs its own authorization check again.

Renewal does not extend the original callback session or permit another manifest conversion. If the provider response was lost before credential retention, reconciliation still fails with an uncertain outcome. Recovery then requires an isolated operator incident procedure; there is no automatic retry or PEM download fallback.

The native signing command and private authority are implemented. An authenticated CLI-to-private-service transport and deployed trust/hardware verifier are still prerequisites for live use. Production remains disabled.
