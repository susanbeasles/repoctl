# Conditional recovery report publication

`recoveryR2Publisher` implements the recovery job publisher interface against an
installed R2 bucket binding. It conditionally creates canonical JSON using
`etagDoesNotMatch: '*'`, reads retained bytes back, and rejects conflicting
content. Identical retries succeed without writing again. A lost PUT response is
surfaced; reconciliation with the retained exact envelope succeeds.

This adapter has no network endpoint or caller-selected bucket. It accepts only
`recovery/v1/<numeric repository ID>/<64 hex intent digest>.json` keys, limits
objects to 4 MiB, and checks declared versus actual read size. The bucket binding
itself grants storage authority; there is no claim that JavaScript prevents its
holder from calling other bucket methods.

Conditional creation is not a retention lock. Provision and independently verify
bucket retention separately. Existing reports are never overwritten, including
expired reports. Current intent-keyed storage cannot renew an expired report for
the identical intent; revision selection and signed renewal remain a separate
protocol change. Do not delete the old evidence to bypass that restriction.

This publisher runs where an R2 binding exists. The local recovery job still
requires an authenticated upload bridge or a native storage adapter; the module
does not magically provide a bucket binding to a Node process. The remote archive
reader must trust only enrolled recovery signatures, not an uploader identity
alone. Live bucket qualification is still pending.
