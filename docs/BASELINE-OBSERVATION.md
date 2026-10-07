# Remote baseline configuration observation

`baselineObserver` reads the existing repository-baseline-v1 schema without
changing its sealed bytes or approval semantics. Installed configuration fixes
numeric owner/repository, accepted policy revision/digest and the baseline body;
provider reads are an installed repository-scoped capability. Caller URLs or new
baseline acceptance are not exposed. The baseline is snapshotted before awaits.

The observer compares identity/default branch/protected tip, repository settings,
all inherited and repository ruleset bodies, all inherited Actions policy bodies,
Actions/selected-actions/workflow permissions and immutable-release settings.
Inventories are sorted by unique numeric IDs and include full conditions/rules,
source identity and bypass actors. Missing/duplicate/foreign/detail mismatches,
permission denial, oversized pages and an unterminated20-page inventory deny.
It collects twice and checks identity/tip again after the last control read.
Abort signals propagate to provider reads; transport must independently bound
requests and honor cancellation. Observations are not atomic provider snapshots.

The result deliberately uses configurationVerified and has no verified:true or
drift:false authorization assertion. The mandatory baseline gate rejects this
observation alone. Accepted signature/hardware enrollment and independently
qualified effective enforcement must be combined by the remote baseline authority
before that service may return an authorization-grade proof. That authority and
live provider qualification remain unfinished; no permissive fallback exists.
Canonical observation digest is a report fingerprint, not a new interpretation
of existing exact-byte policy signatures.

Tests cover complete collection, foreign/missing/duplicate controls, mid-read
control drift, a final protected-tip move, caller baseline mutation, suppressed
provider errors, rejection by the authorization gate and20full-page truncation
with2000 independent details. Provider responses are synthetic; no actual owner
configuration is enrolled or mutated by these tests. Strict type checks and the
complete170-test controller suite pass. Source remains unpublished pending the
existing configured hardware signing blocker.
