# Combined promotion evidence

The admission verifier composes installed GitHub, anchored history and archive
recovery adapters. It independently verifies owner and validator signatures,
checks the exact approved intent and recomputes component report digests. All three
components must match the proposal. It rereads accepted policy and checks expiry
before returning the authority's `verified: true` admission response.

Candidate evidence additionally requires the private `EVIDENCE_SIGNATURES`
designated-signer service described in [GitHub evidence](GITHUB-EVIDENCE.md).
Admission refuses missing, foreign, revoked or unavailable verification even
when GitHub reports a valid signature. Production commissioning remains required.

The stable report contains protocol `repoctl-admission-evidence-v1`, repositoryID,
policyDigest, githubDigest, historyDigest and archiveDigest. Its canonical SHA-256
becomes the intent's evidenceDigest before signing. Nonce, expiry and evidenceDigest
are excluded from component proposals to avoid self-reference.

Private named Worker entrypoint AdmissionEvidenceService implements only POST
`/v1/evidence/admission`. Bind it as AUTHORIZATION_EVIDENCE on the authority.
Public ingress returns 404, workers.dev is disabled, admission starts disabled.

| Binding | Required capability |
|---|---|
| EVIDENCE_POLICY | AcceptedPolicyService `/v1/policy/current` |
| EVIDENCE_HISTORY | Private anchored history `/v1/evidence/history` |
| EVIDENCE_ARCHIVES | Private recovery verifier `/v1/evidence/archive` |
| EVIDENCE_SIGNATURES | Designated candidate and current role verifier `/v1/candidate/verify` |

EVIDENCE_CONFIG_JSON is an array of records with exactly repositoryID, repository,
targetRef, policyDigest, requiredChecks and actorIDs. requiredChecks uses the GitHub
evidence recipe schema. Repository and policy digest must match accepted policy.
No caller can select a recipe or redirect verification.

Archive adapters receive `{intent}` containing repositoryID, commitSHA, sourceSHA,
treeSHA and archiveDigests. Return protocol `repoctl-archive-evidence-v1`, exact intent,
objects, recovery, archiveVerified true, recoveryVerified true and the canonical digest
of `{protocol,intent,objects,recovery}`. The adapter must actually retrieve, verify and
restore retained objects. ETags and upload acknowledgments do not establish recovery.
No archive recovery adapter is supplied here. Installed components are trusted code;
digest validation establishes binding, not truth if a verifier is compromised.

This entrypoint does not implement BROKER_VERIFIER authorization/completion routes.
Those must use retained authority state and distinguish pre-write checks from post-write
reconciliation. Binding the broker directly to this entrypoint fails closed.
Independent checkpoint hosting, hardware trust, archive recovery and live qualification
remain mandatory before credential issuance.

## Mandatory remote baseline

Admission now requires an installed baseline verifier in addition to independent
GitHub/history/archive and designated signer evidence. Before collecting those
components and again before confirming admission, it binds repository ID,
accepted policy revision/digest, protected target and base SHA to remote verification
with verified:true and drift:false. The verifier must independently compare live
effective provider controls against the accepted enrolled baseline for that exact
current policy; caller booleans or local doctor output are not substitutes.

Private `EVIDENCE_BASELINE` calls `/v1/baseline/verify` with `{binding}`. Missing
binding denies the Worker before downstream calls. The typed verification boundary
has a maximum10s timeout, propagates an abort signal and suppresses capability
error contents. Service transport must honor cancellation; observation timeout
does not prove remote work stopped. No baseline service or production trust is
commissioned here. Missing/foreign/drifted/revoked/unavailable baseline must deny.

Existing exact-byte approvals and v1 evidence report bytes remain unchanged;
this is a mandatory prerequisite, not a reinterpretation of their signatures.
Tests prove absent verifier rejection, wrong policy revision and drift denial
before component collection, mid-collection drift denial and100ms stalled adapter
abortion with no provider evidence calls. Actual workerd covers absent private
baseline binding separately from absent designated signer binding.

The typed [configuration observer](BASELINE-OBSERVATION.md) now implements complete enrolled control comparisons. Its configurationVerified report intentionally cannot satisfy this gate alone; independently accepted enrollment and effective enforcement remain required.
