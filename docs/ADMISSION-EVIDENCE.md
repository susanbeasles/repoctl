# Combined promotion evidence

The admission verifier composes installed GitHub, anchored history and archive
recovery adapters. It independently verifies owner and validator signatures,
checks the exact approved intent and recomputes component report digests. All three
components must match the proposal. It rereads accepted policy and checks expiry
before returning the authority's `verified: true` admission response.

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
