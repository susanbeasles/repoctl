# Read-only GitHub candidate evidence

`controller/src/evidence/github-observer.mjs` reads only the deployment-selected public repository through fixed GitHub HTTPS URLs. It accepts no caller URL, authorization header or alternate repository/ref. Responses are bounded, redirects are refused, and repository numeric identity is checked on observation.

`candidateEvidence` in `controller/src/evidence/candidate.ts` independently requires:

- Main remains at the expected base before and after verification.
- Candidate is exactly one signed child of that base, with the approved tree.
- The installed designated-signer verifier confirms the exact repository/base/
  candidate/tree binding before CI inspection and again before returning evidence.
  GitHub's general valid-signature flag cannot replace this capability.
- Source commit remains available.
- Every configured check occurs exactly once on the candidate and completes successfully through the configured App.
- Each check suite resolves to exactly one Actions run in the same non-fork repository.
- Workflow ID, path, push event, integration branch prefix, actor and rerun actor match trusted policy.
- The actual workflow bytes at the candidate match the pinned SHA-256 recipe.

Required checks must be nonempty. Each rule has exactly `name`, `appID`, `workflowID`, `workflowPath`, `workflowDigest`. Actor IDs and checks are selected by trusted configuration, never the candidate request. Workflow dependencies must themselves be immutably pinned in the reviewed recipe; this module does not recursively audit dependencies.

The private admission Worker requires `EVIDENCE_SIGNATURES` alongside policy,
history and archive bindings. Its fixed POST `/v1/candidate/verify` request contains
`{candidate: {repositoryID, baseSHA, commitSHA, treeSHA}}`; the installed service
must return those exact fields with `verified: true` only after designated key,
current role/enrollment and revocation verification. This service is separate
from App JWT signing. Missing bindings deny admission with503 before downstream
calls. It remains an uncommissioned production dependency; no fabricated
signature service or public route was added.

Calls are bounded to ten seconds with secret exception suppression. A stalled
verifier, changed signer result or caller mutation cannot yield evidence. The
existing v1 report and signed approval byte protocols remain unchanged.

The module returns `githubVerified: true`, never the broader `verified: true` broker authorization result. It does not replace independent owner/validator approvals, archive recoverability, anchored ledger/history, required vulnerability findings thresholds, or policy/ruleset drift evaluation. Those checks remain mandatory before promotion. It is not wired as a standalone broker verifier that can grant authority.

## Trigger compatibility

This implementation verifies push-triggered checks on the exact candidate's integration branch. The older `templates/candidate-security.yml` dispatches from main and checks out an input SHA; its check suite's head SHA may identify main rather than that input. That template is deliberately not accepted as exact-candidate evidence here. A dispatch-based scanner needs a separately verified artifact or attestation binding its scanned input SHA; checking only a green workflow is insufficient.

This adapter supports public repositories without credentials. GitHub unauthenticated API rate limits apply. A future read-only credential adapter must remain separate from writer custody. No authenticated fallback or private-repository access is assumed.
