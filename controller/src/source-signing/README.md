# Standalone source signing

This local core implements the source-object and approval boundary, immutable
shadow publication, and a draft PR through the standalone delivery_control
publisher. It does not update main, configure GitHub protections, deploy code,
enroll a key, or run a production reviewer/scanner. No production bindings or
accepting fallback implementations are installed here.

## Fixed sequence

1. `prepare({repositoryID, sourcePR, author, committer, message,
   artifactIntentDigest, expiresAt})` reserves a durable per-repository sequence
   before signing. Failed and uncertain generations leave permanent gaps. The
   installed source adapter retains the complete original source history P and
   current main M, proves their merge base with normal Git, and computes the
   squash tree with `git merge-tree`. The unsigned commit contains that tree,
   exactly one parent M, and the exact supplied author, committer, times and
   message. Independently accepted **workflow_depot** policy must authorize the
   digest of the complete candidate request, including all those commit bytes.
2. The isolated, pinned existing Git SSH signer signs the eligible commit.
   Signing is candidate production, not owner promotion approval. Its signature
   is verified before calculating final Git commit S. No owner signature is
   needed to produce this policy-eligible candidate. An uncertain signing call
   is never retried automatically.
3. `publishShadow({repositoryID, sequence})` publishes only that exact S to
   `refs/heads/int/<working-branch>`. Replacement closes the old PR, deletes the
   exact old ref, recreates the same name and opens a new PR. Generation records
   and commit-to-generation bindings remain immutable.
   The original source PR/history is retained separately. All build, automated
   checks and scans operate on S during the PR phase. The standalone publisher
   creates one draft PR against M; durable reservations and exact readback
   prevent duplicate refs/PRs after ambiguous responses. This does not qualify
   the hosting provider's protections.
4. `approvalIntent({repositoryID, sequence, expiresAt})` validates current P/M,
   the exact signed S, CI, authenticated scan coverage, then independent review.
   It returns a fresh approval payload without amending or re-signing S. This
   allows CI to take longer than the short owner-approval lifetime. Reviewer
   evidence must follow the automated gates; a model judgment alone is rejected.
5. The existing owner hardware approves the detached canonical payload in the
   existing `repoctl-promotion-owner-v1` domain. The payload binds repository,
   source PR, source P, parent M, signed S/tree, signer fingerprint, policy,
   artifact intent, sequence and **both complete unsigned annotated-tag bodies**.
   No signature is appended to or otherwise changes S after approval or CI.
6. `approve({repositoryID, sequence, ownerApproval})` verifies that signature
   against independently enrolled owner keys and current hardware proof, repeats
   the gates, consumes the exact approval durably once, and signs the two fixed
   tags. Their names are `promotion/<sequence>/source` and
   `promotion/<sequence>/main`, targeting P and S respectively. Both complete
   messages cross-link P/S, both tag names, repository, sequence and the immutable
   owner approval reference. A tag-signing interruption remains uncertain and
   requires explicit reconciliation; it never silently signs again.
7. `publish({repositoryID, sequence})` publishes only the retained objects and
   create-only tag refs. It reserves each ref mutation before attempting it.
   Readback may reconcile a lost response to the exact object; an absent or
   conflicting ref after an uncertain write never causes an automatic retry or
   retag. The successful paired-tag receipt is retained immutably.

The existing promotion controller must separately verify all three authorities
(automated gates, independent review, detached owner hardware approval) and
fast-forward main **exactly** from M to S. It must not merge, squash or amend S
after CI. Any P/M/S change requires a new candidate and fresh checks/approval.
Tag publication and main advancement are separate operations, not an atomic
GitHub transaction. This component does not claim to implement that final main
update or a complete production promotion workflow.

`createSourcePromotion` in `promotion.mjs` supplies the executable handoff to
that existing controller. `prepare({receiptDigest, nonce, expiresAt})` rechecks
the source core's private `verifyPromotion` capability, current accepted policy,
and independently retained checkpoint. It computes the original admission
evidence digest and durably binds the source receipt to the operation. Its ledger
sequence is checkpoint + 1; source generation gaps remain separate. `expiresAt`
uses the existing promotion protocol's milliseconds.

Install the bridge as the existing authority's evidence capability for admission
and every later fresh check. It repeats source/ledger checks around the original
admission verifier. The owner and independent validator must still approve the
unchanged generic promotion intent, and the owner must separately approve the
exact execution run in `repoctl-execution-owner-v1` (seconds). A source/tag
approval cannot substitute for any of those envelopes. The bridge writes no
main ref, creates no credential and signs nothing. Production service bindings
for this composition are not commissioned by the local tests.

## Trusted adapters

`createSourceSigning` requires durable transactional `storage` and installed
`policy`, `git`, `signer`, `approvalVerifier`, `ci`, `scans`, `review`, `publisher`
capabilities. They are configuration of the isolated service, never request
arguments. `policy.current` must derive accepted policy from workflow_depot;
`policy.authorizeCandidate` must authenticate exact request-digest eligibility.
The core's `authority: 'workflow_depot'` check is a context pin, not itself proof
of that trust relationship.

`authorizePublication` is an installed private effect capability for the
standalone publisher. It consumes a durable reservation exactly once and binds
the complete ref/object or deterministic PR request. It is not a public
publication API. Shadow/PR effects recheck candidate eligibility; paired tags
recheck current owner hardware and all evidence. The publisher uses normal Git
against one fixed HTTPS remote and an empty expected-ref lease, with no hooks,
application configuration, force update of existing refs, or main write. Its
existing builder-role credential is confined to that standalone service. Both
the source snapshotter and publisher must use the same complete retained Git
object store; staging a dangling commit is insufficient for a push.

`ownerApprovalVerifier` reuses the existing repoctl P256 owner domain and raw-key
SHA256 identity. `currentPolicy` supplies enrolled public keys and
`currentHardware.verify` independently supplies current, unrevoked hardware
proof. A caller assertion, key created by this process, GitHub's `verified` bit,
or a software fallback cannot substitute for these capabilities.

`createInstalledGitSigner` is an **internal effect adapter**, not a public
arbitrary-signing RPC. It requires immutable trusted executable SHA256 pins,
the existing public SSH key/fingerprint, a fixed agent socket, and an independent
`authorize` callback which checks the exact object digest and the corresponding
durable policy/owner reservation. It invokes fixed `-Y sign -U -n git -f` arguments
without a shell or inherited credential environment. Verification parses the
SSHSIG namespace/key and runs the pinned verifier. The operator must install it
inside the isolated signer boundary; placing it inside a production CI job or
exposing `signGit` directly would violate this contract. Existing key custody
and hardware availability have not been exercised by these tests.

`createLocalGitSource` uses a fixed local operator-owned clone and pinned Git
executable. It never fetches or pushes. It rejects shallow/partial/grafted
history, external merge drivers and submodules, retains and hashes the complete
reachable object closure, and verifies immutable archive readback. It uses a
trusted complete-inventory classifier; unknown stacks have no default support.
The only Git mutation it performs is writing the local merge-tree result in the
scratch clone. Archive retention/classification must not be derived from PR
configuration. Resource bounds default to 100,000 objects and 64 MiB.

The scan validator requires the policy's complete tool/version/ruleset pins,
source inventory and coverage, fresh dependency database and all passing
statuses. Mandatory categories are dependency integrity, inventory,
vulnerability, SAST, DAST, pentest, malware and quality, including an explicitly
pinned SonarQube standard ruleset. Extra applicable categories and exemptions
come only from accepted policy. These structural checks do not run those tools
or claim that any stack has been qualified. Complete CI build-input, hidden/cache
and artifact inventory, dependency integrity and isolated tool provenance must
be authenticated by the CI scan-evidence adapter in addition to this retained
source-tree coverage check.

The review adapter must independently authenticate the pinned GitHub App,
installation and actor, final candidate/source/base, actual style-guide
path/revision/digest, and evidence-based verdict. Its identity must differ from
the privileged owner/signer/executor identities. Missing/inconclusive review,
blocking findings and model-only methods deny approval. This code performs no
model call, source upload, review posting, dependency installation or execution
in a reviewer. Shared reviewer runtime isolation and any platform-required human
review remain obligations of the trusted reviewer adapter and accepted policy;
a bot check is never represented as a human review.

## Private read contracts

`lookupCandidate({repositoryID, commitSHA, shadowRef})` verifies exact retained
signed bytes, authorized signer, current P/M, and actual shadow-ref readback S.
The ref must equal `integrationRef(sourceRef)` under the shared safe-ref validator.
The independent sequence must be a positive safe integer and the exact active
generation must still match; historical PRs at the same ref are not candidates.
It returns:

```text
{schema: 'repoctl-source-candidate/v1', verified: true,
 repository, repositoryID, commitSHA, treeSHA, sourceRef, sourceSHA,
 expectedMainParent, shadowRef, sourcePR: {number, repositoryID, headSHA},
 sequence, signerKeyID, unsignedCommitDigest, artifactIntentDigest,
 policyDigest, sourceHistoryDigest}
```

`lookupReceipt({receiptDigest})` checks the immutable receipt digest, existing
owner approval/current hardware proof, and exact retained signed commit/tag
objects. It returns:

```text
{schema: 'repoctl-source-receipt/v1', repository, repositoryID,
 sourceRef, sourceSHA, baseSHA, finalSignedCommitSHA, treeSHA, sequence,
 shadowRef, sourcePR, signerKeyID, ownerApprovalReference,
 hardwareApprovalVerified: true,
 pairedTags: {source: {name, objectSHA, targetSHA},
              main:   {name, objectSHA, targetSHA}},
 artifactIntentDigest, ciReceiptDigest, reviewReceiptDigest,
 scanReceiptDigest, historyDigest}
```

`receiptDigest` is SHA256 of the existing repoctl canonical JSON encoding of
that entire receipt. An external deployment verifier must still observe that
main equals S and verify the previously built artifact's provenance from this
shadow generation. A source-signing receipt alone is not deployment authority.

Run `node --test controller/test/source-signing.test.mjs` from the repository
root. Fixtures use generated test keys, synthetic trust/provider responses and
a temporary bare Git repository. They do not prove live hardware, provider,
production scanner/reviewer, PR publication or promotion qualification.
