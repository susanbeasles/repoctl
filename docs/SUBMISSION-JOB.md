# Isolated submission job

`controller/src/candidate/submission.ts` composes the existing preparation,
snapshot retention, designated signing and immutable generation capabilities.
Installed configuration fixes the numeric repository and one canonical private
job directory; intent supplies only source/base SHA and a fresh generation ID.
No credential, caller URL, signer key, force option or project execution is accepted.

`submit(intent, message)` creates the job exclusively and advances in order:

1. Preserve exact source/base history and prepare the single-parent candidate tree.
2. Retain the submission pack through the installed immutable snapshot capability.
3. Finalize the signed candidate through the existing signing adapter, which
   independently verifies retention and reconstructs the submitted tree.
4. Retain the exact generation binding before invoking publication.
5. Return only bound public status `published-awaiting-validation`.

Each capability observation is bounded to ten seconds. A timeout cannot undo a
request already issued; failure retains its phase without repeating it. Preparation
results are snapshotted before retention awaits, and existing job directories are
never overwritten. Capability failures and private response fields are suppressed.
Publication and reconciliation receive the job cancellation signal. The generation
coordinator propagates it to provider requests, candidate/namespace verification
and native upload, and checks cancellation before starting those capabilities.
Late proof completion cannot advance an expired job into publication. Cancellation
after the durable creating claim leaves an uncertain journal, without starting upload.

`reconcile()` reads the bounded, regular, nonsymlink generation record and calls
only the installed non-creating generation reconciliation capability. It never
prepares, retains a new snapshot, signs or publishes. Missing generation records
and unknown/unresolved remote provenance require inspection of the retained job.
Local metadata is not independent authority: the generation service must verify
its durable journal, current base, immutable namespace and designated signature.

For queue execution, the installed factory must configure `submissionProgress`
bound to that job's journal/generation. Its begin check requires the claimed
preparing state and exact repository/base/source/message before creating output.
Prepared metadata is retained before snapshot retention, the independent receipt
digest before signing, and the signed commit before publication. Checkpoint denial
stops the next action. Publication confirmation follows fresh generation proof.
Failure attempts to retain uncertain state; the private failed-job record reports
whether the journal acknowledged it. Failure never rewinds an already completed
record. The optional absence of this adapter supports primitive local job fixtures;
it does not qualify a queued production execution.

The actual local Git-chain fixture prepares and signs a commit using a temporary
fixture software key, packs and transfers it through receive-pack, then verifies
the pinned SSH signature in the receiving repository. A lost publication reply
recovers through readback with exactly one signature and one upload. The source
checkout remains unchanged. Snapshot retention proof and provider coordination
are synthetic in this fixture; this does not qualify production custody,
hardware origin, GitHub rules or remote immutable retention.

Native CLI dispatch, authenticated remote job admission, installed retention and
publication adapters, exact candidate workflow validation, fresh independent
approvals and central promotion remain required. Publishing a generation does
not admit or authorize a promotion. The job introduces no production rollout.
