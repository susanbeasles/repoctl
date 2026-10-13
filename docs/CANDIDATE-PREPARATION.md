# Isolated candidate preparation

`controller/src/candidate/preparation.mjs` is a Git job adapter for the construction
step in the governance specification. It is not a Worker route, signing service,
promotion authorization or installed `submit` command.

Installed job configuration supplies a canonical Git object directory, an absolute
Git executable, numeric repository identity and an object/patch size bound. A
request supplies only that repository identity and exact source/base commit SHAs.
Each preparation requires a new canonical output directory outside the source
Git directory. Existing outputs and partial preparations are never overwritten.

The job packs the submitted and base history into `submission.pack`, imports it
into a separate bare object store, finds exactly one merge base, and computes the
submitted branch change as a binary full-index patch. It applies that patch to an
index seeded from the pinned base and writes a prepared tree. No working tree is
checked out, project program is executed, source ref is changed or commit signed.
Shallow and externally linked source object stores, linked common directories,
and symlinked object roots are rejected. Storage independence is checked both at
configuration and before each preparation. Output directories are private to
the invoking user (0700), including the imported Git objects.
Git hooks, replacement objects, grafts, global/system configuration, lazy fetch,
external diff and text conversion are disabled. Commands and output are bounded.
A conflict or missing/ambiguous ancestry retains `failed.json` and requires a new
preparation rather than changing history or choosing a different base silently.

`preparation.json` binds source, base, merge base and prepared tree to SHA-256
snapshot/patch digests. Its state is `prepared-awaiting-signature`. The local
snapshot is preserved evidence, not an independently retained immutable archive.
It cannot authorize a promotion or supply trusted signature/evidence claims.

The tests in `controller/test/candidate-preparation.test.mjs` use actual Git:
advancing main and submitted binary changes combine correctly; dirty staged work
and source HEAD remain unchanged; existing output and foreign identity fail;
conflicts retain failed state; candidate attributes/configured filters do not
execute. The full controller suite includes these checks.

Still required: remote immutable submission retention and receipt verification,
designated candidate signer with its enrollment policy, creation/readback of the
fresh integration generation, approved validation, authenticated operator
transport and native `submit` integration. Existing candidate/history/evidence
verifiers remain mandatory downstream; the preparation report does not replace
them or the native GitHub approval/fast-forward qualification.

Preparation captures an immutable typed snapshot of repository ID and primitive source/base SHA strings before filesystem awaits. Caller mutation cannot change the packed source, replay base or retained manifest; coercible objects are rejected before creating output. The native Git regression exercises these boundaries against actual packed objects.
