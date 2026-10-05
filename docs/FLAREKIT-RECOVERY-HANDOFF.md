# FlareKit recovery handoff

Reviewed FlareKit commit `3f17fc91bb279955266f8ce5f691822cedea934d`.

FlareKit v1 stores age-encrypted manifests and chunks. A recovery job must fetch
an independently trusted manifest ciphertext digest, authenticate/decrypt the
snapshot, verify the captured file digests, and restore Git into a fresh private
directory. Neither the webhook Worker nor the promotion executor receives the
age recovery identity. FlareKit's encrypted deduplication index is unnecessary
for restoration.

`controller/src/archive/restored-git-reader.mjs` is a local Node recovery-job
adapter for that restored Git directory. It reads loose and packed objects using
an explicitly installed Git executable, disables replacement refs and lazy
fetching, rejects shallow repositories, alternate stores and object-store
symlinks, and enforces bounded subprocess output and timeouts. It feeds the
existing independent object hash/graph verifier. It does not check out files or
execute repository hooks.

The archive digest and repository binding are installed job configuration, not
untrusted request assertions. **This adapter does not establish encrypted archive
provenance by itself.** Do not point it at a working checkout and call that an
archive recovery test. A dedicated job still needs to perform FlareKit fetch,
authenticated restore, capture verification, and Git restore before opening this
reader. Use a private quiescent directory; validation cannot prevent another
process with the same filesystem authority from subsequently changing it.

The resulting report covers candidate/source reachable Git history. It does not
claim full dangling-object, reflog, linked-worktree, LFS or submodule recovery.
External gitlinks are recorded explicitly. FlareKit's full capture inventory
verification remains a separate check.

Remote admission remains disabled until the recovery report is independently
authenticated and bound to the approved archive manifest digest and current
policy. No caller-supplied success flag substitutes for that transport.
