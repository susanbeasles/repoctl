# Git archive recovery verifier

The Worker-compatible gitRecoveryVerifier traverses actual decoded Git object bytes
from an installed archive reader. It verifies Git SHA-1 object identity, SHA-256 content
digests, canonical object headers, object types, lengths, commit trees, parent history
and every referenced blob/tree. Both the approved candidate and source commit must be
present, with their complete reachable history. A missing base makes recovery fail.

The reader interface is `object({repositoryID,objectID,archiveDigests})`, returning
exactly `{archiveDigest,bytes}`. bytes is a Uint8Array containing Git's decoded object
header, NUL separator and payload, not compressed zlib or a packfile. archiveDigest
must belong to the approved archive set. The installed reader must verify the actual
archive manifest/ciphertext and decrypt or unpack it before returning object bytes.
Caller-supplied readers, object URLs and success flags are not accepted.

Reports use the admission gate's repoctl-archive-evidence-v1 protocol and bind the
exact intent, every recovered object, archive provenance and recovery summary.
The verifier does not execute code, materialize checkout paths or follow symlinks.
Gitlinks are recorded as external submodule references; submodule repositories are
not claimed recovered. Only SHA-1 Git repositories and UTF-8 commit records are
supported in this increment. Limits default to 10,000 distinct objects and 64 MiB of
recovered bytes; exceeding them fails closed. This is complete reachable history,
not a claim to recover every dangling local object, reflog or working tree file.

This implements the recovery verification core. It does not invent a competing
FlareKit encryption format or implement the encrypted R2 archive reader. That adapter
must use the actual archive format and independently verify object provenance.
Consequently EVIDENCE_ARCHIVES is not ready to enable from this patch alone.
