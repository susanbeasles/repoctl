# FlareKit restore adapter

`flarekitRestore` is a local Node capability for `recoveryJob.restore`. It runs
an installed absolute `fk` executable with an installed configuration file,
fixed argument list and explicit environment. Requests travel over stdin; no
shell runs and no caller may select a command, executable, vault or identity.

Install an `archives` list with repositoryID, archiveDigest (encrypted snapshot
manifest SHA256), gitManifestDigest (captured Git manifest SHA256), vault,
snapshotID and identity credential reference. Optional fetch=true additionally
requires vaultID and profile. These descriptors must come from trusted archive
publication records, not from untrusted job inputs. Pin and verify the installed
fk binary separately; an absolute pathname is not binary integrity verification.

The adapter optionally invokes snapshot.fetch, requires snapshot.restore's
full authenticated plaintext result, then invokes git.restore and requires
fsck, complete local object reconstruction and quarantined unsafe configuration.
It returns a canonical .git directory, archiveDigest and cleanup capability.
Use restoredGitReader with that directory and your installed Git executable;
repoctl independently verifies the approved candidate/source object closure.

Environment is not inherited. Install only needed HOME/PATH and trusted FK_AGE,
FK_AGE_KEYGEN paths, plus explicitly approved credential-provider settings.
FlareKit receives credential references, never a GitHub writer credential.
The adapter bounds stdout and per-command runtime and sanitizes failures.
Plaintext staging is removed on failure and by recoveryJob's finally block on
completion. Forced termination of the parent still needs runner teardown.

Qualification: subprocess contract tests use a synthetic fk executable.
Actual macOS Keychain/age/FlareKit recovery and live R2 fetch remain required.
This adapter does not supply report signing, OIDC upload, retention or remote
credential provisioning. It composes with those separate capabilities.
