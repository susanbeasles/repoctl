# repoctl — native CLI preview and promotion contract

This preview adds a native Swift policy-sealing CLI, SEP and Keychain signing,
and optional Developer ID signing/notarization scripts. Native source has not
been compiled in the Linux authoring environment. Run the Mac tests before
using it. GitHub installation and promotion remain an implementation contract.

## Build and install on macOS

```sh
./scripts/install
repoctl --help
```

For a signed build, explicitly select an identity from `security find-identity
-v -p codesigning`. The build discovers that certificate's designated requirement;
it does not hardcode a publisher name or Team ID.

```sh
export REPOCTL_SIGNING_IDENTITY="YOUR_DEVELOPER_ID_APPLICATION_IDENTITY"
export REPOCTL_NOTARY_PROFILE="YOUR_EXISTING_NOTARYTOOL_KEYCHAIN_PROFILE"
./scripts/install
```

Omit both variables for a development build, or set only the identity for a
signed build. Notarization uses existing credentials; it does not create them.
Distribution is an app bundle containing a universal Mach-O CLI. The app bundle
is stapled, then zipped. The installer places it under `/usr/local/libexec` and
links `/usr/local/bin/repoctl`. It is not yet a signed PKG installer.

## Seal a policy

```sh
cp profile.example.json profile.json
# Edit and review profile.json before approving it.
repoctl policy seal profile.json --approve
repoctl policy verify profile.json
repoctl policy status profile.json
```

Default provider is SEP, with user presence and no fallback. To explicitly
choose a software Keychain key, add `--provider keychain` when sealing.
Each revision signs exact JSON bytes, so even formatting changes invalidate
verification. This is not RFC 8785 canonicalization. The detached seal contains
no private key. Public-key enrollment, accepted revision and signature are
stored separately in the current user's Keychain, keyed by absolute policy path.
Do not move the file after enrollment in this preview.

Re-sealing requires the existing key. Missing keys and provider changes fail
closed. No rotation, recovery, unseal, YubiKey, password-manager or encrypted-file
provider is implemented yet. SEP enrollment is local to that Mac. Keychain
provider does not require touch for each signature.

`--approve` is explicit authorization to sign the current file. This preview
has no built-in review/diff UI or GitHub operations. The JSON is checked to be
an object, but domain schema enforcement is still performed by `render.py`.
Run `Tests/mac-smoke.sh` to check tampering and rollback rejection using a test
Keychain key; it deliberately retains test enrollment.

## Security boundary of this preview

The application verifies the enrolled signer requirement when running from a
signed app bundle. Removing/replacing the entire bundle can also remove that
self-check: root-owned installation permissions and macOS signature enforcement
are separate defenses. No claim is made of resistance to a compromised admin.
Startup verification checks signatures, not a stapled ticket on every invocation;
notarization and stapling are verified during the release build.

A process with access to this user's trust records can delete or replace them;
this prototype is not yet an independently protected policy authority. Signing
prevents content edits from passing existing enrollment but does not guarantee
rollback protection against deletion of Keychain state. There is also no
cross-process sealing lock yet. Do not treat this preview as production policy
enforcement. Recovery enrollment and a hardened trust-record lifecycle are next.

## Everyday interface to implement

```sh
repoctl init susanbeasles/new-project --profile personal
repoctl submit --from work/my-feature
repoctl status
repoctl doctor
```

`init` should create the repository with Actions disabled, seed the signed
default branch, install the pinned controller/CI policy, reconcile rules,
enable immutable releases, verify effective permissions, and only then enable
Actions. Existing repos require a plan of their current refs and policies;
never silently overwrite unrelated rules or workflows. Every step is resumable.
No opt-in means no repository changes. Personal and professional identities
are separate profiles; the controller behavior remains the same.

Today, the implemented command renders API payloads without making changes:

```sh
python3 render.py profile.json > plan.json
```

Copy `profile.example.json` to `profile.json`. Populate verified numeric User,
GitHub App, and CI App IDs; installation IDs are not App IDs. Do not put secrets
in the profile. The renderer deliberately refuses missing IDs.

## Effective access

| Ref | Create | Update | Delete |
| --- | --- | --- | --- |
| Unmanaged / working branch | Owner | Owner | Owner |
| Default, main, master | Nobody after seed | Promotion App subject to integrity checks | Nobody |
| `pr/**` snapshot | App | Nobody | App after verified archival |
| `int/**` candidate | App | Nobody | App after verified archival |
| All tags | App | Nobody | Nobody |

An owner-only blanket on *all* refs also blocks the App. A different ruleset
cannot grant permission through it. This plan excludes App-managed refs from
the owner-only blanket and applies stricter rules to those namespaces.
The App has no administration permission and cannot edit its own rules.
The owner remains able to edit repository settings as the repository admin;
rulesets are not a defense against an administrator intentionally disabling them.

Frozen means never update the ref. Cleanup is a separate deletion permission.
If you mean never delete either, keeping both branches is the alternative.

## Promotion state machine

1. Owner submits working SHA P. The App validates repository ID and owner ID,
   creates a fresh `pr/<submission>` ref at P, and opens a draft tracking PR.
   Never accept arbitrary fork heads or branch names supplied in comments.
2. Capture current main M. In a disposable checkout, replay the submitted change
   onto M and squash it into a signed candidate S. S must have exactly one parent
   M. Conflict resolution produces a new reviewed candidate; never guess it.
   The snapshot remains P. Intermediate rebase commits never enter main.
3. Create `int/<submission>/<generation>` at S once. The App opens a promotion PR
   from it to main. Link both PRs and show P, M, S, CI URLs and current generation
   in a maintained comment. The App authors the promotion PR so the owner can
   approve it. The owner's original tracking PR is not the approval authority.
4. Run CI only on the integration branch's exact S. Use push events with an
   `int/**` branch filter. Disable pull_request, pull_request_target, workflow_run,
   review, and comment events in the repository-wide execution policy. Reject
   outsider/fork webhooks in the controller before scheduling work. A YAML `if`
   condition alone is not the repository-wide policy.
5. Require owner approval on S, all designated checks actually successful on S
   from their expected App IDs, resolved threads, valid signing identity, and
   unchanged M. A trusted gate must validate CI workflow identity/version too;
   a check name alone is insufficient. Keep signing keys and promotion tokens
   out of CI executing candidate code. Validate IDs, not merely login strings.
6. Serialize promotions per repository. Recheck state from GitHub immediately
   before updating main to S with `force:false`. Assert S has one parent M.
   If main advances, publish a NEW immutable integration generation, rerun CI,
   and obtain new approval. Never move the old integration ref.
7. Record a durable receipt binding repository ID, P, M, S, tree SHA, review ID,
   reviewer ID, check run IDs, policy version and signing identity. Create
   `pr/<submission>/source` at P and `pr/<submission>/integration` at S. Verify
   both tag targets and immutable rules. Retry unfinished steps idempotently.
8. Only after both tags exist and the receipt is durable, close the tracking PR
   with the promotion link and delete the snapshot and integration branches.
   Keep the working branch. The original tracking PR is closed, not falsely
   reported as squash-merged by GitHub. Verify GitHub's merged-state behavior
   for the promotion PR during the compatibility test.

Do not run the ordinary GitHub squash/rebase merge endpoint after testing S:
that can create another commit instead of promoting the tested SHA unchanged.
Native main rules cannot express "exactly one new commit"; the trusted
controller must enforce the parent assertion and serialized promotion.

## Deployment blocker: native required PR + exact fast-forward

GitHub's PR merge endpoint exposes merge, squash and rebase, not fast-forward.
Native required-PR rules may reject a direct ref update even if the linked PR
is approved. The supplied plan keeps the no-bypass approval layer intact and
explicitly marks deployment blocked until a disposable repository proves:

- App-authored PR with one signed child commit can FF to that exact SHA after
  owner approval and successful checks, while the integrity rules remain active.
- The same update fails without approval, with stale/dismissed approval, failed
  or forged checks, an outdated base, an extra commit, and a human writer.
- Snapshot/candidate updates, main deletion/recreation, and existing tag mutation
  fail for both owner and App.
- Fork/outsider events cannot start workflow execution.

If native approval enforcement cannot support exact FF, choose explicitly
between GitHub-native merging and an independently enforced custom approval
gate. Do not silently grant the App bypass on the approval ruleset.

## Releases

Immutable tags apply to every tag; release immutability adds locked assets and
release attestations after publication. Build from promoted S, create a draft,
attach all assets, verify, then publish. Publication is the freeze boundary.
GitHub release immutability does not make the entire release object undeletable;
release deletion authorization needs a separate operational boundary. Give
CI no release write token. Only the trusted publisher has Contents write.

## Reusable implementation layout

- Central versioned `repoctl` repository: installer, renderer, controller,
  gate, tests and workflow definitions, with consumers pinned by commit SHA.
- One GitHub App per trust domain, installed only on opted-in repositories.
  Contents/PR write and checks/status/actions read as required; no admin rights.
- Separate bootstrap owner credentials for repository administration. Check
  the authenticated numeric account against the profile before any write.
- Optional per-repo `.repoctl.json`: profile, required checks, build command,
  release adapter and version strategy; no credentials.
- Periodic/on-demand doctor detects drift and fails promotion closed. Managed
  rules reconcile by exact name/ID; unrelated or inherited rules stay intact.

The professional profile currently changes configured owner/App/check identities
only. Organization teams and enterprise policies require a separately reviewed
renderer extension; this package does not invent a work policy.

## Sources checked 2026-10-04

- https://docs.github.com/en/rest/repos/rules
- https://docs.github.com/en/rest/actions/policies
- https://docs.github.com/en/rest/pulls/pulls#merge-a-pull-request
- https://docs.github.com/en/rest/git/refs#update-a-reference
- https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches
- https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases

## App Management validation on the target Mac

macOS App Management controls which other apps may update or delete apps.
It is separate from Gatekeeper signature assessment and SIP. Whether this
CLI bundle at `/usr/local/libexec` receives the expected protection must be
verified on the supported macOS version. Do not claim this preview prevents
all root modification. Test an unauthorized modifying process, an explicitly
authorized updater, and a signed bundle whose resource is modified. Use a
copy for destructive tests. Root permissions alone are not the whole boundary.

## Native GitHub bootstrap commands

This version adds a personal `locked-bootstrap` phase using the installed
GitHub CLI (`gh`) for authentication and API transport. It is an interim runtime
dependency; the binary does not yet have native GitHub OAuth/Keychain transport.

```sh
repoctl repo inspect susanbeasles/repoctl
repoctl repo plan susanbeasles/repoctl
```

Both commands are read-only. The plan binds the authenticated numeric owner ID
and confirms the default branch exists. Only a personal repository administered
by its exact owner is supported in this phase.

The explicit apply command changes remote settings:

```sh
repoctl repo apply susanbeasles/repoctl --accept-locked-bootstrap
repoctl repo verify susanbeasles/repoctl
```

**Apply locks main/default/master against ALL updates, creation and deletion,
including by you; it also disables Actions.** Do not apply expecting ordinary
PR merging to work. Configure the promotion App in a later phase before any
writer is allowed onto protected branches. An administrator can edit rules
through GitHub if recovery is necessary; this is not administrator-proof.

The phase also requires signed protected commits/linear history/no force pushes,
allows only owner updates to other branches, restricts tag creation to owner,
forbids existing-tag updates/deletion without bypass, and enables immutable
releases. Frozen snapshot/integration namespaces and the promotion protocol
are not active in this phase. No policy-seal file is consumed by these fixed
bootstrap commands; do not mistake them for sealed customizable policy apply.

Managed rules use `repoctl/bootstrap-v1/` names. Unrelated and inherited rules
are preserved. Matching inherited names and duplicates abort before mutation.
Actions are disabled first; subsequent failure does not automatically remove
protections. Re-running resumes reconciliation. Verification compares managed
configuration and checks Actions/immutability; it is not an adversarial test
of effective platform enforcement. Multi-call GitHub changes are non-atomic.

Native Swift compilation and authenticated API writes must be tested on macOS.
Do not claim the full promotion preset works from this bootstrap phase alone.
