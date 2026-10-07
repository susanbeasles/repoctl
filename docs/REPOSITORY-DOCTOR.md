# Approved repository configuration drift

`repoctl doctor` reads `.repoctl-baseline.json`. Use `repoctl doctor --baseline FILE`
for another baseline. It makes no repository changes and never refreshes or seals
a baseline implicitly. The baseline must already be enrolled through the existing
exact-byte `policy seal` protocol. The CLI uses the same bytes it verified, then
verifies the enrolled bytes again before reporting success.

The baseline is a JSON object with exactly these fields:

| Field | Contract |
| --- | --- |
| `protocol` | `repoctl-repository-baseline-v1` |
| `repository` | Personal `OWNER/REPO` |
| `repository_id`, `owner_id` | Positive numeric GitHub identities |
| `default_branch` | Approved default branch name |
| `settings` | Exactly `archived`, `fork`, `allow_auto_merge`, `delete_branch_on_merge` booleans; archived/fork must be false |
| `rulesets` | Complete nonempty inventory, including inherited rules |
| `actions_policies` | Complete nonempty inventory, including inherited policies |
| `actions_permissions` | Full expected GET response; enabled must be true |
| `selected_actions` | Full expected selected-actions response when allowed_actions is selected; null otherwise |
| `workflow_permissions` | Full expected GET response; token permissions read, automatic PR approval false |
| `immutable_releases` | Full expected GET response; enabled must be true |

Every inventory entry has exactly `id`, `source`, `source_type`, `body`. IDs must
be unique within each inventory. Sources are repository, organization or
enterprise sources as reported by GitHub. Ruleset bodies retain `name`, `target`,
`enforcement`, `conditions`, `rules`, `bypass_actors`; Actions bodies retain `name`,
`enforcement`, `conditions`, `rules`. Bodies must be active with nonempty rules.
Inventory order is normalized by ID; body array order is compared exactly.
Baseline approval must review complete bodies and inheritance, rather than
assuming a managed name or active flag proves effective policy.

The check verifies the selected account matches the exact numeric personal owner,
repository identity and default branch. It compares settings, inventory sources,
IDs and normalized detail bodies, Actions token permissions/selected action allowlists, and immutable
releases. New/deleted/inherited/duplicate rules and policies, permission failures,
changed details and settings fail. Collection is repeated to catch observed drift;
this is not an atomic GitHub transaction or continuous monitoring guarantee.
No `apply` or automatic mutation follows failure.

The existing seal is a preview trust record. Its documented Keychain lifecycle
and hardware-origin limitations remain applicable. This command does not upgrade
it to independently anchored production policy, reinterpret signed v1 bytes, or
claim hardware proof. A software fixture is not a production baseline approval.
Missing enrollment blocks before provider observation.

`Tests/mac-doctor.sh` compiles the actual Swift comparison/transport source and
exercises the actual doctor command and exact-byte signature verifier with a
temporary in-memory software fixture signer/trust record and adversarial provider
responses. No permanent key or Keychain enrollment is created. It also builds
the real CLI and verifies an unenrolled baseline is denied before provider access.
The fixture does not qualify hardware enrollment or a live positive CLI flow.
A live positive check requires a reviewed, enrolled baseline and its existing
signing boundary; no new key or automatic provider snapshot approval is created.

Still required: independently accepted production baseline authority, verified
hardware enrollment/rollback protection, authenticated controller transport, and
mandatory baseline checks in admission and immediately before execution. Native
configuration success cannot authorize promotion or replace behavioral tests of
actor restrictions, signed commits, immutable refs and PR/fast-forward behavior.

Provider endpoint contracts: [rulesets](https://docs.github.com/en/rest/repos/rules),
[Actions policies](https://docs.github.com/en/rest/actions/policies), and
[Actions permissions and selected allowlists](https://docs.github.com/en/rest/actions/permissions).
