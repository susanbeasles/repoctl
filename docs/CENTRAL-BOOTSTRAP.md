# Publish the central repositories

Run `scripts/bootstrap-central-repos --owner OWNER --directory ~/code --plan` from a published repoctl checkout, then repeat without `--plan` to publish.

The helper exports the committed `delivery_control` and `workflow_depot` directories into separate public repositories of those names. It records the source commit in `repoctl-source.json`, copies the source checkout’s repository-local Git signing and SSH configuration, makes signed initial commits, and pushes without force. It checks the active GitHub account, applies repoctl’s owner/event Actions policy before the first push, and does not modify global Git or SSH configuration.

Requirements: Python 3, Git, authenticated GitHub CLI, installed repoctl with `actions apply`, and an already existing destination parent directory. Publish repoctl HEAD first. The exported directories must have no uncommitted changes. PIN and hardware touch prompts remain interactive; read-only remote inspection can also require a touch.

The helper refuses symlink destinations, changed exports, extra tracked/untracked files, different origins, and remote history that does not match the existing bootstrap checkout. Re-running the same source revision can resume a partial bootstrap. It does not update repositories exported from an older source revision; review those updates separately. A failure can retain directories, commits or an empty remote already created; inspect the reported state before retrying.

Publishing these repositories does not make promotion operational. The remote broker routes, durable authority adapters, isolated GitHub App enrollment, independently verified archives, public controller configuration and exact OIDC trust enrollment still require provisioning and live qualification. Do not apply the App-only main protection until its writer and recovery path work. Workflow depot validation currently runs controller tests; it is not a complete SAST/DAST/malware pipeline.
