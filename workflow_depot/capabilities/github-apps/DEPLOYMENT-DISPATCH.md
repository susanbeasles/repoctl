Prepared source only; registration, conversion, custody writes, installation and
runtime commissioning have not run.

Reviewed identity: Vespoli Deployment Dispatch, private App owned by
susanbeasles (215839550). Actions write only, with GitHub's implicit Metadata
read. No webhook events or active webhook. Installation must use selected
repositories and contain only susanbeasles/delivery_control (1405415291).
Manifest callback: https://provision.vespoli.me/github/callback. This hostname
is an existing-framework deployment input, not evidence of a commissioned route.
Do not invent a new publicly accessible registration service to make it work.

Use deploymentDispatchPlan and createDeploymentDispatchProvisioner from
src/deployment-dispatch.mjs. They reuse the existing registration session,
manifest verification, enrollment journal and provider identity verification.
Use onepasswordCLIVault with officialOPRunner for this profile. The official
CLI installer pins package digest and version. Keep the runner within the
approved private Node runtime; do not route conversion responses through CI
artifacts, chat, browser responses or repository files. Close the runner in a
finally block. The existing Durable Object worker cannot directly spawn op;
its private enrollment service adapter must be bound to this approved runtime.
No new service/binding is installed by these modules.

Generated PEM, webhook secret and client secret flow from the conversion
response into a scoped existing 1Password vault via private JSON stdin. CLI
stdout stays private in memory; stderr is discarded and failures are sanitized.
Only nonsecret custody metadata is journaled. An uncertain conversion or item
creation never triggers automatic reconversion or duplicate item creation.
If an item was created but its acknowledgement was lost, recovery requires
separately approved reconciliation of the retained item identity; do not rerun
registration. The generated client/webhook secrets are retained confidentially
for recovery, not used to request OAuth access or subscribe to webhooks.

Before activation, action-time confirmation must authorize (1) registration of
this exact named App/profile/callback under susanbeasles, (2) one-shot manifest
conversion and direct transfer of generated credentials into the approved
existing vault with the CLI, and (3) selected-repository installation for
 delivery_control only. Independently authenticated approval references are
required by the framework. The user approves GitHub registration/installation
screens, not secret creation or copying. Any policy gate requiring credential
transfer handoff must be respected; no handoff of raw App credentials through
chat is implemented. The existing CLI bootstrap must already be approved for
the destination vault; this source does not create or broaden it.

After registration, obtain nonsecret App client ID/slug from authenticated App
identity metadata and bind the reviewed installation ID. Verify the installation
using verifyDispatchInstallation before commissioning dispatch. Existing scoped
runtime must still request Actions write only for delivery_control and revoke
its short-lived installation token. This source mints no installation token and
does not enable any dispatch caller.

Synthetic tests: node --test test/*.test.mjs (28 pass). They cover reviewed
manifest, exact target, approval revocation, one-shot conversion, CLI stdin
custody, no secrets in public/journal/argv, verification failure, uncertain
custody failure and installation narrowing. They do not prove live callback
reachability, vault permissions, policy authorization or App installation.
