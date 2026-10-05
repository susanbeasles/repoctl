# Composed recovery runtime

`recoveryRuntime(installedCapabilities).run(archiveIntent)` connects the FlareKit
restore adapter, isolated Git reader, object-closure verifier, recovery signer
and authenticated publication client. It accepts one bounded intent and returns
one nonsecret publication receipt. It grants no GitHub writer credentials.

Installed configuration supplies `flarekit`, absolute `gitExecutable`, `signer`,
`policyDigest`, `transport`, and optional clock/lifetimeMs. FlareKit installation
and archive descriptors follow FLAREKIT-RESTORE-ADAPTER.md. Transport follows
RECOVERY-HTTP-PUBLISHER.md. The signer provides sign(payload) and trustedKeys;
its signature is locally verified before publication. Do not let a dispatch
payload override any of these capabilities.

The run restores authenticated plaintext, reconstructs Git with unsafe hooks
and configuration quarantined, independently traverses the approved candidate
and source history, signs the report, checks the server's publication receipt,
and removes staging in finally. Failures do not return a successful receipt.
An ambiguous upload is not retried automatically. Retain the identical signed
envelope separately before designing restart reconciliation; a rerun signs a
new envelope and cannot replace an existing publication.

The integration test creates real commits and packed objects, traverses them
through the production Git reader, uses real P-256 signatures, and verifies
publication through the production private service. The subprocess fixture
substitutes for FlareKit and transport substitutes for live GitHub/Cloudflare.
This is not evidence of actual age decryption or live OIDC authorization.

Remaining activation work includes an enrolled production recovery signer,
trusted archive publication descriptors, macOS FlareKit/Keychain qualification,
remote service bindings and retention, report renewal/restart reconciliation,
and a selected-repository live workflow run. This module supplies composition,
not those credentials or deployment state.
