# GitHub App provisioning capability

This library composes the existing repoctl registration sessions, independently authorized enrollment journal, GitHub identity verification and encrypted credential custody. SOURCE.json records the original source revision and hashes. It creates no Worker host, network route, storage binding or GitHub grant.

`createGitHubAppProvisioner` accepts trusted storage, vault, provider and approval adapters, an exact GitHub owner and numeric owner ID, an HTTPS callback and reviewed named permission/event profiles. Request input cannot supply a new profile. Registration binds the owner, role and manifest digest to an independently accepted approval reference; conversion reserves state before its one-shot provider effect. Provider verification checks the exact owner ID, App ID, permissions and events before custody activation. Public results contain operation state and App ID, never provider credentials or callback codes. Recovery reconciles retained custody without repeating conversion.

Configure `githubEnrollmentProvider` and `appVault` with the same reviewed profiles used by the composition. The storage adapter must provide durable serializable transactions; the vault keyring must provide the existing nonextractable encryption keys; the approval adapter must independently verify owner/hardware approval for each requested action and return the bound session. These are commissioning inputs, not defaults supplied by this package. Installation and runtime signing capability attachment require their own reviewed evidence.

The four default repoctl roles remain available. New sessions retain a profile digest. Older in-flight enrollment records without that digest are preserved but fail closed for exchange/reconciliation and require reviewed recovery; no automatic migration or reconversion is provided. Existing credential custody records are neither deleted nor transferred by this library.

Run `npm test` in this directory for bounded synthetic tests. They do not prove live identity, custody, network access or deployment.
