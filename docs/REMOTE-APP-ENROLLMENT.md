# Journaled remote App enrollment

`enrollment/journal.mjs` is the private session state machine. `enrollment/github.mjs` implements fixed-origin GitHub manifest conversion and authenticated App verification. These adapters are not public endpoints.

An independently authorized session supplies an operation reference, numeric owner, role, manifest digest and expiry (at most ten minutes). Session creation must occur only after the isolated owner approval flow. The manifest digest is recorded for that flow to bind; the adapter does not itself authenticate an operator or generate/validate the manifest.

States are ready, exchanging, staged and active. An atomic transaction reserves exchanging before sending the one-use conversion request. Returned PEM/client/webhook secrets are immediately passed to encrypted vault staging. No callback code or provider secret enters the enrollment journal.

Verification uses the staged private key to authenticate GET /app. It requires the exact numeric App and owner IDs, the exact role permissions plus mandatory metadata read, and no subscribed events. This increment deliberately supports Apps without webhook subscriptions. Apps subscribing to push are rejected. Existing manifest helper webhook support does not broaden this verifier.

The vault becomes active only after successful verification. A staged credential can be verified again without repeating conversion. If vault staging succeeds but the journal update fails, reconciliation discovers the staged vault record. If the response or durable staging is lost, exchanging remains uncertain and blocks another conversion. Recovery then requires isolated provider-side remediation; this is not automatically recoverable.

The owner-approved session service, isolated browser callback transport and signer Durable Object integration remain to be wired. Do not expose create/exchange through a generic public endpoint or route credential-bearing callbacks through the local CLI. The legacy provisioning enrollApp helper is not replaced or invoked by these new adapters.

## Qualification

67 controller tests pass. Six new tests cover one-use conversion, secret-free journaling, staged recovery, lost-response refusal, concurrent reservation, pinned provider endpoints, exact identity/authority and event checks. Provider calls are mocked. Live GitHub enrollment and real-runtime journal restart/concurrency tests remain required.
