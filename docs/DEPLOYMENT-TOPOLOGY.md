# Repeatable service wiring plan

Create a nonsecret JSON input with prefix, receiptBucket and recoveryBucket.
Example: `{"prefix":"repoctl-personal","receiptBucket":"repoctl-receipts","recoveryBucket":"repoctl-recovery"}`.
Run `node controller/scripts/plan-deployment.mjs INPUT.json > PLAN.json` from
the repository root. This performs no network calls or deployment.

The plan contains fourteen Worker configurations with named service bindings,
separate receipt/recovery buckets, existing Durable Object migrations and every
activation flag false. Workers.dev and preview URLs are disabled. No App key,
wrapping key, private signing key or OAuth credential belongs in the input.
Generated main paths remain relative to the controller directory; a deployment
adapter must preserve that resolution when writing configuration files.

The upload gateway binds only RecoveryPublicationService. The broker binds
only authorization, App signing, prewrite verification and receipt services.
Observation has read-only private broker/authority entrypoints. Evidence reads
policy, checkpoint and archive verification independently. This is capability
wiring, not proof of isolation against a Cloudflare account administrator.

Registration binds remote AppEnrollmentService and EnrollmentApprovalService.
OperatorService binds the registration control and retained approval services;
the separate operator ingress selects only OperatorService. The planner does
not invent an `OPERATOR_SESSIONS` provider or populate Access issuer, audience,
owner subject or protected routes. Those installed dependencies remain explicit
unresolved items, along with the isolated registration origin/owner configuration.
The topology test checks every included target and its exported named entrypoint,
and the actual planner CLI emits all fourteen disabled configurations. Neither
check establishes live service availability or authorizes activation.

Activation is intentionally not implemented by this planner. Current source
still lacks a deployed hardware provenance/revocation verifier and enrollment
trust inventory. Those are required by policy admission, owner authorization
and App enrollment. Additional gates include reviewed inventories, remote key
custody, retention, an independent checkpoint witness, authenticated operator
provisioning, and live GitHub/Cloudflare qualification. Merely binding a service
or setting an enabled flag does not satisfy them.
