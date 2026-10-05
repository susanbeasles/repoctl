# Hardware-approved App enrollment

The private EnrollmentApprovalService verifies domain-separated P-256 signatures over exact reviewed JSON bytes. Its payload has only operationID, ownerID, role, manifestDigest and expiresAt (Unix seconds, maximum five minutes). The manifest digest must be computed by the isolated enrollment initiation flow over the exact approved manifest. This service verifies the digest's signed value; the browser initiation integration must enforce the actual manifest match.

`repoctl approval sign-enrollment INTENT --policy POLICY --approve` uses the existing enrolled sealed-policy key, emits an explicit review message and signs once. Its public approval envelope contains no App credential. Keychain signatures are software-backed and must not be admitted as hardware enrollment by the remote verifier.

Private POST /v1/enrollment/admit accepts the signature envelope and retains its digest under the operation. Conflicting approvals cannot replace it. Private POST /v1/enrollment/authorize accepts operationID, approvalReference and action, re-verifies the signature, current trust and hardware status, then returns the matching signer session. Expiry blocks all authorization, including reconciliation. Renewals/recovery after expiry need a separate authenticated protocol; this increment does not silently prolong authority.

The App signer APP_ENROLLMENT_APPROVAL binding must target repoctl-enrollment-approval with entrypoint EnrollmentApprovalService. The approval Worker requires separate ENROLLMENT_TRUST and ENROLLMENT_HARDWARE private bindings:

- POST /v1/enrollment/trust with keyID returns the pinned keyID, ownerID, publicKeyX963 and revoked flag. It must use independently provisioned accepted trust, never request-supplied enrollment.
- POST /v1/enrollment/verify with keyID and ownerID returns keyID, hardwareVerified, revoked, proofDigest and validUntil. Actual hardware provenance must be independently verified. A matching software signature alone proves no hardware origin.

Those record services and authenticated bootstrap still need implementation. The packaged Worker remains disabled and has no public route. No production enrollment or deployment has occurred.

## Qualification

```bash
cd ~/code/repoctl
./Tests/mac-enrollment-approval.sh
(cd controller && npm test && npx wrangler deploy --config wrangler.enrollment-approval.jsonc --dry-run --outdir /tmp/repoctl-enrollment-approval-dry-run)
node controller/scripts/qualify-enrollment-approval-local.mjs /tmp/repoctl-enrollment-approval-dry-run/entrypoint.js
./scripts/install
```

70 controller tests pass. Real workerd qualification covers public/private boundaries, DER exact-byte verification and live revocation readback using synthetic trust/hardware services. The macOS script compiles the native CLI, verifies its DER signature independently, rejects another signing domain and rejects expiry. macOS qualification is pending user execution; no Swift compiler is available in the implementation workspace. Test enrollment uses software Keychain keys only and retains its temporary enrollment for explicit cleanup.
