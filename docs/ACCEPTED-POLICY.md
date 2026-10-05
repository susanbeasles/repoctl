# Accepted policy service

This private Worker implements `ACCEPTED_POLICY /v1/policy/current`. `/v1/policy/admit` requires independent owner and validator signatures over identical reviewed bytes plus current owner hardware verification.

The signed payload is `{policy, previousDigest, expiresAt}`. The accepted-policy schema is enforced by `importPolicy`. Expiry is seconds since epoch, within five minutes at admission. Parent is the preceding admission digest, or 64 zeroes for revision 1. Revisions increment exactly one.

Envelope protocols are `repoctl-policy-owner-v1` and `repoctl-policy-validator-v1`. Signatures cover protocol plus newline plus exact payload bytes; P-256 DER and P1363 are supported. Native owner approval:

```sh
repoctl approval sign-policy admission.json --policy profile.json --approve
```

The independent validator reviews and signs the same bytes. A general-purpose validator signer is not provided. Initial signer keys are pinned by deployment configuration; later revisions require the previously accepted signers. A proposed policy cannot approve itself. `policy.digest` retains its external approved-policy identifier meaning; `admissionDigest` separately hashes the entire signed bundle. No old protocol is reinterpreted.

## Deployment

Use `controller/wrangler.policy.jsonc`. `POLICY_BOOTSTRAP_JSON` has exactly `repositoryID`, `repository`, `ownerKeys`, `validatorKeys`. Keys contain `keyID` (SHA-256 of X963 bytes) and `publicKeyX963` (base64). Pin public roots through reviewed infrastructure; never use caller-supplied roots.

Bind `POLICY_HARDWARE` to the real provenance/revocation verifier implementing `/v1/enrollment/verify`. Bind named `AcceptedPolicyService` to the authority's `ACCEPTED_POLICY` binding. Checked-in `ACCEPTED_POLICY_ENABLED` remains false. Public ingress returns 404; private responses use no-store.

Readback verifies every retained revision from bootstrap: signatures, parents, identities, signer transitions and current pointer. Admission atomically retains revision records and updates the pointer. There is a 1,000-revision qualification limit to bound readback work.

This is logical append-only storage. Restoration of an entire older database requires detection through an external checkpoint; the independent anchoring service remains unfinished. This component alone does not resist full Cloudflare account compromise.

Native signing requires macOS qualification. Real hardware provenance, independent validator operation, authenticated operator transport and live deployment remain rollout gates.
