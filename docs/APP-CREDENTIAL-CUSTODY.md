# Remote App credential custody

`controller/src/enrollment/app-vault.mjs` implements encrypted server-side storage for GitHub App private keys, webhook secrets, and client secrets. It is a private adapter, not a public endpoint or a local key importer.

An isolated enrollment adapter calls `stage` immediately after receiving credentials. Only `activate`, using a trusted server-side verifier, can permit signing. The verifier must independently confirm the App ID, numeric owner ID, role and exact provider permissions using the generated App identity. Its evidence digest is retained. A client-supplied `verified` flag must never be used as that adapter.

`sign` decrypts only an active record, imports an unextractable RSA key, and delegates to the fixed App-JWT policy. It cannot sign arbitrary claims. `status` returns public identifiers and state only. `revoke` removes ciphertext and retains a tombstone; it does not revoke the key at GitHub. Provider-side key deletion and installation-token revocation are separate operations.

Each record uses AES-256-GCM with a fresh nonce. Authenticated data binds the protocol, credential reference, App ID, owner ID and role. Wrapping keys must come from remote secret bindings. `reencrypt` supports additive wrapping-key rotation: retain both KEKs, reencrypt and verify all records, then remove the old KEK. Credential identity/key rotation is a separate enrollment operation.

Storage must provide atomic transactions. Activation, signing and re-encryption compare the retained record before committing or releasing a result, rejecting concurrent retirement or changes. A result already released cannot be recalled; policy and credential issuance still need their existing downstream checks.

This is software custody in a trusted Cloudflare runtime. PEM material exists briefly in server memory; nonextractable WebCrypto does not make it hardware-backed. No production key is generated or enrolled by the tests.

## Qualification and remaining activation gates

Three tests cover ciphertext-only persistence, staged/revoked refusal, authenticated-data substitution, verification refusal, KEK rotation and retirement during verification. The full controller suite passes 61 tests.

Not yet wired: isolated browser enrollment, journaled one-shot manifest exchange recovery, the actual GitHub identity/permission verifier, private signer Worker deployment, and remote KEK provisioning. Existing policy, hardware, evidence and receipt service bindings must also be implemented and qualified. Do not enable the public broker or apply App-only main protection on the strength of this adapter alone.
