# Signed receipt finalization and broker verification

LedgerReceiptService implements the broker's private `/v1/ledger/finalize` and the
authority's private `/v1/ledger/observe`. The caller supplies an operation ID and fixed
execution intent or retained record. The service independently loads the originally
admitted ledger payload; caller-supplied entries and signing keys are not accepted.

## Production service connections

| Consumer | Binding | Named entrypoint |
|---|---|---|
| Broker | BROKER_VERIFIER | BrokerVerificationService |
| Broker | BROKER_RECEIPTS | LedgerReceiptService |
| Authority | AUTHORIZATION_RECEIPTS | LedgerReceiptService |
| Receipts | RECEIPT_AUTHORITY | AuthorizationService |
| Receipts | RECEIPT_COMPLETION | CompletionObservationService |
| Receipts | RECEIPT_CHECKPOINT | CheckpointService |
| Checkpoint | CHECKPOINT_COMPLETION | CompletionObservationService |

BrokerVerificationService is hosted by the completion observer Worker. Pre-write
`/v1/evidence/authorization` compares the exact broker request with retained authority,
repeats current authorization (including policy, hardware and all admission evidence),
and observes main/base plus the signed single-child candidate and approved tree.
Post-write `/v1/evidence/completion` uses the independent completion observer and the
successfully issued lease. It reconciles an already authorized operation after expiry;
it does not mint credentials or reopen authorization.

## Receipt persistence

Finalization independently confirms promotion before signing. A SQLite transaction
signs and retains the exact envelope before any checkpoint network call. Subsequent
retries use the retained signature, including after a successful append response is
lost. Concurrent calls select one retained envelope. The checkpoint independently
confirms promotion again, conditionally creates the signed object and advances its
retained tip. Finalization verifies checkpoint receipt readback before local completion.

Observation verifies the retained authority record and the independently retained
checkpoint receipt. It can confirm a successful checkpoint append while the receipt
service's local completion marker is still pending. It does not accept an executor's
success assertion. A missing or altered ledger object blocks receipt success.

The checkpoint adds private `/v1/checkpoint/receipt`, taking repositoryID and operationID.
It verifies retained ledger continuity and the exact completion object before returning
the stable operation receipt. No checkpoint pointer or signing key comes from callers.

## Signing configuration

RECEIPTS_ENABLED starts false. RECEIPT_REPOSITORIES_JSON contains the installed numeric
repository allowlist. Required bindings are those listed above and LEDGER_RECEIPT_COORDINATOR.
Each operation uses a separate SQLite Durable Object. Public ingress returns 404.

RECEIPT_SIGNING_KEY_JSON is a remote secret containing exactly keyID, privateKeyPKCS8
(base64 P-256 PKCS8) and publicKeyX963 (base64 raw public key). keyID must equal the
SHA-256 public-key fingerprint. The private key is imported nonextractable into
WebCrypto and its public pair is verified. This is a **software key in remote custody**,
not hardware-backed generation or hardware attestation. Secret provisioning and remote
key generation are not implemented by this patch; synthetic local test keys are not
production enrollment.

For additive rotation, optional RECEIPT_VERIFICATION_KEYS_JSON contains old public
keys as keyID/publicKeyX963 records. It excludes the active key, which is automatically
included. Retain every historical public key needed by existing receipts, and update
the checkpoint's trusted public inventory before signing with the new key. Removing
an old key blocks verification instead of accepting unverifiable history. Rotation
configuration must be reviewed; it does not retroactively re-sign old receipts.

## Qualification and remaining work

Node tests exercise real signature creation, the actual checkpoint component, exact
retry, concurrent finalization, failed promotion, missing archive objects and additive
verification-key rotation. Real workerd tests compose private receipt and checkpoint
entrypoints with SQLite/R2, lose a successful append response, restart, and verify
that the signature and retained object remain byte-identical. Completion and authority
adapters in that test use synthetic records; live promotion is not qualified.

The broker's verifier and receipt interface implementations now exist. Production
hardware enrollment, archive recovery verification, remote key provisioning, locks,
service bindings and disposable live GitHub issuance/promotion/revocation qualification
remain required. All default deployment flags remain disabled.
