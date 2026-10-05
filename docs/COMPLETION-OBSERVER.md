# Independent promotion completion

CompletionObservationService is the private confirmation capability used by
CHECKPOINT_COMPLETION. POST `/v1/ledger/promotion-observation` accepts exactly
operationID, repositoryID, entryPayloadDigest, baseSHA and commitSHA. It loads retained
authority approval and the broker's read-only lease view from installed bindings.
Caller success assertions, credentials, alternate URLs and target refs are not inputs.

The authority view preserves the originally admitted promotion payload. Readback
checks retained bundle integrity and binding to the fixed execution record. It does
not repeat expired authorization or permit another credential issue. The independent
observer matches the payload digest, operation, repository, ref, tree and executor
run against the broker's retained record digest. A lease must have reached successful
issuance: issued, uncertain or completed plus retained provider expiry. Issuing alone
or uncertainty without evidence of successful issuance cannot confirm completion.

GitHub observation independently requires actual main/master to point at the candidate,
a verified signed single-parent child of approved base, the approved tree, and available
source commit. Authority readback and the ref are checked again before confirmation.
Approval expiry does not make completed work disappear. No observer method writes refs,
mints tokens, signs ledger entries or clears reservations.

## Bindings

| Worker | Binding | Named entrypoint |
|---|---|---|
| Completion observer | OBSERVATION_AUTHORITY | AuthorizationService |
| Completion observer | OBSERVATION_BROKER | BrokerObservationService |
| Checkpoint | CHECKPOINT_COMPLETION | CompletionObservationService |

OBSERVATION_CONFIG_JSON is an array of records with exactly repositoryID, repository
and branch. Configuration pins repository identity and main/master observation target.
OBSERVATION_ENABLED starts false. Public observer ingress returns 404.

The authority adds private `/v1/authorization/completion-record`. The broker adds named
BrokerObservationService with private `/v1/broker/lease-observation`. It returns only
operation ID, execution record digest, lease state, run IDs and expiry metadata. No token,
JWT, JTI, custody ciphertext or App key is returned. Public broker routing does not expose
this path. The read runs in a storage transaction outside the execution promise queue:
completion already awaits it from inside that queue, so enqueueing it would deadlock.

Wrangler's controller entrypoint is now src/broker-worker.mjs, which reexports the existing
controller and Durable Object classes and adds the private named observation entrypoint.
Durable Object class names and migration history are unchanged.

## Remaining boundaries

Retained authority and broker records are trusted private services. This observer does
not protect against compromise or simultaneous rollback of all those services. It does
not prove that an issued token caused the update; it confirms that the approved candidate
is now the protected tip and the corresponding lease was successfully issued.

Signed receipt construction and BROKER_RECEIPTS finalize/observe routing are implemented
by LedgerReceiptService. BrokerVerificationService supplies pre-write and completion
routes from this Worker. See SIGNED-RECEIPTS.md for binding and custody requirements. Archive recovery,
hardware enrollment, provider locks and production bindings still require qualification.
Do not enable issuance by substituting caller flags or test observers for those services.

Tests cover exact binding, tampered retained approval, foreign runs, failed issuance,
expired reconciliation, moving ref, merges and changed tree. Real workerd qualification
covers private entrypoints, fixed-origin GitHub observations with a test network adapter,
and public exclusion of broker lease readback. No live GitHub credential or ref update
is involved in those tests.
