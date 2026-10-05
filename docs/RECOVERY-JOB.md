# Dedicated archive recovery job

`recoveryJob` coordinates installed restore, Git reader, signer and publisher
capabilities. It validates the intent before restoration, verifies the complete
candidate/source reachable object closure, signs the exact report, independently
verifies that signature against the installed public key inventory, publishes,
and compares readback to the exact signed envelope. Cleanup runs in `finally`.
Cleanup failure fails the job; it is not silently reported as success.

`restore.run(intent)` must fetch and authenticate the approved FlareKit archive
and restore into an isolated temporary directory. Return a session with an async
`cleanup()` method. The restore adapter must clean its own partial output if it
throws before returning a session. `readerFor(session,intent)` supplies the
restored Git reader. No working checkout may substitute for archive recovery.

`signer.sign(payload)` returns a standard signed ledger envelope; the supplied
`recoverySigner` supports a separately provisioned P-256 key. This is not a
hardware provenance claim. `publisher.create(key,envelope)` must conditionally
create the object or reconcile an identical existing object; `publisher.get(key)`
returns the retained envelope. Never overwrite a conflicting report.

Report lifetime defaults to four minutes, capped at five. Publication does not
trigger promotion or issue credentials. The private archive-evidence service
performs its own signature, policy and expiry checks on every admission request.

The runner is implemented and tested with injected capabilities. Concrete
FlareKit process execution, credential-provider integration and R2 publisher
provisioning are still required for a live job. This module does not shell out
with caller-selected commands, accept caller-selected endpoints, or provision
signing/decryption keys.
