# Recovery restart journal

Install `journal: await recoveryJournal(canonicalPrivateDirectory)` in
recoveryRuntime or recoveryJob. The directory must already exist, belong to the
current user and deny group/other access. The journal contains public signed
reports only, never signing keys, credential tokens or restored plaintext.

Reports are fsynced before atomic create-only publication into the journal.
Concurrent retain attempts select the first complete record. Records are keyed
by the approved intent plus installed policy digest. A restart verifies the
retained signature, current trust inventory, intent, policy and expiry before
retrying publication. It does not restore or sign again. Lost upload responses
can therefore reconcile with the exact original envelope.

No automatic deletion or replacement exists. Expired evidence fails closed;
this does not solve report renewal at the fixed remote object key. A durable
journal must survive runner teardown to provide cross-run recovery. Ephemeral
GitHub runner storage alone does not. Same-user/root compromise and rollback of
the entire local journal are outside its storage guarantee; signatures and the
remote conditional publisher remain verification boundaries.
