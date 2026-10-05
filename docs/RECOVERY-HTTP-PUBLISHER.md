# Recovery job upload transport

Compose `recoveryHTTPPublisher` as recoveryJob's publisher. Install the HTTPS
upload origin, audiencePrefix, GitHub runner OIDC URL/request token, positive
runID/runAttempt and exact approved archive intent. The client requests an OIDC
token whose audience binds canonical `{intent,envelope}`, then uploads that
publication to `/v1/archive/recovery/upload`. Redirects are rejected, requests
have 15-second deadlines, and responses are bounded. No storage API token or
GitHub writer token is issued or forwarded.

The client checks the returned repository, object key, envelope/report digests,
expiry and publication protocol before confirming success. Its get method returns
the locally retained envelope confirmed by the server receipt. It is not a second
remote object read: the private publication service performs R2 readback before
returning the receipt. TLS and the installed gateway are trust boundaries.

Lost responses fail rather than implying success. Retrying the identical signed
envelope is safe under conditional publication. Re-signing on an independent
job retry produces a different envelope and cannot overwrite the existing key;
retain the reviewed envelope for reconciliation. Expired-report renewal remains
a separate protocol requirement.

The FlareKit adapter, Git reader, recovery signer and this publisher are separate
installed capabilities. This change supplies the upload transport, not live
provisioning or a runnable workflow with enrolled production signing credentials.
