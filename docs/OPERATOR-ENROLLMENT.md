# Operator enrollment recovery adapter

`controller/src/operator/enrollment.ts` connects authenticated operator context
with existing private enrollment authority and registration recovery capabilities.
Status and reconcile require the fixed numeric owner, authorized context and exact
operation/approval references. References alone are not operator authentication.
The adapter verifies retained approval before private registration access; that
service independently checks authorization again for the selected recovery action.

Responses project only protocol, operation ID, state and optional numeric App ID.
Callback codes, launch state, manifest bytes and provider credentials are never
projected. Provider failures are suppressed and recovery mutations are never
retried. Each installed capability has a ten-second observation bound. A timeout
does not prove the underlying service stopped; retained remote state must be
reconciled rather than replaying an uncertain mutation.

This is a private composition module, not public authentication middleware or a
native command. An installed ingress must independently authenticate owner context.
Native init/submit, isolated provisioning browser, installation verification and
production enrollment remain unfinished. Focused tests use synthetic capabilities;
strict type checks and the controller suite pass without deploying authority.

## HTTP composition

`src/operator/http.ts` exposes exact POST status/reconcile routes under
`/v1/operator/enrollment/`. It is disabled by default. An installed identity
verifier must establish the fixed numeric owner from verified identity evidence,
including signature/issuer/audience/expiry and revocation; header claims alone
are insufficient. The handler authenticates before reading the request body,
limits JSON to1KiB, rejects extra fields and query parameters, and projects the
same public-only response. Errors use a fixed message and no-store headers.

The entire request has a ten-second observation deadline and passes cancellation
to identity verification. Cancellation stops further local progression, not an
already issued private recovery mutation. Do not replay an uncertain reconcile.
This module is not a deployed ingress or a commissioned identity verifier. Native
client wiring and the installed verifier remain required. Tests cover disabled
ingress, foreign identity, spoofed body claims, route denial, oversized input,
stalled authentication and provider-error suppression using synthetic identity.

HTTP cancellation is propagated to the enrollment adapter. It checks cancellation
before and after each capability call, preventing a delayed approval response
from starting recovery after the caller has already timed out. The regression
composes both real modules, expires HTTP while approval is pending, resolves the
approval afterward and verifies zero registration recovery calls. An already
issued mutation still needs independent reconciliation; cancellation does not
undo it or establish its outcome.

## Private Worker integration

`src/operator/entrypoint.ts` exports only the named `OperatorService`; public
fetch returns404. `wrangler.operator.jsonc` disables rollout and contains no
service bindings. Commissioning requires the fixed owner and private
`OPERATOR_SESSIONS`, `OPERATOR_APPROVAL` and `OPERATOR_REGISTRATION` bindings,
plus reviewed `OPERATOR_IDENTITY_CONFIG_JSON` containing exact issuer, audience,
subject and maximum lifetime in seconds.
The latter two connect existing enrollment approval and registration contracts.

The Worker uses the Access verification core on the bounded
`Cf-Access-Jwt-Assertion`; it validates issuer, signature, exact audience, expiry
and owner subject. Only the token digest and fixed identity binding reach the
private session service at `/v1/operator/session`. The actual owner mapping and
current-session service remain uncommissioned. Native client authentication
remains required.

`npm run check:runtime` now includes a real workerd qualifier for named service
isolation, disabled rollout, absent/foreign identity, approved status/reconcile
and secret-free projection even when a private fixture returns secret fields.
Identity and provider capabilities in this qualifier are synthetic. No live
Access authentication, enrollment or provider mutation is established.

## Access identity verification core

`src/operator/identity.ts` verifies actual RS256 application JWTs using only the
configured HTTPS Cloudflare Access team issuer's `/cdn-cgi/access/certs` endpoint.
It pins the exact single application audience and Access user subject to the
numeric personal owner. Email strings do not establish ownership; org tokens and
service-token subjects are denied. Algorithms and trust URLs cannot be selected
by token headers; public keys must be unique, signature-only RSA with at least
2048 bits. JWT lifetime is bounded by configured policy.

Authorization additionally requires an installed current-session verifier with
an exact issuer/audience/subject/owner/token-digest/expiry binding, active and
unrevoked status, and proof validity at most30 seconds. Signature and expiry alone
do not claim revocation. Neither that session service nor the real Access owner
mapping is commissioned here. The core is now wired into the Worker; the former identity-response binding
is removed. Missing proof, timeout, redirect, oversized key inventory and token
expiry during verification deny. Tokens and provider errors are not returned.

Tests generate an actual temporary2048-bit RSA key and verify positive and
adversarial signatures; JWKS and session provider responses remain synthetic.
Official contracts: [Access token claims](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/application-token/)
and [JWT validation](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/).

The actual workerd qualifier now generates an RSA-signed application assertion
and exercises verification inside the bundled Worker. Foreign subject/audience,
expired token and revoked session deny before enrollment capabilities; status
and reconcile retain the exact public-only projection. Public JWKS retrieval and
current-session proof are intercepted synthetic services. No real Access grant
or provider-backed revocation is claimed.

## Native transport increment

`Sources/repoctl/OperatorClient.swift` implements bounded enrollment status and
reconcile requests to a fixed HTTPS origin. An installed authentication adapter
must supply the assertion in memory; it is never accepted as a command argument,
printed, returned or persisted by this transport. The client clears cookies,
credential storage, caches and inherited extra headers, rejects redirects, limits
responses to64KiB and uses10-second network deadlines. It never retries recovery.
Only the typed public status projection can reach client output.

The native Swift6 fixture exercises actual URLSession delegate behavior with
synthetic URLProtocol responses, including foreign binding, denial, oversize,
invalid origin/assertion and injected ambient header removal. It does not prove
remote authentication or real provider behavior. Build/check commands:

```sh
swift build
swiftc -swift-version 6 -parse-as-library Sources/repoctl/OperatorClient.swift Tests/operator-client.swift -o /tmp/repoctl-operator-client-check
/tmp/repoctl-operator-client-check
```

The client is wired into `app status` and `app reconcile` with exact operation,
approval, controller and absolute Access CLI arguments. Cached-token retrieval
uses only `access token --app`; stdin and stderr are suppressed, output is bounded
in memory, and lookup has a ten-second deadline. Empty, malformed or unavailable
sessions fail without login or browser fallback. Synthetic helper fixtures cover
fixed arguments, failure, overflow, timeout and origin rejection before execution.
Existing Access CLI
`cloudflared` was not found in the operator PATH; no login or token request ran.
Live authentication acquisition, installed protected ingress and full native
init/submit remain required. A private named Worker service alone is not a public
client endpoint, and its404 public behavior remains intact.

## Public ingress relay

`src/operator/ingress.ts` uses `operatorRelay` for the two exact enrollment routes.
`wrangler.operator-ingress.jsonc` disables rollout, workers.dev and all service
bindings; it contains no deployed route. The relay requires an application JWT,
limits input to1KiB and output to64KiB, allows ten seconds, forwards only the
assertion and JSON content type, and projects only bound public status. Cookies,
ambient Authorization, provider response headers and private fields are discarded.
The relay never establishes identity or approval: the bound private OperatorService
verifies both independently. It has no retry, login, registration or custody API.
A deadline or transport failure leaves recovery outcome uncertain; inspect retained
state before retrying. Cancellation does not undo a mutation already issued.

Installation requires the personal Access application and protected custom route,
fixed issuer/audience/owner subject, the private live session/approval/registration
services, and an `OPERATOR_SERVICE` binding selecting the `OperatorService`
entrypoint. These remain unqualified external dependencies; no public deployment
or Access policy was changed.

The full local runtime check now builds12 configurations and runs14 workerd
qualifiers. The operator fixture drives the actual ingress bundle through the
private service with RSA-signed JWTs, disabled gates and foreign/expired/revoked
denials. JWKS, session proofs and registration providers remain synthetic.
