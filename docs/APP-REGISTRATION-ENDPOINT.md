# Remote App registration endpoint

This Worker connects a reviewed App plan to the existing private enrollment authority and remote credential vault. It is disabled by default. Registration does not install the App or activate repository protection.

## Private control

Bind the named `RegistrationControlService` to an authenticated operator service. Public ingress cannot call it.

- `POST /v1/registration/create`: exact fields `operationID`, `approvalReference`, `plan`, `expiresAt` (milliseconds; at most five minutes).
- `POST /v1/registration/status`: `operationID`, `approvalReference`.
- `POST /v1/registration/reconcile`: `operationID`, `approvalReference`.

The plan must use the configured owner, a fixed role and exactly `REGISTRATION_ORIGIN/github/callback`. The independent enrollment authority must have admitted the signed enrollment intent beforehand. Its approved owner ID, role and manifest digest must match the reviewed plan. Custody verifies authorization again before conversion.

Creation returns the random state and manifest bytes. Open `REGISTRATION_ORIGIN/github/register?state=STATE` in the authorized registration browser. GitHub requires account consent and may require MFA.

## Public routes

The registration page submits the exact reviewed manifest to GitHub's personal-account registration endpoint. GitHub redirects to `/github/callback?state=STATE&code=CODE`. The Durable Object resolves the hashed state, atomically reserves the exchange, and sends the code to the private custody service. It retains neither code nor provider secrets. A repeated or concurrent callback cannot issue another conversion.

HTML is escaped, scripts are forbidden, framing is forbidden, and responses use no-store and no-referrer. Callback query parameters must be excluded from HTTP logs and analytics at the hosting layer. Do not enable request tracing that captures URLs or bodies.

## Deployment configuration

Use `controller/wrangler.registration.jsonc`. Configure:

- `REGISTRATION_ORIGIN`: dedicated HTTPS origin without path, query or fragment.
- `REGISTRATION_OWNER` and numeric `REGISTRATION_OWNER_ID`.
- `APP_ENROLLMENT_APPROVAL`: named `EnrollmentApprovalService` binding.
- `APP_ENROLLMENT`: named `AppEnrollmentService` binding.
- Enable `REGISTRATION_ENABLED` only after the authority and custody services are qualified.

The registration Worker has no App keyring, signing service, archive keys or repository writer permissions. The custody Worker separately owns the encrypted App credentials.

## Recovery and remaining gates

A lost exchange response remains reserved. Use private reconciliation against the custody journal; never resend the conversion code. Expired approval blocks recovery until a new owner signature is admitted through the private renewal protocol in [ENROLLMENT-RECOVERY.md](ENROLLMENT-RECOVERY.md). A failure during session creation can retain a reservation without a usable launch token; status exposes custody state but does not silently recreate a session.

This endpoint does not provide an isolated remote browser. Using a local browser exposes the temporary callback code to that browser, though the PEM stays remote. The requirement that even the temporary code never reach the laptop requires a separately isolated registration browser and authenticated operator transport. Those are not implemented here. Neither are installation verification and the native `app provision` command.

## Qualification

```sh
cd controller
npm test
npx wrangler deploy --config wrangler.registration.jsonc --dry-run --outdir /tmp/repoctl-registration-dry-run
node scripts/qualify-registration-local.mjs /tmp/repoctl-registration-dry-run/entrypoint.js
```

The workerd qualification uses synthetic approval and custody bindings. It tests RPC isolation, the reviewed form, wrong-state rejection and one exchange across simultaneous callbacks. It is not a live GitHub registration or deployed custody test.
