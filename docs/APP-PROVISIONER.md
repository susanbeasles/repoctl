# Repeatable App provisioner

Start with `templates/apps/writer.example.json`. Each configuration selects a name, owner, role, HTTPS homepage/callback and repositories. The callback example is not deployed. V1 profiles are writer, validator, builder and release; arbitrary permissions and webhook subscriptions are not implemented.

```bash
repoctl app plan templates/apps/writer.example.json > writer.plan.json
```

Planning performs no remote writes. Output contains the exact GitHub manifest bytes, their SHA-256 digest and explicit unregistered/uninstalled states. Owner and repositories are installation intent; GitHub repository IDs and actual installation scope must be verified remotely. Repeated provisioning of different configurations must create distinct operation references and App credentials; no shared secret export is required.

The remote `verifyAppPlan` adapter validates the exact digest, manifests, permission profile and owner/repository selection. It rejects added permissions, mismatched bytes, foreign targets and caller assertions of successful registration. The approved digest must be bound into the existing hardware-signed enrollment intent. The isolated registration flow must submit those exact bytes to GitHub.

## Qualification

```bash
./Tests/mac-app-plan.sh
./scripts/install
repoctl app --help
```

The native script independently verifies the plan digest and permission payload and rejects HTTP callbacks. Linux cannot compile the macOS target; native qualification is pending. Node tests cover plan substitution and foreign-target refusal.

## Unfinished commands

`app provision`, `app status`, `app rotate` and `app retire` are still targets, not installed commands. They require the isolated authenticated registration transport, remotely accepted owner/hardware trust, installation verification and credential lifecycle adapters. Existing remote journal/signer/approval services implement parts of that path but are not activated by app plan. No App is registered by this increment.
