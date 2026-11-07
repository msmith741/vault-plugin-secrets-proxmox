# Vault Proxmox Secrets Engine

A community **HashiCorp Vault external secrets-engine plugin** that creates temporary **Proxmox Virtual Environment API tokens**. Vault issues a lease for each generated credential and calls Proxmox to delete the token when that lease is revoked or expires.

> [!WARNING]
> **Pre-production software.** Unit tests and an ephemeral real-Vault/simulated-Proxmox integration test are available, but successful integration with every Vault and Proxmox version, issuer privilege delegation, and protection against generated tokens creating replacement tokens have **not** been established. Complete the [security acceptance checklist](docs/security.md#pre-production-acceptance-checklist) before deploying with privileged or production infrastructure access.

## Features and constraints

| Feature | Behavior |
|---|---|
| Dynamic credentials | One fresh Proxmox token per read of `<mount>/creds/<role>` |
| Lifetime | Role default 30 minutes; minimum 1 minute, permitted role maximum no more than 24 hours |
| Proxmox expiry | Native expiration timestamp, independent of Vault availability |
| Vault leases | Non-renewable; explicit and automatic revocation supported |
| Role mapping | Vault role selects the target Proxmox username and realm |
| TLS | HTTPS required; normal certificate validation or optional PEM CA |
| Multiple credentials | One issuer credential per mount; use separate mounts for isolated issuers |
| **Privilege separation** | Generated tokens use `privsep=false` and inherit the **entire** target user's permissions |
| Compatibility | Go 1.26.2+ module; CI uses Go 1.27.3; validate deployed Vault/Proxmox versions independently |

The `inherit_user_privileges=true` role setting is an **explicit acknowledgement** of inherited permissions, **not** a mechanism that restricts them. Roles targeting `root@pam` are rejected. A temporary token may still be able to create another token if its Proxmox permissions allow it.

## Documentation

| Document | Contents |
|---|---|
| **[Deployment guide](docs/deployment.md)** | Prerequisites; Proxmox identities; compilation; Vault server configuration; plugin registration; live mount/role configuration; credentials; verification |
| **[Ephemeral integration tests](docs/testing.md)** | One-click GitHub Actions test with real disposable Vault and a local Proxmox HTTPS simulator; no persistent deployment required |
| **[Configuration and API reference](docs/configuration.md)** | Every Vault API path, field, response, TTL rule, examples, and Vault ACL policy patterns |
| **[Security and acceptance](docs/security.md)** | Permission model, threat analysis, release gates, token lifetime implications, safe authentication |
| **[Operations](docs/operations.md)** | Health checks, issuance/revocation, issuer rotation, upgrades, rollback, HA, backup, alerting, troubleshooting |
| **[Development](docs/development.md)** | Local build, test commands, synthetic API tests, dependency management, releases and contribution guidelines |
| **[Consumer policy example](docs/examples/consumer-policy.hcl)** | Read-only access to one Vault credential role |
| **[Operator policy example](docs/examples/operator-policy.hcl)** | Mount-specific management policy; requires review before granting |

## Quick orientation

The plugin is not a standalone HTTP service. Vault starts it as a child process after an administrator installs and registers its binary.

```text
CI / workload --Vault authentication--> Vault secrets engine
                                          |
                                  /creds/workload
                                          |
                                     Proxmox API
                                       create
                                          |
                           temporary token + Vault lease
                                          |
                                workload uses token
                                          |
                       lease expiry/revoke -> Proxmox delete
```

The Proxmox issuer API token is stored in the **secrets engine's config**, not in the calling workload's credentials. Workloads should have read access only to their own `creds/` endpoint. Do not grant them permission to manage `config` or `role/`.

### Minimal CLI example (after deployment)

An administrator defines a role for an existing, restricted Proxmox account:

```shell
vault write proxmox/role/workload \
  user="workload" \
  realm="pve" \
  ttl="30m" \
  max_ttl="1h" \
  inherit_user_privileges=true
```

An authorized consumer requests credentials:

```shell
vault read proxmox/creds/workload
```

**The response contains a secret.** Do not use a terminal recording, shared CI log, or unprotected file. The response includes `lease_id`, `lease_duration`, `lease_renewable=false`, `data.token_id_full` and `data.secret`. For the raw Proxmox API format, concatenate `token_id_full + "=" + secret`.

To revoke, use the **exact returned** lease ID, not the role path:

```shell
vault lease revoke "<LEASE_ID_FROM_RESPONSE>"
```

Read [the deployment guide](docs/deployment.md) for the required infrastructure configuration, authenticated secret entry, Vault policies, and validation steps.

## Current release status

- GitHub Actions verifies the module graph, unit tests, race detector, compilation, `go vet`, formatting, and release configuration.
- GitHub Actions runs a real disposable Vault 1.21.4 plugin process against a loopback HTTPS Proxmox simulator. Registration, mounting, authorization, issuance, expiry metadata and lease revocation have passed.
- [Run the ephemeral integration test](https://github.com/msmith741/vault-plugin-secrets-proxmox/actions/workflows/test-ephemeral-vault.yml) directly from GitHub; no real Vault or Proxmox credentials are required.
- It has **not** been approved for unattended use with privileged Proxmox accounts; the permission-boundary acceptance tests remain outstanding.
- Token renewal and per-token Proxmox ACL assignment are not implemented.
- The plugin's Vault `role.max_ttl` field validates configuration; because leases are non-renewable, it does not enable renewals or extend `role.ttl`.

## License and provenance

See [LICENSE](LICENSE). This project is maintained as a community fork of [mollstam/vault-plugin-secrets-proxmox](https://github.com/mollstam/vault-plugin-secrets-proxmox).

For official Vault plugin mechanics, consult the [Vault external-plugin documentation](https://developer.hashicorp.com/vault/docs/plugins/register). For Proxmox token semantics, consult [Proxmox user management documentation](https://pve.proxmox.com/pve-docs/pveum.html).
