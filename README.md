# Vault Proxmox secrets engine

Community HashiCorp Vault secrets-engine plugin that issues **short-lived Proxmox VE API tokens**, associates them with nonrenewable Vault leases, and deletes them when revoked.

> [!IMPORTANT]
> **Same-user issuance only.** The plugin refuses to issue credentials for any Proxmox user other than the account configured on that Vault mount. Use a separate mount for each identity (for example, one for image operations and another for VM deployment). Do not grant the plugin an issuer token with global `PVEUserAdmin` access on `/access`; disposable Proxmox VE 9.2.2 tests confirmed that such an issuer can mint a working `root@pam` token.

## Security model

```text
Authenticated workload
      |
      v
Vault ACL -> proxmox-deploy/creds/deployer
      |
      v
Vault external plugin (mount: proxmox-deploy/)
      |    issuer: deployer@pve
      |    auth: password -> short Proxmox session ticket
      v
Proxmox API -> create deployer@pve!<unique-temporary-token>
      |
      v
Vault returns credential + nonrenewable lease
      |
      +-- Vault revoke / expiry -> same-user token deletion
```

A separate `proxmox-images/` mount can use `images@pve` credentials. Vault policies can allow callers to access one mount and not the other. The generated API tokens use `privsep=false`, so the **Proxmox user must be restricted at its own ACL layer**; an explicit `inherit_user_privileges=true` role field acknowledges this.

## Supported functionality

| Capability | Behavior |
|---|---|
| One token per credential read | Each `<mount>/creds/<role>` request generates an independent Proxmox token |
| User selection | Role's target Proxmox user must match the mount's issuer user and realm |
| Preferred issuer auth | `auth_method=password`; dedicated PVE-realm account authenticates using a fresh Proxmox ticket for each API operation |
| Legacy issuer auth | `auth_method=token` supported, but still restricted to the same Proxmox user |
| Native expiration | Proxmox token expiration always finite, based on role TTL |
| Vault expiration | Nonrenewable Vault leases, explicit revoke and automatic revoke on expiry |
| TLS | Verified HTTPS; optional `ca_cert_pem` for private certificate authorities; redirects refused and new issuance rejects insecure TLS or custom headers/proxies |
| Multiple workloads | Separate Vault mounts with independent issuers, target users and ACL policies |
| Known limitations | Generated tokens inherit user permissions; no per-token ACLs, orphan reconciler, issuer history or HA/production acceptance certification |

## Documentation

| Guide | Coverage |
|---|---|
| [Deployment](docs/deployment.md) | Installation, same-user Proxmox account creation, Vault registration and secure production-style configuration |
| [Configuration and API](docs/configuration.md) | Full path and field reference; authentication modes and Vault ACLs |
| [Security](docs/security.md) | Real Proxmox authorization evidence, least-privilege model, migration safety and remaining risks |
| [Operations](docs/operations.md) | Credentials, revocation, password rotation, upgrades, backup and troubleshooting |
| [Real Proxmox CI](docs/real-proxmox-testing.md) | Containerized Proxmox 9.2.2 tests, verified findings and known limits |
| [Mock integration CI](docs/testing.md) | Disposable Vault + mock HTTPS Proxmox tests |
| [Development](docs/development.md) | Build/test tooling, source structure, release process |
| [Hermes Host Operations](docs/hermes-host-operations.md) | Kubernetes-authenticated MCP integration with ephemeral Proxmox tokens, least-privilege policies and cleanup |
| [Security audit](docs/audits/2026-11-07-security-review.md) | Reviewed controls, remaining risks, CI evidence and real-integration/production gates |

## Minimal role example

After the plugin is deployed and its mount is configured for `deployer@pve`:

```sh
vault write proxmox-deploy/role/deployer \
  user=deployer realm=pve ttl=30m max_ttl=1h \
  inherit_user_privileges=true
```

A Vault caller with `read` access to the exact credential path can issue credentials:

```sh
vault read proxmox-deploy/creds/deployer
```

The response contains `lease_id`, a token identifier in `data.token_id_full` and a one-time token secret in `data.secret`. Compose the Proxmox API authorization token as `<token_id_full>=<secret>`, not with the issuer's password.

Revoke with the **exact returned** lease ID:

```sh
vault lease revoke "<LEASE_ID_FROM_RESPONSE>"
```

> [!WARNING]
> Never log or commit issuer passwords, returned token secrets or unredacted Vault responses. Do not point the test-only workflows at production. Existing cross-user mounts from earlier versions will stop issuing new credentials after this security change; **existing leases remain revocable** while their former issuer still has adequate permissions. See [migration](docs/deployment.md#migrating-from-the-legacy-cross-user-configuration).

## Test status

- Standard Go tests, race detector, build/vet, module checks and pinned `govulncheck` vulnerability scanning run in GitHub Actions.
- A disposable Vault 1.21.4 process runs the plugin against a synthetic HTTPS Proxmox API.
- A disposable **real Proxmox VE 9.2.2** container validates same-user password-ticket issuance, Vault lease revocation, native expiry, and denial of cross-user issuance and token self-minting.
- The real-container suite also demonstrates that granting a non-root issuer global `PVEUserAdmin` can mint an authenticating `root@pam` token, and verifies this plugin refuses to use that issuer for cross-user issuance.
- A passing CI suite does not automatically certify compatibility with every real Proxmox/Vault installation; independently review ACLs and authentication methods before production use.

Source provenance and license: see [LICENSE](LICENSE) and the original [mollstam/vault-plugin-secrets-proxmox](https://github.com/mollstam/vault-plugin-secrets-proxmox).
