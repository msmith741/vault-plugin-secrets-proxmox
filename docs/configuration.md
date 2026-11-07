# Configuration and API reference

All paths below are relative to a Vault secrets-engine mount. Example mount names `proxmox-deploy/` and `proxmox-images/` correspond to **different dedicated Proxmox identities**; the binary is registered once but each mount maintains its own configuration and leases.

> [!WARNING]
> Cross-user token issuance is **disabled**. A role's Proxmox `user` and `realm` must match the configured issuer's `user` and `realm` for its mount. This is enforced **before Proxmox API calls** even if the issuer credential is overprivileged. Do not grant global `PVEUserAdmin` on `/access`; the real-Proxmox test showed that issuer can mint authenticating `root@pam` tokens.

## API endpoints

| Vault CLI | Mount-relative path | Behavior |
|---|---|---|
| `vault write` | `config` | Store/update mount's issuer credential and TLS settings |
| `vault read` | `config` | Read non-secret issuer settings; password and API-token secret omitted |
| `vault delete` | `config` | Delete issuer configuration (may break old lease revocation) |
| `vault write` | `role/<name>` | Create or update a named target role |
| `vault read` | `role/<name>` | Read role identity and TTL settings |
| `vault delete` | `role/<name>` | Delete role (affects future issuance only) |
| `vault list` | `role` | List roles |
| `vault read` | `creds/<name>` | **Create** a temporary Proxmox token and lease |
| `vault lease revoke` | `<exact_lease_id>` | Invoke target-token deletion |

The Vault mount's issuer identity is **not** exposed to consumers as a credential. Each response from `creds/<name>` contains a *new target token*.

## Issuer configuration: `<mount>/config`

| Field | Type | Default | Meaning |
|---|---|---|---|
| `auth_method` | String | `token` for legacy compatibility | `password` (recommended) or `token` |
| `user` | String | Required | Proxmox issuer account name without realm |
| `realm` | String | Required | Proxmox authentication realm |
| `password` | Secret string | Required for `password` | Issuer account password, used to create short-lived tickets |
| `token_id` | String | Required for `token` | Issuer API-token name without username/realm |
| `token_secret` | Secret string | Required for `token` | Issuer API-token secret |
| `proxmox_url` | HTTPS URL | Required | Must end in `/api2/json`; no embedded userinfo/query/fragment |
| `ca_cert_pem` | String | Optional | PEM certificate authorities for Proxmox HTTPS endpoint |
| `insecure_skip_tls_verify` | Boolean | `false` | Legacy TLS bypass; **do not enable** in production |
| `timeout` | Seconds | 120 | API operation timeout, 1–300 seconds |
| `proxy_server` | String | Empty | Underlying API-client proxy configuration; avoid uncontrolled proxies |
| `http_headers` | String | Empty | Additional headers; restrict to trusted operator configuration |

**Credential modes are mutually exclusive.** Configuring a password together with API-token authentication fields is rejected. When changing `auth_method`, the plugin clears the previous mode's credential fields. Existing stored configurations without an `auth_method` field are interpreted as legacy `token` mode for compatibility.

### Password-ticket mode (recommended)

Proxmox authenticates as the **same** dedicated account that owns the short-lived tokens. The plugin obtains a fresh ticket for each create or revoke operation rather than caching potentially expired tickets.

```bash
set +x
read -r -s -p "Restricted Proxmox user password: " ISSUER_PASSWORD
printf '\n'
printf '%s' "$ISSUER_PASSWORD" | vault write proxmox-deploy/config \
  auth_method=password \
  user=deployer realm=pve password=- \
  proxmox_url="https://pve.example.invalid:8006/api2/json" \
  insecure_skip_tls_verify=false timeout=120
unset ISSUER_PASSWORD

vault read proxmox-deploy/config
```

For private TLS, add `ca_cert_pem=@/path/to/trusted-ca.pem` to the `vault write` command. This file is read by the Vault CLI machine and must contain public certificates only.

The PVE user's password is intentionally **not** returned by `vault read`, but remains protected in Vault's storage. An authorized Vault mount operator can replace it, so that operator must be trusted.

### Legacy same-user API-token mode

This mode remains available but **may not** be allowed by Proxmox to create additional tokens for its own user, depending on privileges and API version.

```bash
set +x
read -r -s -p "Same-user token secret: " API_TOKEN_SECRET
printf '\n'
printf '%s' "$API_TOKEN_SECRET" | vault write proxmox-deploy/config \
  auth_method=token \
  user=deployer realm=pve \
  token_id=bootstrap token_secret=- \
  proxmox_url="https://pve.example.invalid:8006/api2/json" \
  insecure_skip_tls_verify=false timeout=120
unset API_TOKEN_SECRET
```

No token issuer configuration permits minting for a different user, regardless of the Proxmox permissions held by the issuer token.

## Role configuration: `<mount>/role/<name>`

A role is a TTL policy tied to the **exact configured mount identity**:

| Field | Type | Default | Behavior |
|---|---|---|---|
| `user` | String | Required | Must equal mount config `user` for issuance |
| `realm` | String | Required | Must equal mount config `realm` for issuance |
| `ttl` | Duration | 30m | Native token expiry and nonrenewable Vault lease duration; minimum 1m |
| `max_ttl` | Duration | 1h | Role validation ceiling, at least `ttl` and no greater than 24h |
| `inherit_user_privileges` | Boolean | `false` | **Must be explicitly true**; acknowledges `privsep=false` inheritance |
| `name` | Path parameter | Required | Vault role name; need not equal Proxmox username |

Examples:

```sh
vault write proxmox-deploy/role/deployer \
  user=deployer realm=pve \
  ttl=30m max_ttl=1h inherit_user_privileges=true

vault write proxmox-images/role/image \
  user=images realm=pve \
  ttl=20m max_ttl=1h inherit_user_privileges=true
```

A role targeting `root@pam` is always rejected. A role targeting another user may exist in old storage, but attempts to read its `creds` path are rejected **before any Proxmox token creation**. Issuer identity matching is exact, not a fuzzy alias.

## Credential responses: `<mount>/creds/<name>`

Each successful `read` issues a new token. Example redacted response:

```text
lease_id:        proxmox-deploy/creds/deployer/<lease>
lease_duration:  1800
lease_renewable: false

data:
  token_id:       <unique-generated-token-name>
  token_id_full:  deployer@pve!<unique-generated-token-name>
  secret:         <one-time-secret>
```

The Proxmox authorization header is:

```text
Authorization: PVEAPIToken=deployer@pve!<unique-generated-token-name>=<one-time-secret>
```

The Vault consumer must capture the **exact lease ID** and revoke it when the token is no longer needed:

```sh
vault lease revoke -sync "<LEASE_ID>"
```

Native Proxmox expiry is a fallback for runner crashes and revocation errors. The Vault lease cannot be renewed; a different credentials read creates a fresh, independently expiring token.

## Vault ACLs and multiple issuer mounts

A normal job needs only read access to the credential role it uses:

```hcl
path "proxmox-deploy/creds/deployer" {
  capabilities = ["read"]
}
```

An independent image job should have:

```hcl
path "proxmox-images/creds/image" {
  capabilities = ["read"]
}
```

Only trusted mount operators should receive config/role management. Neither consumer should receive `sys/*` or issuer config access. Vault ACLs control *who can request a credential*; Proxmox ACLs control *what issued credentials can do*.

Use independent mounts for different target Proxmox users:

```text
proxmox-deploy/config -> password for deployer@pve
proxmox-deploy/role/deployer -> deployer@pve

proxmox-images/config -> password for images@pve
proxmox-images/role/image -> images@pve
```

The current code has one issuer per mount, not per role; a multi-role mount is suitable only when every role maps to **the same** Proxmox account. Do not use the globally privileged issuer workaround.

## Migration and revocation compatibility

Existing mounts without `auth_method` decode as legacy token-auth configurations. They can still **revoke previously issued leases**, including leases with different target-user metadata when the stored issuer retains authority. However, **new cross-user issuance is prohibited**. Follow the [migration guide](deployment.md#migrating-from-the-legacy-cross-user-configuration) before removing any old issuer authority.

If the password is rotated while leases are active, update the mount config promptly and verify revocation still works. Do not delete the mount until all outstanding tokens are revoked or confirmed expired. See [Operations](operations.md#issuer-rotation).

## References

- [Deployment](deployment.md)
- [Security](security.md)
- [Real Proxmox integration tests](real-proxmox-testing.md)
- [Vault policies](https://developer.hashicorp.com/vault/docs/concepts/policies)
- [Proxmox VE user management](https://pve.proxmox.com/pve-docs/pveum.html)
