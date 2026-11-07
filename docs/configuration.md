# Configuration and API reference

This is a reference for the plugin **as currently implemented**. All paths below are relative to a Vault mount named `proxmox/`. If the engine is enabled at another path, replace that prefix. There is no automatic registration of Proxmox roles, accounts or ACLs.

> [!WARNING]
> The `proxmox/config` endpoint contains an issuer credential, and `proxmox/creds/*` responses contain newly generated credentials. Treat both paths as sensitive. Issued tokens currently inherit **all** rights of their Proxmox user.

## Vault endpoint table

| Method / Vault CLI | Path | Description |
|---|---|---|
| `vault write` | `proxmox/config` | Create or update the mount's issuer API settings |
| `vault read` | `proxmox/config` | Read non-sensitive config fields; token secret omitted |
| `vault delete` | `proxmox/config` | Delete issuer settings; active lease revocation can break |
| `vault write` | `proxmox/role/<name>` | Create or update a role |
| `vault read` | `proxmox/role/<name>` | Inspect role mapping and lifetime |
| `vault delete` | `proxmox/role/<name>` | Delete role (affects future issuance) |
| `vault list` | `proxmox/role` | List role names |
| `vault read` | `proxmox/creds/<name>` | **Create a new token** and return its Vault lease |
| `vault lease revoke` | `<lease_id>` | Revoke the Vault lease and call Proxmox token deletion |

These are plugin-specific paths. Vault's system endpoints manage the **catalog** (`sys/plugins/catalog`), **mount** (`sys/mounts`), **ACLs** and **leases**. Do not grant these broad system capabilities to ordinary credential consumers.

## Issuer configuration: `proxmox/config`

Exactly **one issuer configuration** exists per mount. Every role at that mount uses the configured Proxmox issuer credential to create and delete target tokens.

| Field | Type | Required | Description |
|---|---|---|---|
| `user` | String | Yes | Issuer account name, without realm |
| `realm` | String | Yes | Issuer's Proxmox authentication realm |
| `token_id` | String | Yes | Issuer's API token name, without `user@realm!` prefix |
| `token_secret` | String | Yes | **Secret** value returned once at Proxmox token creation |
| `proxmox_url` | HTTPS URL | Yes | Exact `https://<host>:8006/api2/json` endpoint |
| `insecure_skip_tls_verify` | Boolean | No; default false | **Unsafe** legacy bypass; do not enable in production |
| `ca_cert_pem` | String | No | PEM-encoded CA certificates for private TLS trust |
| `timeout` | Integer seconds | No; default 120 | API client operation timeout, permitted 1–300 seconds |
| `http_headers` | String | No | Extra HTTP headers accepted by underlying Proxmox client |
| `proxy_server` | String | No | HTTP proxy passed to underlying client; restrict use |

The URL must be HTTPS, have a hostname, use path `/api2/json` and contain no userinfo, query string or fragment. Valid PEM is required when `ca_cert_pem` is set. On read, `token_secret` and `ca_cert_pem` are not returned.

### Example: secure issuer entry

```bash
set +x
read -r -s -p "Issuer token secret: " ISSUER_TOKEN_SECRET
printf '\n'

printf '%s' "$ISSUER_TOKEN_SECRET" | vault write proxmox/config \
  user="issuer" realm="pve" token_id="vault-bootstrap" \
  token_secret=- \
  proxmox_url="https://pve.example.invalid:8006/api2/json" \
  insecure_skip_tls_verify=false \
  timeout=120 \
  ca_cert_pem=@/secure/path/pve-ca.pem

unset ISSUER_TOKEN_SECRET

vault read proxmox/config
```

`token_secret=-` reads only that field from stdin; `ca_cert_pem=@...` reads the local file. Never include a real bootstrap token in a script, command-line argument, Git repository or log. The CA bundle must contain certificates only, not a private key.

### Caution: issuer rotation

Replacing or deleting `proxmox/config` affects future revocation calls as well as issuance. The lease records the target token's username, realm and ID, but does **not** pin the issuer credential used to create it. Keep enough revocation authority available for all outstanding leases until expiry and independently verify cleanup. See [Operations](operations.md#issuer-rotation).

## Role configuration: `proxmox/role/<name>`

A role is **a named Proxmox target user plus a lifetime policy**. It is not a Proxmox ACL; it does not grant permissions or create users.

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | Path segment | Yes | Vault role name; used in `creds/<name>` |
| `user` | String | Yes | Target Proxmox account name |
| `realm` | String | Yes | Target Proxmox realm |
| `ttl` | Duration | No; defaults to 30m | Native token lifetime and requested Vault lease TTL; minimum 1m |
| `max_ttl` | Duration | No; defaults to 1h | Validation limit; must be at least `ttl` and at most 24h |
| `inherit_user_privileges` | Boolean | Yes; must be true | Explicit acknowledgement that generated token uses `privsep=false` |

Rules:

- `ttl` must be finite and at least one minute, no more than `max_ttl`.
- `max_ttl` must be finite, at least `ttl` and no more than 24 hours.
- A role targeting `root@pam` is rejected.
- Roles without explicit acknowledgement are refused; older stored role definitions may require updating before issuance.
- Issued leases are **not renewable**; changing `max_ttl` does not renew or extend an existing lease.
- Updating a role affects **new** token requests. Current leases store the target user and realm from issuance; older upstream leases may still depend on a role existing during revoke.

### Example

```sh
vault write proxmox/role/build-agent \
  user="build-agent" realm="pve" \
  ttl=20m max_ttl=1h \
  inherit_user_privileges=true

vault read proxmox/role/build-agent
vault list proxmox/role
```

## Credentials: `proxmox/creds/<name>`

Every successful **read** creates a new target Proxmox API token. There is no API for requesting an arbitrary target user, token ID, expiration timestamp or extra permissions during credential issuance; those come from the Vault role and issuer's Proxmox permissions.

Example response, with the secret redacted:

```text
Key                 Value
---                 -----
lease_id            proxmox/creds/build-agent/<unique-lease>
lease_duration      1200
lease_renewable     false

data:
  token_id:          <generated-token-name>
  token_id_full:     build-agent@pve!<generated-token-name>
  secret:            <generated-secret>
```

Only the initial Vault response contains the new Proxmox token secret. To authenticate to Proxmox, use:

```text
Authorization: PVEAPIToken=build-agent@pve!<generated-token-name>=<generated-secret>
```

For OpenTofu providers that accept the Telmate/BPG-style combined token format:

```text
PROXMOX_VE_API_TOKEN=build-agent@pve!<generated-token-name>=<generated-secret>
```

Provider environment variable names may vary; consult the exact provider you use.

### Lease guarantees and limits

Vault returns a lease ID and `lease_renewable=false`. When the lease is explicitly revoked or reaches its lifetime, Vault invokes the plugin's revoke callback to delete the target token. The generated token also has a native Proxmox expiration timestamp, rounded up to whole-second precision, as a fallback when Vault cannot revoke immediately.

A short token expiration **does not prevent self-minting** if the target account has sufficient user-management permissions. This remains a required acceptance test.

### Example: request and revoke without printing the secret

```bash
set +x
response="$(vault read -format=json proxmox/creds/build-agent)" || exit 1
lease_id="$(jq -r '.lease_id' <<<"$response")"
echo "Lease created: $lease_id"
unset response

vault lease lookup "$lease_id"
vault lease revoke "$lease_id"
unset lease_id
```

This example discards the Proxmox secret after issuing it; use a properly secured consumer to work with the full response.

## Vault ACL policies

One **consumer** should have only read permission on its specific role:

```hcl
path "proxmox/creds/build-agent" {
  capabilities = ["read"]
}
```

Store it as `docs/examples/consumer-policy.hcl` and install it using:

```sh
vault policy write proxmox-build-agent docs/examples/consumer-policy.hcl
```

A **mount operator** needs separate scoped permissions to manage `config` and `role/`. Use [operator-policy.hcl](examples/operator-policy.hcl) only after reviewing whether that operator should possess issuer-management authority. Token issuance is never part of the operator policy unless explicitly granted.

Catalog registration, mount lifecycle, version pinning and lease administration use Vault's separate system policies. Never grant `sys/*` to a workload simply to let it read a credential.

## Multiple issuer identities

A single mount has one issuer. Different roles can target different users, but the **same issuer** must have the required token-management permissions for them all. To reduce this authority, use two mounts of the **same registered plugin**:

```sh
vault secrets enable -path=proxmox-build vault-plugin-secrets-proxmox
vault secrets enable -path=proxmox-deploy vault-plugin-secrets-proxmox
```

Configure each independently:

```text
proxmox-build/config   -> issuer-build@pve token
proxmox-build/role/... -> restricted build identity

proxmox-deploy/config  -> issuer-deploy@pve token
proxmox-deploy/role/... -> restricted deploy identity
```

For each mount, separately configure issuer credentials, target Proxmox permissions, Vault ACL policies, TTL settings and monitoring. Prefer version-pinned plugin mounts as illustrated in [Deployment](deployment.md#6-enable-and-tune-the-secrets-engine).

### Proxmox identity is separate from Vault identity

Vault authentication and policies decide **who may ask Vault for a token**. Proxmox user ACLs decide **what the token can do once issued**. Neither layer substitutes for the other.

## References

- [Vault ACL policies](https://developer.hashicorp.com/vault/docs/concepts/policies)
- [Vault leases](https://developer.hashicorp.com/vault/docs/concepts/lease)
- [Proxmox VE user management](https://pve.proxmox.com/pve-docs/pveum.html)
