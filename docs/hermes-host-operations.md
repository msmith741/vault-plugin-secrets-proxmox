# Hermes Host Operations: dynamic Proxmox API credentials

This guide describes integrating a typed, restricted **Hermes Host Operations MCP service** with the Vault Proxmox secrets engine, without embedding a permanent Proxmox API token in Hermes configuration or application secrets.

The plugin **issues Proxmox VE REST API tokens only**. It does **not** issue SSH certificates, grant host shell access or authorize generic Linux host operations. Keep the SSH/key-based host operations transport independent; a Vault SSH CA, if adopted, is a separate secrets/authentication architecture.

## Security model

```text
Hermes agent
  |  typed, read-only operation (e.g., get_proxmox_vm_inventory)
  v
Host Operations MCP service (trusted backend, not the LLM)
  |  short-lived Kubernetes service account JWT
  v
Vault Kubernetes auth -> short-lived Vault service token
  |  policy allows only: proxmox-observer/creds/inventory (read)
  v
Vault Proxmox secrets engine -> Proxmox short-lived API token
  |  issuer password stored in Vault; same Proxmox identity
  v
Proxmox VE API (TLS-verified, ACL-restricted)
  |  query allowed inventory/health endpoints
  v
Host Operations MCP -> allowlisted, sanitized results to Hermes

On completion:
  revoke Vault service token (revoke-self)
    -> Vault revokes associated Proxmox dynamic lease(s)
  native Proxmox expiry remains as crash/network fallback
```

**Important distinction:** "scoped credential" means the **Vault policy selects a credential path** and the **Proxmox account's ACLs restrict its API capabilities**. The plugin currently creates `privsep=false` tokens, which inherit *all privileges of their parent Proxmox user*. It does **not** assign a different Proxmox ACL to each token or each Vault role.

The Proxmox issuer password is a longer-lived credential stored in Vault, not inside the MCP or Hermes application. Thus this design removes the *long-lived Proxmox API token from Hermes*, but it does not eliminate all long-lived secrets.

## 1. Create a restricted Proxmox observer

A Proxmox administrator creates a dedicated non-root PVE-realm identity:

```sh
pveum user add observer@pve --comment "Read-only API inventory consumer"
pveum passwd observer@pve
```

Assign only **read permissions** for the resources this MCP must inspect. Proxmox's built-in `PVEAuditor` can be used only at reviewed ACL paths; assigning it at `/` exposes a broad inventory view. Do not give the observer `PVEUserAdmin`, `User.Modify`, `Permissions.Modify`, `VM.Allocate` or elevated storage/node management rights.

Test the exact API endpoints with the observer's identity. A role name alone is insufficient proof of least privilege; verify effective Proxmox permissions and negative probes for unauthorized nodes, VMs and storage.

## 2. Mount and configure the Vault engine

The plugin must already be checksum-verified, installed and enabled, as described in the [deployment guide](deployment.md). This example uses a **dedicated mount** for the observer identity:

```sh
vault secrets enable -path=proxmox-observer vault-plugin-secrets-proxmox
```

Configure the same-user, password-ticket issuer using a trusted operator shell. Keep issuer passwords out of shell arguments, GitHub secrets, ConfigMaps and Kubernetes manifests.

```bash
set +x
read -r -s -p "Proxmox observer@pve password: " OBSERVER_PASSWORD
printf '\n'
printf '%s' "$OBSERVER_PASSWORD" | vault write proxmox-observer/config \
  auth_method=password user=observer realm=pve \
  password=- \
  proxmox_url="https://pve.example.invalid:8006/api2/json" \
  ca_cert_pem=@/secure/path/to/trusted-proxmox-ca.pem \
  insecure_skip_tls_verify=false timeout=30
unset OBSERVER_PASSWORD
```

Create a short-lived role:

```sh
vault write proxmox-observer/role/inventory \
  user=observer realm=pve \
  ttl=5m max_ttl=10m \
  inherit_user_privileges=true
```

Every read of `proxmox-observer/creds/inventory` **creates a new real Proxmox API token**. A health check must use `vault read proxmox-observer/config` instead of repeatedly reading the credentials endpoint.

## 3. Limit the Vault policy to one credential path

Example `hermes-proxmox-inventory.hcl`:

```hcl
path "proxmox-observer/creds/inventory" {
  capabilities = ["read"]
}
```

Register the policy through an approved Vault operator:

```sh
vault policy write hermes-proxmox-inventory hermes-proxmox-inventory.hcl
```

Do **not** grant the MCP access to `proxmox-observer/config`, other credentials mounts, Vault's plugin catalog, `sys/leases/revoke-prefix`, or a general-purpose Vault root/administrator token.

### Kubernetes service account authentication

Use a **dedicated Kubernetes ServiceAccount** for the MCP backend process, not the general Hermes agent. Configure Vault's [Kubernetes auth method](https://developer.hashicorp.com/vault/docs/auth/kubernetes) once, including its Kubernetes API trust and token-reviewer settings. Then create a narrowly bound Vault role:

```sh
vault write auth/kubernetes/role/hermes-host-operations \
  bound_service_account_names=host-operations-mcp \
  bound_service_account_namespaces=operations \
  audience=vault \
  token_policies=hermes-proxmox-inventory \
  token_ttl=10m token_max_ttl=10m \
  token_type=service
```

The example namespace, service account and audience are placeholders. Ensure the pod's projected JWT `aud` matches the configured Vault role and that the JWT is scoped to the intended workload.

For a Kubernetes deployment, mount a bounded-audience service-account token into **only the MCP container**. A sample pod-spec fragment:

```yaml
spec:
  serviceAccountName: host-operations-mcp
  automountServiceAccountToken: false
  containers:
    - name: host-operations-mcp
      volumeMounts:
        - name: vault-service-account-token
          mountPath: /var/run/secrets/vault
          readOnly: true
  volumes:
    - name: vault-service-account-token
      projected:
        sources:
          - serviceAccountToken:
              path: token
              audience: vault
              expirationSeconds: 600
```

Set Vault TLS trust through the workload's approved CA bundle and authenticate using the Kubernetes JWT at `POST /v1/auth/kubernetes/login`. The Vault response yields a **short-lived Vault service token**; never present it to Hermes or another MCP consumer.

## 4. Implement the MCP credential lifecycle

The credential broker belongs **inside the trusted Host Operations MCP server**. The agent sees only typed operations and sanitized results.

1. Check the tool is on the static allowlist (for example `get_proxmox_host_health` or `list_proxmox_vms`) and that the caller is authorized for it. Reject arbitrary hostnames, raw URL paths, shell commands and mutations.
2. Authenticate to Vault using the mounted projected service-account JWT. Use a **fresh Vault service token per operation or isolated request group** to avoid revoking unrelated concurrent operations.
3. Read `/v1/proxmox-observer/creds/inventory` with the Vault token, capture `lease_id`, `data.token_id_full` and `data.secret` **in protected process memory only**.
4. Send an authorized Proxmox request using the verified Proxmox HTTPS endpoint and header `Authorization: PVEAPIToken=<token_id_full>=<secret>`.
5. Normalize the API response to an allowlisted typed schema. Redact credentials, tickets, API configuration values, environment variables, raw headers and sensitive host data. Avoid sending unfiltered Proxmox API JSON back to an LLM.
6. On completion, failure or cancellation, ask Vault to revoke the ephemeral **Vault service token itself** using `POST /v1/auth/token/revoke-self`. Vault will revoke its associated dynamic leases. A single service token must not be shared across independent operations if they can complete at different times.
7. If revocation cannot be confirmed, record a **sanitized** alarm and rely on the finite native Proxmox token expiration as a fallback. Never describe a failed cleanup as a successful revoke.

The exact Vault `lease_id` is useful for authorized operator troubleshooting, but is not an API secret to expose in normal MCP outputs. A general MCP policy does **not** need permission to revoke arbitrary leases through `sys/leases/revoke` or `sys/leases/revoke-prefix`. Revoke-self provides a narrower cleanup path when each operation uses its own service token.

### Typed operation interface example

```text
get_proxmox_host_health(host_id) -> {
  host_id: string,
  online: boolean,
  cpu_percent: number,
  memory_used_bytes: integer,
  memory_total_bytes: integer
}

list_proxmox_vms(host_id, limit, cursor) -> {
  items: [{ vm_id, name, status, node }],
  next_cursor: string | null
}
```

These are **interface examples**, not implemented tool names or an assertion that the separate Hermes MCP already has these exact methods. Enforce bounded pagination, output size, timeouts, caller authentication, per-tool authorization and audit correlation. Do not add a generic `execute_command`, unrestricted Proxmox REST proxy, or exposed token/secret-fetching MCP method.

## 5. Operational limits and observability

- Configure reasonable Vault request/issuance rate limits to avoid creating excessive Proxmox tokens. Every successful credential read mutates Proxmox state.
- Keep the Proxmox token TTL slightly above the expected single-operation duration, but no longer than necessary; obtain a new token for longer workflows rather than renewing existing ones.
- Use the shortest viable Kubernetes projected JWT and Vault token lifetime; the **Proxmox lease is nonrenewable**.
- Ensure host-operations application crash handling attempts token cleanup; native expiration covers abnormal terminations.
- Log operation name, caller identity, target resource, status, latency, Vault mount/role and a redacted correlation ID. Never log API token secrets, Proxmox issuer passwords or Vault service tokens.
- Monitor unexpected token issuance, 401/403 failures, orphan tokens, repeated revocation failures, suspicious Vault role reads and Proxmox ACL changes.
- Treat compromise of the MCP Kubernetes ServiceAccount as compromise of access to the credential-issuing Vault policy until identity and sessions are revoked.
- Separate read-only inventory capability from any later mutation/deployment capability by **different** Proxmox accounts, Vault mounts, Vault auth roles and MCP tool allowlists.

## 6. Real-environment acceptance criteria

Before a production Hermes integration, demonstrate on the **actual** target Proxmox and Vault installations:

- Vault Kubernetes auth grants only `proxmox-observer/creds/inventory` to the intended MCP ServiceAccount.
- Other pods/service accounts cannot authenticate as this role; the LLM agent cannot fetch Vault or Proxmox secrets.
- The issued token's effective Proxmox ACL is read-only and does not cover unauthorized resources.
- The issued token cannot create sibling tokens, users, ACLs, VMs or modified snapshots.
- The token is removed after a successful request; it is unusable after explicit revoke or native expiry.
- Failure and cancellation cleanup work, including Vault/Proxmox temporary outages.
- Proxmox and Vault audit trails contain no raw secrets; policy revocation and account disablement block further issuance.
- The Hermes tool does **not** turn the Proxmox API token into an SSH identity. Host operations through SSH continue to use their independently restricted SSH key or SSH CA design.

This integration is an excellent fit for short-lived **Proxmox API credentials**, but it is not a replacement for the separate host SSH transport. See the [security review](audits/2026-11-07-security-review.md) for production gates.
