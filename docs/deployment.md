# Deployment guide: same-user issuer model

This is the generic end-to-end setup for the Vault Proxmox secrets-engine plugin. The supported design issues temporary tokens **only for the same Proxmox account authenticated by the mount**. Cross-user issuance is blocked by the plugin even when the configured issuer has broad Proxmox privileges.

**Do not use the legacy pattern of one `root@pam` or global `PVEUserAdmin` issuer creating API tokens for arbitrary user accounts.** The [real Proxmox test](real-proxmox-testing.md) verified that broad access can mint valid `root@pam` credentials.

## 1. Prerequisites

- A supported, initialized, unsealed Vault cluster with a working TLS endpoint, admin access, and Vault CLI.
- One or more Proxmox VE nodes with the HTTPS API on port 8006.
- Ability to create **dedicated PVE-realm accounts**, assign narrowly scoped roles and set their passwords through an authorized Proxmox administrator.
- Network reachability from the Vault plugin process to the intended Proxmox API, and certificate trust for its hostname.
- A trusted build host with Go meeting `go.mod` requirements (CI currently uses Go 1.27.3) and a Vault-compatible Linux/AMD64 runtime; adjust architecture if needed.
- A genuine plugin directory on each Vault server that may execute the plugin.

Examples below use `deployer@pve`, `images@pve`, `vault.example.invalid` and `pve.example.invalid`. Replace them with your own authorized values.

## 2. Create dedicated Proxmox accounts

Use a Proxmox administrator to create two accounts that represent **different capabilities**:

```sh
pveum user add deployer@pve --comment "Automated VM deployment"
pveum user add images@pve --comment "Automated image management"
```

Set each password using the interactive prompt:

```sh
pveum passwd deployer@pve
pveum passwd images@pve
```

Prefer different, randomly generated passwords stored in an approved secrets workflow. **Do not reuse administrative passwords.** No privileged, cross-user API token is needed by this design.

Assign **only** the Proxmox privileges required by each account. For example, a deployment identity should receive access to explicitly approved VM IDs/pools/storage, while an image identity should be limited to its approved template and storage operations. The exact ACLs depend on the task and Proxmox version; review them independently rather than copying a blanket Administrator role.

Proxmox API tokens created by this plugin have `privsep=false`. They inherit the permissions of their **corresponding account**. Verify that the accounts cannot administer users, ACLs, other VMs, unauthorized storage, or host security settings.

**Key boundary:** The issuer password for `deployer@pve` can obtain only `deployer@pve` tokens through this plugin. The `images@pve` mount needs an independent password and mount.

## 3. Compile the external plugin

Build from a reviewed commit or signed release:

```sh
git clone <REPOSITORY_URL>
cd vault-plugin-secrets-proxmox

go mod verify
go mod tidy -diff
go test ./...
go test -race ./...
go vet ./...

mkdir -p dist
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath \
  -o dist/vault-plugin-secrets-proxmox \
  ./cmd/vault-plugin-secrets-proxmox
sha256sum dist/vault-plugin-secrets-proxmox
```

The build architecture must match the Vault host. Record the exact binary and checksum and avoid reusing the same version number for different binaries.

## 4. Install on Vault servers

Add or preserve the following in the Vault server's existing configuration. **Do not replace storage, TLS listener, seal, or cluster settings wholesale.**

```hcl
# Fragment only; not a complete Vault server configuration.
api_addr         = "https://vault.example.invalid:8200"
plugin_directory = "/opt/vault/plugins"
```

Provision the directory and copy the reviewed binary to **every** Vault node that can execute plugins:

```sh
sudo install -d -o root -g vault -m 0750 /opt/vault/plugins
sudo install -o root -g vault -m 0750 \
  ./vault-plugin-secrets-proxmox \
  /opt/vault/plugins/vault-plugin-secrets-proxmox
sudo sha256sum /opt/vault/plugins/vault-plugin-secrets-proxmox
```

Adjust the group if the Vault service runs under a different identity. Apply Vault configuration through your normal change management and rolling restart procedures. Confirm Vault is healthy afterward.

## 5. Register and enable the engine

Use an authenticated Vault administrator CLI, and verify the plugin checksum on the **Vault server**, not just on your workstation:

```sh
export VAULT_ADDR="https://vault.example.invalid:8200"
vault status

PLUGIN_SHA="$(sha256sum /opt/vault/plugins/vault-plugin-secrets-proxmox | awk '{print $1}')"
PLUGIN_VERSION="v0.1.0" # example label, use the actual reviewed build

vault plugin register \
  -sha256="$PLUGIN_SHA" \
  -command=vault-plugin-secrets-proxmox \
  -version="$PLUGIN_VERSION" \
  secret vault-plugin-secrets-proxmox

vault plugin info -type=secret vault-plugin-secrets-proxmox

vault secrets enable -path=proxmox-deploy \
  -plugin-version="$PLUGIN_VERSION" vault-plugin-secrets-proxmox
vault secrets enable -path=proxmox-images \
  -plugin-version="$PLUGIN_VERSION" vault-plugin-secrets-proxmox

vault secrets tune -default-lease-ttl=30m \
  -max-lease-ttl=24h proxmox-deploy/
vault secrets tune -default-lease-ttl=30m \
  -max-lease-ttl=24h proxmox-images/
```

If administering Vault from a different machine, securely supply the verified installed binary SHA rather than running `sha256sum` on a path that exists only on the server.

Each mount has independent issuer configuration, roles, Vault ACL paths, and leases. Register the shared plugin binary once per Vault cluster.

## 6. Configure per-user password authentication

Use `auth_method=password` to let the dedicated Proxmox user authenticate with a short-lived ticket for each token create/delete operation. Vault stores the issuer password; it is **not** returned to a credential consumer or by `vault read config`.

From a trusted Bash shell with logging/xtrace disabled:

```bash
set +x
read -r -s -p "Proxmox deployer@pve password: " DEPLOY_PASSWORD
printf '\n'

printf '%s' "$DEPLOY_PASSWORD" | vault write proxmox-deploy/config \
  auth_method=password \
  user=deployer realm=pve \
  password=- \
  proxmox_url="https://pve.example.invalid:8006/api2/json" \
  insecure_skip_tls_verify=false \
  timeout=120

unset DEPLOY_PASSWORD
vault read proxmox-deploy/config
```

Repeat independently for `images@pve`:

```bash
set +x
read -r -s -p "Proxmox images@pve password: " IMAGE_PASSWORD
printf '\n'

printf '%s' "$IMAGE_PASSWORD" | vault write proxmox-images/config \
  auth_method=password \
  user=images realm=pve \
  password=- \
  proxmox_url="https://pve.example.invalid:8006/api2/json" \
  insecure_skip_tls_verify=false \
  timeout=120

unset IMAGE_PASSWORD
vault read proxmox-images/config
```

For an internally issued TLS certificate, add `ca_cert_pem=@/secure/path/to/pve-ca-chain.pem` to **each** configuration command. The file must be accessible to the **Vault CLI machine** and contain trusted PEM certificates only. Prefer a verified certificate chain and matching hostname; do not bypass TLS verification.

### Legacy token authentication

`auth_method=token` is still supported for **same-user** credentials:

```bash
read -r -s -p "Same-user issuer token secret: " ISSUER_TOKEN_SECRET
printf '\n'
printf '%s' "$ISSUER_TOKEN_SECRET" | vault write proxmox-deploy/config \
  auth_method=token user=deployer realm=pve \
  token_id=bootstrap token_secret=- \
  proxmox_url="https://pve.example.invalid:8006/api2/json" \
  insecure_skip_tls_verify=false timeout=120
unset ISSUER_TOKEN_SECRET
```

Token-authenticated issuers might **not** be authorized by Proxmox to generate their own tokens. This is why password-ticket authentication is the recommended, tested path. Never grant broad `PVEUserAdmin` rights to make cross-user creation succeed. A password and API-token issuer credential cannot be combined in one mount.

## 7. Configure roles

The role identity **must match** the issuer user/realm configured on the same mount:

```sh
vault write proxmox-deploy/role/deployer \
  user=deployer realm=pve \
  ttl=30m max_ttl=1h \
  inherit_user_privileges=true

vault write proxmox-images/role/image \
  user=images realm=pve \
  ttl=20m max_ttl=1h \
  inherit_user_privileges=true

vault read proxmox-deploy/role/deployer
vault read proxmox-images/role/image
```

A role may have a different **Vault role name**, but it cannot target a different **Proxmox identity**. Issuance rejects such requests before any Proxmox API operation. Roles for `root@pam` are prohibited. The `inherit_user_privileges` acknowledgement remains mandatory.

Lifetime rules: minimum 1 minute, default 30 minutes, nonrenewable, and maximum configured TTL no greater than 24 hours. The native Proxmox expiration is set when the token is created and does not extend if the Vault lease is adjusted.

## 8. Configure Vault consumer policies

Grant workload identities **only** their own credential read path:

```hcl
# Example deploy consumer policy
path "proxmox-deploy/creds/deployer" {
  capabilities = ["read"]
}
```

And a separate policy for image jobs:

```hcl
path "proxmox-images/creds/image" {
  capabilities = ["read"]
}
```

Install these as reviewed Vault policies and bind them to an approved Vault auth method (for example, Kubernetes, AppRole or JWT/OIDC auth). A policy alone does not log a workload in. Do not grant consumers `config`, `role/*`, `sys/plugins/*` or another mount's credential path.

The supplied [consumer-policy example](examples/consumer-policy.hcl) uses a generic mount and should be adjusted to your actual mount and role.

## 9. Issue, use and revoke credentials

After testing against an isolated Proxmox environment, an authorized caller requests:

```sh
vault read proxmox-deploy/creds/deployer
```

Every read **creates** a real Proxmox token. Capture the exact `lease_id` and construct an API credential from the returned `data.token_id_full` and `data.secret`, for example:

```text
PROXMOX_VE_API_TOKEN=<user>@<realm>!<token_name>=<secret>
```

Do not print, commit or persist this secret. An automation runner should remove the credential from its process environment after use, and attempt revocation on failure or cancellation:

```sh
vault lease revoke -sync "<LEASE_ID_FROM_RESPONSE>"
```

A process crash can skip cleanup, so the token also receives a finite native Proxmox expiration.

## 10. Verify the deployed engine

Using disposable credentials and only after ACL review:

1. `vault plugin info` and `vault secrets list -detailed` report the registered plugin and both expected mounts.
2. `vault read <mount>/config` reports the expected issuer and `auth_method=password`, **without** returning passwords or token secrets.
3. Each role uses the same user/realm as its mount's issuer.
4. A cross-user role's `creds` read fails without creating a token.
5. Generated tokens show the target user, finite expiration and `privsep=false`; their real effective permissions match only the assigned restricted account.
6. An issued token cannot create a new API token, alter ACLs, or access the other account's operations.
7. Vault lease revocation deletes its token; native expiration denies authentication even if Vault is unreachable.
8. Rotating a role or changing a role's target does not redirect revocation of an already-issued token.
9. Both password issuer mounts can still revoke after a Vault process restart.

For automated evidence, see [Real Proxmox integration testing](real-proxmox-testing.md). A passing CI suite is not a substitute for validating the exact Proxmox version and ACLs used in production.

## Migrating from the legacy cross-user configuration

Older versions allowed one token issuer to create credentials for other Proxmox users. **That issuance mode is now disabled.** Existing cross-user roles may still exist in Vault storage, but reading their credential path fails immediately. Existing leases retain immutable target user/realm metadata and can still be revoked using the configured issuer, subject to its permissions.

Safe migration procedure:

1. Pause consumers and stop creation of new credentials.
2. Inventory and revoke all outstanding leases that depend on the old cross-user issuer; independently verify deletion or expiration in Proxmox.
3. Create dedicated restricted PVE-realm users, one for each required workload category; set unique passwords.
4. Enable separate mounts and configure `auth_method=password` for each **same-user** identity.
5. Create matching roles and update Vault consumer policies to their new paths.
6. Test issuance, permissions, native expiry and lease revocation on disposable resources.
7. Remove the old mount and overprivileged issuer **only after** old leases are resolved and the rollback plan is approved.

**Do not switch the old shared issuer to an unprivileged account while its leases remain outstanding**, because that can prevent revocation of tokens created for other accounts. Rollback must not silently re-enable cross-user issuance.

## Further information

- [Configuration/API reference](configuration.md)
- [Security model and acceptance checklist](security.md)
- [Operations, upgrades and recovery](operations.md)
- [Real Proxmox integration tests](real-proxmox-testing.md)
- [Official Proxmox user management](https://pve.proxmox.com/pve-docs/pveum.html)
- [Vault plugin registration](https://developer.hashicorp.com/vault/docs/plugins/register)
