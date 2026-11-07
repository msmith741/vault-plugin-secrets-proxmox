# Deployment guide

This guide describes a **complete, generic deployment** of the Vault Proxmox secrets engine: Proxmox identities, plugin compilation, Vault installation, initial configuration, role and policy creation, credential retrieval, lease revocation, and validation.

> [!IMPORTANT]
> **Security acceptance required.** The software has passed automated and synthetic tests, not the required privilege-delegation and self-mint tests against a real Proxmox installation. Complete [Security — pre-production acceptance](security.md#pre-production-acceptance-checklist) using disposable accounts before allowing privileged production workloads.

## 1. Deployment model and prerequisites

The plugin runs **inside Vault's external plugin process architecture**, not as an independent web server.

Requirements:

- A supported, already initialized and unsealed Vault server/cluster with administrative access, an authenticated Vault CLI, and a working `api_addr`.
- A configured `plugin_directory` on **each** Vault node that may run the plugin. This must be a real directory, not a symlink.
- A reachable Proxmox VE API endpoint using HTTPS and a certificate chain/hostname the Vault host can verify. Proxmox normally exposes its API on TCP 8006.
- An authorized Proxmox administrator to create and audit dedicated issuer and target users/tokens; do not use the Vault root token for routine consumers.
- Go compatible with `go.mod` (currently Go 1.26.2 or newer; CI tests on Go 1.27.3), build tools, and `sha256sum`.
- Target Linux OS/CPU architecture appropriate for the Vault nodes (the supplied GoReleaser configuration builds `linux/amd64`).
- Vault API access, plus privileges to register a plugin, enable secrets engines and manage policies.
- `jq` is optional but useful for safe validation of JSON responses.

Example variable values used below:

| Name | Example | Meaning |
|---|---|---|
| Vault address | `https://vault.example.invalid:8200` | Already-deployed Vault API |
| Proxmox endpoint | `https://pve.example.invalid:8006/api2/json` | Proxmox API, including suffix |
| Plugin name | `vault-plugin-secrets-proxmox` | Binary and catalog name |
| Mount | `proxmox/` | Vault API path; customizable |
| Issuer account | `vault-issuer@pve` | Proxmox identity able to manage tokens for a selected target |
| Issuer token ID | `vault-issuer` | Pre-existing Proxmox token belonging to issuer |
| Target account | `workload@pve` | User whose rights the temporary token inherits |
| Version | `v0.1.0` | **Illustrative version label**; use the exact version of a tested build |

Do not substitute example addresses or identities verbatim in a real deployment.

## 2. Prepare restricted Proxmox identities

As an authorized Proxmox administrator, create **two different users**: an issuer that performs token lifecycle actions and a target account whose temporary tokens perform a workload.

Example user creation from a privileged Proxmox shell:

```sh
pveum user add vault-issuer@pve --comment "Vault dynamic-token issuer"
pveum user add workload@pve --comment "Restricted automated workload"
```

Create a bootstrap token for the issuer:

```sh
pveum user token add vault-issuer@pve vault-issuer --privsep 1
```

Record its one-time secret directly in a secure credential handoff. Never commit it to source control or print it in CI logs. A privilege-separated issuer token requires explicit, appropriate Proxmox ACLs in addition to its parent user's rights.

**There is deliberately no copy-and-paste broad ACL grant in this guide.** The Proxmox permission model for creating/deleting another user's API token must be validated for the installed Proxmox version. Grant only the minimum permissions proven necessary and only on the intended target. If cross-user creation requires excessive privileges, stop and redesign the issuer boundary; do not solve an HTTP 403 by granting blanket administration.

Give the target account only the narrowly scoped privileges necessary for its workload. Generated tokens use `privsep=false` and inherit **all** target-user permissions. Confirm the target **cannot create or modify other API tokens or ACLs**. Native expiry does not prevent an authorized identity from generating a replacement credential.

For separate workload categories, create separate issuers, targets and Vault mounts. See [Configuration — multiple mounts](configuration.md#multiple-issuer-identities).

## 3. Build and verify the plugin

On a trusted build host, check out an audited commit or signed release tag:

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
  go build -trimpath -o dist/vault-plugin-secrets-proxmox \
  ./cmd/vault-plugin-secrets-proxmox
sha256sum dist/vault-plugin-secrets-proxmox
```

Choose `GOOS` and `GOARCH` for the Vault hosts. The binary must be compiled using a toolchain compatible with the pinned Go module requirements. Review the binary's release provenance and checksum before deployment. Successful compilation alone is not a guarantee of Vault server compatibility.

## 4. Configure the Vault server

Add the following settings to the existing Vault server configuration, **preserving all existing listeners, storage, sealing and TLS settings**:

```hcl
# Vault server configuration fragment, not a complete vault.hcl
api_addr         = "https://vault.example.invalid:8200"
plugin_directory = "/opt/vault/plugins"
```

On every node, create the real directory and give the Vault service account **read/execute** access without permitting the service to modify the plugin binary:

```sh
sudo install -d -o root -g vault -m 0750 /opt/vault/plugins
```

If the service account/group is not named `vault`, adjust it accordingly. Apply the server configuration through your normal change-management process and use a planned restart/rolling restart as required. Do not restart all HA nodes simultaneously. Verify Vault health after changing its configuration.

Vault requires the same plugin artifact on every node that might execute the plugin; Raft snapshots do **not** back up the external binary.

## 5. Install, checksum and register the plugin

Copy the trusted `linux/amd64` binary to each Vault host, then, on each host, install it:

```sh
sudo install -o root -g vault -m 0750 \
  ./vault-plugin-secrets-proxmox \
  /opt/vault/plugins/vault-plugin-secrets-proxmox
sudo sha256sum /opt/vault/plugins/vault-plugin-secrets-proxmox
```

The source on the left is an example staged artifact copied to that host. Confirm that the checksum is identical on **all** Vault nodes and matches the reviewed release.

From an administrator's Vault CLI session:

```sh
export VAULT_ADDR="https://vault.example.invalid:8200"
# Authenticate with an approved Vault administrative method.
vault status

PLUGIN_SHA="$(sha256sum /opt/vault/plugins/vault-plugin-secrets-proxmox | awk '{print $1}')"
PLUGIN_VERSION="v0.1.0"   # example: use the approved build's actual version

vault plugin register \
  -sha256="$PLUGIN_SHA" \
  -command="vault-plugin-secrets-proxmox" \
  -version="$PLUGIN_VERSION" \
  secret vault-plugin-secrets-proxmox

vault plugin info -type=secret vault-plugin-secrets-proxmox
```

**Important:** The `sha256sum` command above assumes the Vault CLI is executed **on the Vault host** with the installed artifact. If running the CLI remotely, obtain the verified SHA through a secure administrator workflow; `vault plugin register` sends the checksum to Vault and checks the server-side artifact.

Register once per Vault cluster, not on every server. Vault propagates its catalog, not the plugin binary.

## 6. Enable and tune the secrets engine

```sh
vault secrets enable \
  -path=proxmox \
  -plugin-version="$PLUGIN_VERSION" \
  vault-plugin-secrets-proxmox

vault secrets tune -default-lease-ttl=30m -max-lease-ttl=24h proxmox/
vault secrets list -detailed
```

The plugin generates nonrenewable leases. Role `ttl` determines the native Proxmox expiry, so choose a Vault mount maximum TTL that does not unexpectedly truncate the intended role TTL. A role's `max_ttl` is a validation ceiling; it does not enable lease renewal.

## 7. Configure the running mount

The issuer configuration lives at `proxmox/config` and is **independent** of a workload role. Before writing, verify the Proxmox API hostname and HTTPS CA chain.

From a trusted Bash session authenticated to Vault, enter the bootstrap token secret **without putting it in command history**:

```bash
set +x
read -r -s -p "Proxmox issuer token secret: " ISSUER_SECRET
printf '\n'

printf '%s' "$ISSUER_SECRET" | vault write proxmox/config \
  user="vault-issuer" \
  realm="pve" \
  token_id="vault-issuer" \
  token_secret=- \
  proxmox_url="https://pve.example.invalid:8006/api2/json" \
  insecure_skip_tls_verify=false \
  timeout=120

unset ISSUER_SECRET
```

For a Proxmox endpoint signed by a **private CA**, add `ca_cert_pem=@/path/to/ca-chain.pem` to the `vault write` invocation. The `@` file is read **on the machine running the Vault CLI**. Use the actual PEM root/intermediate CA certificate, not a token or private key. Keep `insecure_skip_tls_verify=false`.

The command accepts fields via stdin (`token_secret=-`), and Vault stores the issuer credential in the engine's protected storage. The `vault read proxmox/config` response omits the issuer token secret by design.

Verify only non-sensitive settings:

```sh
vault read proxmox/config
```

Do not grant workload callers `read`/`update` on `proxmox/config`. Administrative policy and authentication methods should be configured separately.

## 8. Define a workload role

Create a Vault role that maps to an existing restricted Proxmox user:

```sh
vault write proxmox/role/workload \
  user="workload" \
  realm="pve" \
  ttl="30m" \
  max_ttl="1h" \
  inherit_user_privileges=true

vault read proxmox/role/workload
vault list proxmox/role
```

The acknowledgement is mandatory because the generated Proxmox token inherits all rights of `workload@pve`. A role targeting `root@pam` is refused. The intended role is **not a Vault identity or permission policy**; it only tells the plugin which Proxmox identity to use.

## 9. Assign a consumer policy and authenticate the caller

Install the included example read-only consumer policy:

```sh
vault policy write proxmox-workload docs/examples/consumer-policy.hcl
vault policy read proxmox-workload
```

Then attach the policy to an approved Vault authentication role (for example a workload identity, Kubernetes auth role, AppRole or OIDC/JWT role) using that authentication method's documented commands. A policy alone does not log in or grant access to a workload. Never give a consumer the plugin configuration or role-administration capabilities.

See [Configuration — ACLs](configuration.md#vault-acl-policies) for separate operator and multi-mount policies.

## 10. Request, verify and revoke credentials

**Reading `creds/workload` creates an actual Proxmox token.** Execute this first on a disposable/sandbox Proxmox instance and only after the authorization tests in the security checklist.

Example Bash session that avoids printing the token secret:

```bash
set +x
umask 077

credential_json="$(vault read -format=json proxmox/creds/workload)" || exit 1
lease_id="$(jq -r '.lease_id' <<<"$credential_json")"
token_id_full="$(jq -r '.data.token_id_full' <<<"$credential_json")"
token_secret="$(jq -r '.data.secret' <<<"$credential_json")"

test -n "$lease_id" && test "$lease_id" != "null"
test -n "$token_id_full" && test "$token_id_full" != "null"
test -n "$token_secret" && test "$token_secret" != "null"

export PROXMOX_VE_API_TOKEN="$token_id_full=$token_secret"
unset credential_json token_id_full token_secret

echo "Vault lease issued (secret not displayed)."
vault lease lookup "$lease_id"

# Run an authorized API operation with PROXMOX_VE_API_TOKEN.
# The caller is responsible for consuming it before it expires.

vault lease revoke "$lease_id"
unset PROXMOX_VE_API_TOKEN lease_id
```

For unattended automation, ensure cleanup is also attempted on failure or cancellation (for example a Bash `trap` or CI `always()` cleanup), and never put the generated token in pipeline outputs, verbose HTTP logs, build artifacts or long-lived configuration files. An abrupt runner crash can prevent cleanup; native Proxmox expiry is the fallback.

The Proxmox HTTP authorization format is:

```text
Authorization: PVEAPIToken=<USER>@<REALM>!<TOKEN_ID>=<SECRET>
```

The plugin returns the identifier and secret separately. A consumer must compose them correctly. The current plugin does **not** return an already-combined `api_token` field.

## 11. Post-deployment verification checklist

- `vault plugin info -type=secret vault-plugin-secrets-proxmox` returns a registered version.
- `vault secrets list -detailed` shows the expected mount, configured version and running version.
- Issuer config reads omit the secret; other non-admin clients cannot access the config path.
- A Vault role read shows a finite `ttl` and explicit privilege inheritance acknowledgement.
- A newly issued lease has `lease_renewable=false` and the expected duration.
- A disposable Proxmox token exists, has native expiration, and has the **target** identity's effective permissions.
- `vault lease revoke <lease_id>` causes Proxmox token deletion (verify separately with authorized read-only inspection).
- An already-revoked token cannot authenticate.
- A token allowed to expire natively cannot authenticate after expiry even if Vault cannot revoke it.
- A workload token **cannot mint another longer-lived token**, modify user/ACL privileges, or cross the intended permission boundary. If any of these tests fail, stop.

## 12. After deployment

Use [Operations](operations.md) for routine audit checks, backups, versioned plugin updates and rollback, issuer rotation and failure response. Use [Security](security.md) for the known containment gaps and pre-production gate. To add a second isolated issuer, follow [Configuration — multiple issuer identities](configuration.md#multiple-issuer-identities).

**Upstream references:** [Vault plugin registration](https://developer.hashicorp.com/vault/docs/plugins/register), [Vault plugins](https://developer.hashicorp.com/vault/docs/plugins/plugin-architecture), [Proxmox VE user management](https://pve.proxmox.com/pve-docs/pveum.html).
