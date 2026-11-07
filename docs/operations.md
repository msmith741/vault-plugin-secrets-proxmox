# Operations and maintenance

This runbook describes how to operate an **already-deployed** Vault Proxmox secrets engine. Replace example mount names, credentials and paths with the values used in your environment.

> [!IMPORTANT]
> Before using the plugin with real Proxmox privileges, complete the [security acceptance checklist](security.md#pre-production-acceptance-checklist). The plugin's tested mock behavior does not establish the Proxmox permission boundary for all versions.

## Daily health and version checks

Authenticate to Vault with the approved operator identity:

```sh
vault status
vault plugin info -type=secret vault-plugin-secrets-proxmox
vault secrets list -detailed
vault read proxmox/config
vault list proxmox/role
```

`vault read proxmox/config` excludes `token_secret`; ensure it returns only the expected issuer metadata. Do **not** query `proxmox/creds/<role>` as a passive health check: that endpoint **creates a real token**.

Use a dedicated, scheduled **disposable** issuance/revocation test only when it is explicitly authorized, and track its lease. Monitor vault audit logs and Proxmox API-token creation/deletion events; treat unexpected issuance volumes, 403s, issuer changes or revoke failures as alerts.

## Issuance and cleanup

A credential consumer reads a role-specific path; for example `vault read proxmox/creds/workload`. The token is non-renewable. On job completion, revoke using the exact lease ID:

```sh
vault lease lookup "<EXACT_LEASE_ID>"
vault lease revoke -sync "<EXACT_LEASE_ID>"
```

`-sync` requests synchronous revocation; verify in Proxmox separately before marking it completely removed. If Proxmox is unreachable, investigate the revoke failure and allow its native expiry to act as the fallback. Do **not** force-revoke unless the Proxmox credential is already confirmed removed or expired and the implications are understood.

For an automation script, register cleanup on both normal and exceptional termination:

```bash
set +x
lease_id=""

cleanup() {
  if [ -n "$lease_id" ]; then
    vault lease revoke -sync "$lease_id" ||
      echo "WARNING: Vault lease revoke failed; inspect Proxmox token state." >&2
  fi
  unset PROXMOX_VE_API_TOKEN
}
trap cleanup EXIT
# After authenticated issuance, set lease_id to the returned lease_id.
# Keep the generated Proxmox token only in the job's protected process memory.
```

A process crash or terminated CI runner may skip cleanup. Never assume that an `EXIT` trap is a substitute for native expiration or reconciliation.

## Issuer rotation

**A currently issued lease captures the target identity but not the original issuer credential.** Its revoke callback uses whichever issuer is currently configured on the mount.

Recommended sequence:

1. Inventory outstanding leases and target tokens for the mount and determine the latest native expiry.
2. Suspend **new issuance** (deny the consumer ACL path or pause the calling workload).
3. Revoke outstanding leases with the **old** issuer, confirm each Proxmox token is gone or expired, and resolve failures.
4. Create a replacement issuer token with audited, restricted permissions.
5. Write the new `token_id` / `token_secret` to `<mount>/config` using stdin, leaving the target issuer user/realm unchanged unless a different reviewed identity is required.
6. Perform a controlled disposable-credential create/delete check through Vault.
7. Re-enable consumers; monitor revoke and 403 rates.

Do not delete the old Proxmox issuer account/token prematurely if outstanding leases may still require it. Avoid rotating Proxmox issuer identity, token and endpoint all at once.

## Plugin upgrades — versioned, reversible

Use immutable binaries and registration versions. A registered plugin's catalog entry and on-disk binary must match by SHA-256. Do not overwrite an existing version's executable with a different build.

Example upgrade from an older registered version to a tested newer version:

```sh
# On EVERY Vault node, stage this separately named binary first:
sudo install -o root -g vault -m 0750 \
  ./vault-plugin-secrets-proxmox-v0.2.0 \
  /opt/vault/plugins/vault-plugin-secrets-proxmox-v0.2.0

# On a trusted Vault host with administrative CLI access:
NEW_SHA="$(sha256sum /opt/vault/plugins/vault-plugin-secrets-proxmox-v0.2.0 | awk '{print $1}')"

vault plugin register \
  -sha256="$NEW_SHA" \
  -command="vault-plugin-secrets-proxmox-v0.2.0" \
  -version="v0.2.0" \
  secret vault-plugin-secrets-proxmox

vault secrets tune -plugin-version="v0.2.0" proxmox/
vault plugin reload -mounts=proxmox/
vault secrets list -detailed
```

The version and path above are **examples**, not a claim that a released `v0.2.0` binary exists. Verify the requested version and checksum before executing. For HA clusters, follow Vault's supported reload approach and ensure every active/standby node has the exact binary *before* initiating a reload.

Record the old and new catalog versions and checksums, your Vault server version, the time of upgrade, and open leases. Test read-only mount config/role lookup first, then a controlled disposable token issuance/revocation.

### Rollback

If the upgrade fails and the previous binary and plugin version are still registered:

```sh
vault secrets tune -plugin-version="<PREVIOUS_REGISTERED_VERSION>" proxmox/
vault plugin reload -mounts=proxmox/
vault secrets list -detailed
```

Do not remove the old artifact until rollback no longer depends on it. Re-test revocation of an older active lease after rollback; a passing build does not guarantee every historical lease can be revoked by every plugin version.

## Backup and recovery

Vault backups and snapshots cover Vault's storage/catalog according to the configured backend and backup strategy, but **not external plugin binaries**. Preserve, in secure backup storage:

- Exact executable for each registered plugin version and its SHA-256 digest.
- Deployment/runbook and Vault server configuration, excluding plaintext secrets.
- Names of Vault mounts, plugin versions, namespace relationships, Vault ACL policies and the Proxmox issuer/target identity model.
- A recovery procedure for secure issuer credential re-entry and Proxmox token inventory.
- Vault's own backup, unseal and disaster recovery procedures, managed independently of this plugin.

During disaster recovery, restore the matching binary to `plugin_directory` on every relevant Vault node before expecting the restored catalog mount to execute. Validate version and checksum, then verify whether previously issued tokens are still live or natively expired.

## Revocation failure response

If Vault cannot revoke:

1. Record the **exact lease ID**, target user and target token ID from authorized audit/lease records.
2. Confirm Vault connectivity and the Proxmox API TLS chain.
3. Check the configured issuer still exists and can delete tokens for the original target user/realm.
4. Retry a regular synchronous Vault revoke when permission and connectivity are restored.
5. Inspect the token directly in Proxmox with an independently authorized operator identity.
6. If needed, delete the token in Proxmox, verify the deletion, and only then reconcile the Vault lease state.
7. Check for other outstanding tokens and any ability to generate replacement credentials.

Avoid `vault lease revoke -force -prefix` during normal operations; it can remove lease tracking without deleting the corresponding Proxmox token.

## Uninstalling the mount

**Disabling the secrets engine is potentially destructive:** it removes mount configuration and causes Vault to try revoking related leases.

Only after pausing issuance, enumerating and revoking outstanding leases, confirming tokens are removed/expired, and backing up configuration:

```sh
vault secrets disable proxmox/
```

Remove the plugin catalog version and on-disk artifact only after verifying no other mounts or rollback plan requires them. A catalog entry may be shared by multiple separately configured mounts.

## Troubleshooting matrix

| Symptom | Likely cause | Safe diagnostic |
|---|---|---|
| Plugin not registered / checksum mismatch | Binary missing, wrong SHA, wrong path, stale version | `vault plugin info`, check files on every Vault node |
| Mount fails to start | Unsupported binary architecture or Vault SDK/runtime mismatch | Confirm OS/architecture, Vault service logs and plugin checksum |
| `config` missing | Issuer mount never configured | `vault read proxmox/config`; do not issue test tokens yet |
| Configuration rejected | URL isn't HTTPS `/api2/json`, token fields missing, invalid CA/timeout | Check non-secret input and certificate chain |
| Unknown certificate authority | Proxmox internal CA is not trusted | Use correct `ca_cert_pem`; do not disable TLS verification |
| HTTP 401 | Issuer token absent, expired or malformed | Verify issuer ID and token status with Proxmox administrator |
| HTTP 403 | Proxmox issuer lacks permission to create/delete target token | Audit delegated ACLs; never grant blanket admin to make it work |
| Role rejected | TTL invalid, missing `inherit_user_privileges=true`, or `root@pam` | `vault read proxmox/role/<name>` and inspect expected fields |
| Credential read creates token but job fails | Consumer cleanup not executed | Revoke lease; inspect token and native expiration |
| Vault lease revokes but target still works | Issuer revoke failed or unauthorized; target can mint replacement | Stop issuance, independently inspect Proxmox and investigate |
| Rotation breaks revocation | Old issuer permissions removed | Restore authorized cleanup path, wait for native expiry where necessary |
| Requests intermittently fail after HA change | Plugin binary not present/compatible on all nodes | Verify catalog version and installed checksum on every node |

## Metrics and audit recommendations

Record issuance count by **Vault mount and role**, failed issuance, failed revocation, lease age, API error class and the count of unmatched/expired Proxmox tokens. Avoid storing raw secrets in metric labels, traces, dashboards or error log bodies. Monitor issuer-account ACL changes, plugin registration/reload, and Vault authentication policy changes as high-signal security events.

For Vault audit setup, follow [Vault audit devices](https://developer.hashicorp.com/vault/docs/audit). For plugin lifecycle, follow [Vault plugin upgrade](https://developer.hashicorp.com/vault/docs/plugins/upgrade).
