# Security model, limitations and acceptance checklist

This document describes the plugin's **implemented security properties**, material unverified assumptions, and the test evidence required before any privileged or production deployment.

## Trust boundaries

There are three independent actors:

1. **Vault administrator/operator** — registers the plugin, configures the issuing Proxmox token, creates roles, and manages Vault ACLs.
2. **Vault credential consumer** — authenticates to Vault with a narrowly scoped identity and reads one `<mount>/creds/<role>` endpoint.
3. **Proxmox API** — authenticates the issuer and generated target token and enforces Proxmox's own ACL model.

### Security facts

- The plugin's issuer token is held in Vault plugin storage and used for token create/delete API requests. It is not returned by `vault read <mount>/config`.
- The Proxmox API token returned to a consumer is **not the issuer token**. It belongs to the target Proxmox identity selected by the Vault role.
- Issued tokens are created with **`privsep=false`**, which grants them all effective privileges of the target Proxmox account.
- `inherit_user_privileges=true` is required for role configuration; it acknowledges the risk but **does not reduce permissions**.
- Roles for `root@pam` are refused. Other Proxmox identities can still be overprivileged and must be audited.
- Tokens have a finite native expiration and a non-renewable Vault lease. Native expiry is a fallback if a Vault revoke request cannot reach Proxmox.
- The issuer is configured **per mount**, not per Vault role. Separate mounts are appropriate when separate Proxmox issuer credentials are needed.
- There is **no automatic per-token Proxmox ACL assignment**, no issuer-rotation tracking in lease metadata, and no built-in orphan-token reconciliation task.

## Why a token TTL may not be a sufficient security boundary

A generated token may inherit Proxmox account permissions that allow user or token management. If it can create a second token with a later expiration, it can effectively extend its access beyond the original Vault lease.

**This must be verified on the exact Proxmox version and ACLs in the target environment.** The plugin's unit tests cannot establish the real API authorization semantics.

Do **not** compensate for a permission failure with an unrestricted Proxmox Administrator role or a root issuer identity. If a restricted issuer cannot mint/delete another account's tokens without excessive privilege, revise the design or do not deploy the dynamic credential workflow.

## Evidence from disposable real-Proxmox testing

A GitHub-hosted test using real **Proxmox VE 9.2.2** authentication services
established that a non-root issuer granted `PVEUserAdmin` on `/access`
could create API tokens for unrelated accounts, **including `root@pam`**.
In the same test, more restricted user-management roles on
`/access/realm/pve` were denied cross-user token creation (HTTP 403).

The workload token itself could **not** mint a replacement token with its
read-only permissions (HTTP 403). The critical escalation path is in the
separately configured *issuer*, not that workload token.

**Do not grant global `PVEUserAdmin` to make cross-user issuance work.**
The current cross-user issuer design is not production approved. See
[Real Proxmox authorization test](real-proxmox-testing.md) for reproducible
test procedures and results. This finding is specific to the tested
permissions and version; production still requires its own acceptance test.

## Risk register

| Severity | Risk | Existing control | Still required |
|---|---|---|---|
| **Critical** | Generated token can mint/extend another token | Finite expiry; role opt-in; `root@pam` refusal | Prove inability to mint/alter new tokens; restrict target account; evaluate `privsep=1` support |
| **Critical** | Issuer identity needs excessive token/user-management access | Independent issuer identity; mount isolation | Test Proxmox delegated authority on disposable accounts; fail closed if too broad |
| High | Credential theft from TLS interception or logs | HTTPS URL validation, normal verification, optional CA PEM | Validate hostname/CA; disable TLS bypass; restrict proxy/headers; scrub logs |
| High | Revocation fails after issuer rotation or removal | Token target user/realm stored in lease | Retain original issuer authority and test new revocation path |
| High | Crash after Proxmox token creation but before Vault records lease | Native expiration always finite | Reconciliation runbook; monitor tokens with reserved prefix; add issuance rollback |
| Medium | Network outage delays revocation | Native expiration, Vault revoke callbacks | Alert and retry; inspect Proxmox directly; never force revoke blindly |
| Medium | Configuration/role write access lets caller redirect issuer | Vault ACL policy separation | Give management only to authorized operators; audit changes |
| Medium | Vault backup restores catalog but not binary | Plugin checksum catalog | Back up exact immutable plugin artifact for every Vault node |
| Medium | Unreviewed dependency/runtime changes | Pinned Go dependencies, CI, versioned plugin registration | Test against deployed Vault/Proxmox versions; review provenance and SBOM where available |

## Production safeguards

### Proxmox accounts and ACLs

- Use a dedicated issuer identity and a different dedicated target identity. Do not let ordinary workloads obtain the issuer token.
- Limit target users to precisely the resource operations and paths they need. Avoid broad permissions on `/` or `/access`.
- Establish whether the issuer may create and delete target tokens. This is an **authorization test**, not a setup assumption.
- Make the issuer's own bootstrap token privilege-separated where supported and ensure its token-specific ACLs contain only the required permissions. Its effective privileges may differ from those of its parent user.
- Test the generated token's ability to create a sibling token, extend expiration, list users, modify ACLs, and perform unrelated resource operations.
- If any boundary fails, stop before production rollout.
- Use separate Vault mounts and credentials when work classes should not share issuing authority.

### Vault access control

- Authenticate users and workloads to Vault using an approved auth method. A credential consumer should have only `read` on its own `<mount>/creds/<role>`.
- Separate issuer configuration permissions from role administration, lease operations, and catalog management.
- Restrict Vault plugin catalog changes and secrets-engine enable/disable privileges to Vault administrators.
- Review and enable Vault audit logging as appropriate. Audit device keys are HMAC-protected by default; do not add generated secrets or issuer fields to non-HMAC exclusions.
- Do not persist raw credentials in CI artifacts, build cache, service logs, shell history, crash reports or Terraform state.
- Use short-lived Vault authentication tokens for CI; the Vault login TTL and Proxmox token TTL are **different lifecycles**.

### TLS, service and artifact integrity

- Use validated HTTPS for Vault and Proxmox. Use `ca_cert_pem` when Proxmox is signed by a private CA.
- Keep `insecure_skip_tls_verify=false`. A legacy flag exists for compatibility but bypasses endpoint authentication.
- Restrict proxies and injected HTTP headers because they can redirect or expose issuer requests.
- Pin reviewed plugin build artifacts by SHA-256 and semantic version; don't replace a registered version's binary in place.
- Install the plugin directory so the Vault service can execute the binary but cannot rewrite it.
- Protect Vault's seal/unseal process, storage, snapshots and audit log access independently.
- Keep a recovery method outside the plugin if Vault itself becomes unavailable.

## Pre-production acceptance checklist

**Status:** unit tests, an HTTPS API simulator, and an ephemeral **real Vault 1.21.4** plugin lifecycle test pass in GitHub Actions. The synthetic coverage includes plugin mounting, consumer Vault ACLs, token issuance and lease revocation. **Real Proxmox permission-boundary tests remain outstanding**; see [Ephemeral integration testing](testing.md).

| Test | Expected result |
|---|---|
| Compile the binary against the pinned module graph | `go mod verify`, `go test -race ./...`, `go vet` and GoReleaser validation pass |
| Register in a disposable Vault instance | Plugin loads with expected version and checksum |
| Validate issuer TLS trust | Properly signed Proxmox endpoint succeeds, unknown CA/hostname fails |
| Configure a restricted issuer | Token issuance/deletion works without broad admin privileges |
| Issue for a separate target user | Token identifies the correct target; no issuer secret is returned |
| Inspect target permissions | Only approved Proxmox paths/operations permitted |
| Attempt sibling-token creation | **Must fail**; otherwise pause rollout and redesign permissions |
| Attempt user/ACL changes | **Must fail** for normal target credential |
| Test 1-minute native expiry | Token stops authenticating even without Vault revocation |
| Revoke the Vault lease | Corresponding Proxmox token deleted; repeated delete is safe |
| Edit/delete a Vault role while lease exists | Lease still targets original user/realm for revoke |
| Interrupt Proxmox during revoke | Failure observed and operational retry/reconciliation succeeds |
| Rotate issuer while lease exists | Existing lease can still be revoked or is natively expired |
| Restart Vault with a live lease | Revocation still works after recovery |
| Confirm two isolated mounts | Workload for mount A cannot read mount B credentials/config |
| Audit and backup restore | Artifact present on every Vault node; access and change logs preserved |

The checklist should be recorded with actual software versions, issuer/target ACLs, API responses and outcome for each case. It is **not** a claim that these tests have already passed in a live environment.

## Failure containment

If credentials are suspected compromised:

1. Block the affected Vault role's **consumer access**, and stop further issuance.
2. Revoke known leases using `vault lease revoke <lease_id>` where revocation authority still works.
3. On Proxmox, independently verify deletion or expiry of the affected target tokens.
4. Remove or disable any illicit replacement tokens and evaluate changes to ACLs or resources.
5. Rotate the affected issuer credentials only after understanding its active lease impact.
6. Preserve audit evidence, repair the permission model and retest before resuming use.

Never rely solely on Vault's reported revocation status when Proxmox was unavailable or network access was interrupted.

## Security references

- [Proxmox VE user and API token management](https://pve.proxmox.com/pve-docs/pveum.html)
- [Vault policies](https://developer.hashicorp.com/vault/docs/concepts/policies)
- [Vault leases and revocation](https://developer.hashicorp.com/vault/docs/concepts/lease)
- [Vault external plugin architecture](https://developer.hashicorp.com/vault/docs/plugins/plugin-architecture)
