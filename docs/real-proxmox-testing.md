# Real Proxmox VE authorization integration in GitHub Actions

This workflow starts an actual **Proxmox VE 9.2.2** API/authentication stack inside a disposable privileged container, alongside a disposable Vault **1.21.4** server and the compiled plugin. It is more realistic than the [HTTPS mock API suite](testing.md) but does not create a permanent Proxmox installation.

[GitHub Actions workflow](../.github/workflows/test-real-proxmox.yml) · [Python integration harness](../tests/e2e/real_proxmox_vault_e2e.py)

## Test environment and safety

- GitHub-hosted `ubuntu-24.04` runner only; no self-hosted runners, infrastructure secrets, VPNs or production endpoints.
- Third-party `client-api/proxmox-docker` PVE 9.2.2 image, pinned by an immutable OCI SHA-256 digest.
- The Proxmox container is `--privileged` because of systemd/FUSE requirements. Its API port is published on the runner's **loopback interface only**.
- PVE fixture passwords are public, but any extra PVE-realm user passwords are randomly generated for that run.
- The container's generated TLS leaf certificate is obtained over loopback, its actual hostname is used for verification and the plugin's TLS bypass remains disabled.
- All API tokens are temporary and restricted to this test environment. Any root-token permission probe is deleted immediately.
- Vault runs in development mode with a synthetic root token and exits at the end of the job.
- The workflow deliberately enables **no VM/container fixture deployments**. It tests only authentication, token lifecycle and ACL behavior.

## Verified same-user model

1. Create two restricted `@pve` users in the disposable Proxmox API, with independent passwords and resource ACLs.
2. Mount the same Vault plugin twice, each with `auth_method=password` and an issuer username equal to the matching role's target user.
3. Issue temporary API tokens through each real Vault mount, authenticate to real Proxmox and inspect the native expiration and `privsep=false` state.
4. Confirm the restricted workload token cannot create a longer-lived replacement (HTTP 403).
5. Revoke a token after changing its Vault role and confirm the **original** Proxmox account's token is gone and cannot authenticate.
6. Confirm a cross-user role is refused by the plugin before making any Proxmox token-creation API call.
7. Independently confirm native Proxmox expiry makes an issued token unusable.
8. Demonstrate that **direct Proxmox** token issuance under a non-root user with global `PVEUserAdmin` could create an authenticating `root@pam` token.
9. Configure that dangerous issuer with the plugin and confirm the **plugin refuses its cross-user credential request** despite the underlying Proxmox permission.
10. Delete any privilege-boundary probe token and destroy both test processes.

## Confirmed findings

| Scenario | Proxmox VE 9.2.2 test result |
|---|---|
| Dedicated `deployer@pve` password ticket creates its own expiring token | **Passed** |
| Dedicated `images@pve` password ticket creates/revokes its own token | **Passed** |
| New token authenticates, then fails authentication after Vault revoke | **Passed** |
| Restricted workload token creates longer-lived sibling | **Denied (HTTP 403)** |
| Plugin targets another user despite role mismatch | **Denied before Proxmox request** |
| Broad non-root issuer uses `PVEUserAdmin` on `/access` to mint a root token directly | **Allowed — risk confirmed** |
| Same broad issuer uses plugin to create token for another user | **Denied by plugin** |
| Real token expiry without Vault action | **Passed** |

**Interpretation:** The self-user password-ticket architecture eliminates the plugin's need for globally delegated cross-user token administration. It does **not** make Proxmox's global user-administration role safe to grant, and does not eliminate the need for restricted account ACLs.

## Rerunning CI

On the default branch, open **Actions → Real Proxmox API integration (disposable container) → Run workflow**. The workflow also runs on same-repository code changes. It builds the plugin, installs a checksum-verified Vault binary, runs the Proxmox test image, and writes a redacted summary to GitHub.

The image is a test fixture and may diverge from the real hardware/cluster environment. All production deployments require independent review of Vault version, Proxmox version, ACLs, TLS and revocation behavior.

## What is not tested

- VM provisioning, storage manipulation, actual clustering, host ACL propagation, disks, node-to-node migration and live infrastructure networking.
- Proxmox versions other than the pinned test image.
- Every possible user permission combination.
- Durable Vault storage and all HA/DR restoration scenarios.
- Automated orphan-token reconciliation, which is not implemented.

For requirements before production deployment, see [security acceptance](security.md#pre-production-acceptance-checklist) and [deployment](deployment.md).
