# Ephemeral integration testing

The repository includes a **real Vault server / simulated Proxmox** integration suite that runs on GitHub-hosted Actions runners. It is intended to validate the Vault SDK process boundary, plugin registration, lease lifecycle and authorization handling **without deploying a persistent Vault server or connecting to a real Proxmox VE instance**.

## Run from GitHub, including from a phone

Open **Actions → Ephemeral Vault plugin integration test → Run workflow** on the repository's default branch. The workflow also runs automatically for pull requests that modify Go code, the e2e scripts, module files or the workflow itself.

- [Workflow file](../.github/workflows/test-ephemeral-vault.yml)
- [Proxmox HTTPS mock](../tests/e2e/mock_proxmox_api.py)
- [Vault end-to-end harness](../tests/e2e/run_vault_e2e.py)

The runner has no need for repository secrets, a VPN, your Vault address, a Proxmox host, or your SSH credentials. The root token and API tokens are fixed, clearly synthetic test fixtures; the processes bind only to the ephemeral runner's loopback interface. GitHub destroys the runner after the job ends.

## What happens during a run

1. GitHub checks out the branch and builds the plugin using the pinned Go toolchain.
2. The job downloads the official HashiCorp Vault Community Edition **1.21.4** Linux binary and checks its SHA-256 against the official published checksums over HTTPS.
3. It generates a one-day, self-signed local TLS certificate and starts a Python HTTPS API server on `localhost:8843`. The fake service implements only the token-creation and deletion operations required by the test.
4. It starts a real **Vault 1.21.4** process in disposable development mode on `127.0.0.1:8200`. Vault's plugin directory contains the newly compiled binary.
5. The harness registers the plugin with its SHA-256, mounts the secrets engine, configures an issuer with the local CA, creates Vault roles and an isolated consumer ACL.
6. It reads a generated Proxmox token through a restricted Vault identity and checks the returned lease, role mapping, native expiration and mock authentication.
7. It changes the underlying Vault role and revokes the original lease, verifying the original Proxmox token has been deleted. A second token is allowed to expire naturally after a one-minute Vault TTL, confirming Vault's expiration manager also deletes it automatically and that lease renewal is refused. It also tests a simulated Proxmox **403**, refusal of `root@pam` issuance and rejection of an untrusted HTTPS certificate.
8. The workflow attempts to stop both local processes even on failure, and the disposable runner is destroyed.

## Checks performed

| Test | Tested against |
|---|---|
| Vault plugin binary registration and process startup | Real disposable Vault |
| Secret engine mount and issuer configuration | Real disposable Vault |
| Vault role CRUD and security validation | Real disposable Vault |
| Consumer denied access to privileged paths | Real disposable Vault ACL engine |
| Real Vault dynamic lease returned | Real disposable Vault |
| Non-renewable lease metadata | Real disposable Vault |
| Token creation API / native expiration / privilege mode | Synthetic Proxmox HTTPS API |
| Token identity remains stable across role update | Real Vault + synthetic Proxmox |
| Explicit synchronous lease revoke calls Proxmox delete | Real Vault + synthetic Proxmox |
| Natural Vault lease expiry calls Proxmox delete; lease renewal denied | Real Vault + synthetic Proxmox |
| Revoked API token cannot authenticate | Synthetic Proxmox HTTPS API |
| Upstream API denies token creation with HTTP 403 | Synthetic Proxmox HTTPS API |
| Custom CA trusted; unknown CA rejected | Real Vault plugin TLS client + synthetic HTTPS server |

Normal `go test ./...` and `go test -race ./...` continue to run in a separate validation workflow.

## What is NOT established

This test **does not** prove real Proxmox permissions, including whether the issuer token can create and delete a token for another user under narrowly scoped permissions. It also does not prove that generated tokens cannot mint replacement credentials to bypass their TTL, nor does it test any actual deployment, raw-disk passthrough, Proxmox cluster behavior or a durable/HA Vault installation.

Additional work should include fault injection for delayed revocation, simulated Vault process restarts, issuer rotation, orphan-token handling and Proxmox version compatibility. The real permission boundary remains a **production release blocker**.

Review the [security checklist](security.md#pre-production-acceptance-checklist) before any live test or production rollout. No job in this workflow contacts an externally hosted Proxmox or Vault system.

## Local execution

The suite can also run on an isolated local machine using its checked-in workflow steps. It requires a Vault binary, Go, Python 3, OpenSSL, SHA-256 checksum support and the source repository. Do not use a real `VAULT_ADDR` or real credentials when executing the harness. A separately started Vault dev process with `-dev-plugin-dir` and the local HTTPS mock server are prerequisites.

## Real Proxmox authorization tests

In addition to the simulated Proxmox workflow above, the repository includes a
[real Proxmox VE authorization test](real-proxmox-testing.md) using a disposable,
privileged **Proxmox VE 9.2.2 container** on a GitHub-hosted runner. It verifies
actual PVE authentication, token creation/deletion and native expiry.

**Security finding:** In this container, a non-root API-token issuer granted
`PVEUserAdmin` on `/access` could create a token for `root@pam`. The test
deletes the probe token and fails its production-readiness security gate.
A restricted workload token did **not** self-mint a replacement (HTTP 403).
The workflow is test-only and must not be interpreted as permission to use
broad cross-user issuer privileges in production.
