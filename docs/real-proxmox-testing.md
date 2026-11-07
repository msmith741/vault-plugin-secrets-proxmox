# Real Proxmox VE authorization integration (GitHub Actions)

This suite complements the [mock-based Vault integration test](testing.md). It runs **actual Proxmox VE authentication, API token, user and permission services** in an ephemeral third-party test container alongside a real disposable Vault process and the compiled plugin.

The test does **not** contact a live or externally hosted Proxmox instance. Its test credentials are created entirely within a temporary GitHub-hosted runner. The Proxmox image is intentionally **not suitable for production**.

## Running the test

Open [Real Proxmox API integration](../.github/workflows/test-real-proxmox.yml) and use **Actions → Real Proxmox API integration → Run workflow → main**, or review the workflow results on a same-repository pull request. It uses a standard GitHub-hosted Ubuntu 24.04 runner, no runner repository secrets, no homelab credentials and no permanent services.

It runs the third-party `client-api/proxmox-docker` PVE 9.2.2 test image with `--privileged` and disables VM/CT fixtures because this suite only needs the real PVE API. Only loopback port 8006 is published. The image includes documented, public fixture root credentials, used only inside the runner to create disposable test accounts. Its own CA is copied for **normal TLS verification**; Vault's `insecure_skip_tls_verify` remains false.

The test runner builds the plugin, verifies and launches Vault 1.21.4, registers the plugin and uses real Vault leases to issue temporary Proxmox credentials through the real PVE API.

## Coverage

| Behavior | Verification |
|---|---|
| Real HTTPS Proxmox API | Verify certificate chain and hostname against container-generated CA |
| Vault plugin installed and mounted | Real plugin RPC in ephemeral Vault |
| Proxmox token create/revoke | Actual `pveproxy`/`pvedaemon` token API |
| Multiple Vault roles | Distinct target users for workload and image tasks |
| Native expiration | Inspect real PVE token metadata and verify short token ceases authenticating |
| Vault revocation | Revoke lease, verify deleted PVE token and authentication failure |
| Inherited privileges | Inspect real PVE `privsep=0` token metadata |
| Token self-minting | **Attempt** to create a one-hour sibling token with a temporary token; if successful, emit a critical finding and fail the security gate |
| Cross-user issuer | Probe whether a restricted API-token issuer can mint for another user with no ACL and a realm-scoped user-admin role |
| Issuer scope | If delegated cross-user creation works, verify Vault issuance and revocation using that issuer |

The issuer-probe outcomes are recorded in the GitHub Actions **job summary** without logging token secrets. A failing self-mint test indicates a **real release-blocking weakness in the proposed privilege-inheritance model**, not simply a flaky mock.

## Limitations

- This is Proxmox software running within a privileged container, **not** a normal Proxmox host installation. It exercises actual token authorization, but not production networking, host capabilities, real VM provisioning, cluster roles, storage or device passthrough.
- The workflow pins the test-only image to OCI digest `sha256:d40381c1d096ffb419e48ea5c47786dab544b0de58bb845332d0892ab8a6695e` (PVE 9.2.2); pinning preserves reproducibility but is **not** a third-party security audit. Use only GitHub-hosted ephemeral runners, with read-only GitHub permissions and no user-supplied secrets.
- A test demonstrating permissive cross-user issuance does not automatically mean the issuer can be given sufficient privileges without broad user-management authority in production. Audit the actual Proxmox ACLs and supported scopes.
- A successful test against PVE 9.2.2 does not establish behavior on all other PVE versions. Test the intended release separately before production rollout.

## What a pass means

A **passing** run confirms the program can create and revoke real Proxmox API tokens, that the generated credentials have finite expiration, and that the selected restricted target account cannot escape its lease by creating another token.

A **failing** run is intentionally actionable: examine the test summary and distinguish a test harness/setup problem from an actual API permission-security finding. Do not deploy the plugin with privileged issuer accounts while the security gate remains blocked.

For production-release criteria see [Security](security.md#pre-production-acceptance-checklist). This job is additive to, not a replacement for, the existing mock-Vault test and unit tests.

## Confirmed findings on Proxmox VE 9.2.2

The disposable CI integration exercises actual Proxmox token authorization.
The initial runs showed:

- Vault successfully issues, revokes, and expires real Proxmox API tokens.
- Temporary workload credentials with only `PVEAuditor` privileges were denied
  the ability to mint longer-lived replacement tokens (HTTP 403).
- A separate API-token issuer could **not** create tokens for another user
  without rights or with the tested realm-scoped `PVEUserAdmin` and
  `Realm.AllocateUser` permissions (HTTP 403).
- Granting that issuer `PVEUserAdmin` on global `/access` enabled
  cross-user token issuance. The issuer could mint tokens for unrelated users,
  **including `root@pam`**. A non-root issuer must not be granted that role
  merely to make the plugin work.

The privileged root-token probe is immediately deleted within the isolated
test container, and the security gate intentionally returns failure for this
condition. This is a finding about the **chosen issuer permissions**,
not evidence that an ordinary temporary token can create replacements.

**Production deployment of cross-user token issuance remains blocked**
until a safer issuer architecture or a verified narrow privilege boundary
is implemented and independently tested.
