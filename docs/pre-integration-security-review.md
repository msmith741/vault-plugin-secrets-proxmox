# Pre-integration security review — Vault Proxmox secrets engine

## Scope

Baseline: merged PR #1 (Go 1.27.3, Vault SDK v0.26.0, Vault API v1.23.0, Telmate Proxmox API Oct 2026).
This is a **code and synthetic-test review only**. No real Proxmox instance, Vault service, credentials or K3s infrastructure were modified.

## Findings and disposition

| Risk | Finding | Mitigation / remaining condition |
|---|---|---|
| **Critical** | Generated tokens use `privsep=false` and inherit all permissions of their Proxmox account. | Require explicit role `inherit_user_privileges=true`; refuse to issue root@pam tokens; still must use restricted parent users. Not a sandbox. |
| **Critical** | A target token may be able to issue sibling or replacement tokens, defeating its TTL. | **Release blocker**: prove Proxmox self-token creation, alteration and ACL behavior with disposable accounts. If possible, implement per-token ACL delegation or redesign issuance. |
| High | Issuer API credential is stored in plugin config; TLS interception leaks it. | HTTPS-only canonical endpoint checks, private CA PEM support, default TLS validation; legacy insecure opt-out remains, disallow it operationally. |
| High | Issuer rotation can strand active leases when the replacement lacks authority to delete previously issued tokens. | Keep previous issuer identity and revocation authority until all leases are cleared. A future version should record issuer identity/rotation metadata in leases. |
| High | Vault crash between Proxmox create and lease registration could strand temporary credentials. | Native Proxmox expiration is required; add an orphan-token reconciler with a reserved token prefix before production. |
| Medium | Proxmox unavailable during lease revocation. | Vault can retry; monitor lease failures; Proxmox native expiration as fallback. Do not force-revoke leases unless externally confirmed deleted. |
| Medium | API client cache could race during simultaneous reads or config changes. | Double-checked locking; explicit unconfigured errors. |
| Medium | Unconfigured `config` read could dereference nil. | Return no data and fail issuance without network access. |
| Medium | No proof of plugin compatibility with your particular Vault runtime. | Verify server version and execute an isolated Vault dev-plugin test before connecting to a live Proxmox host. |

## Required isolated tests before using real Proxmox

1. `go mod verify`, `go mod tidy -diff`, `go test -race ./...`, `go vet ./...`, `go build ./cmd/vault-plugin-secrets-proxmox` and GoReleaser configuration check.
2. Register the binary in a disposable Vault dev instance. Validate role creation, Vault lease issue, expiry and revoke callbacks against a mock HTTPS Proxmox service.
3. Verify custom CA PEM trust, invalid TLS rejection, token expiry timestamp, token ID uniqueness, request authorization and deletion behavior against the mock.
4. Confirm roles and policies cannot issue arbitrary user IDs, set arbitrary TTLs, change issuer config or read another role's issued token without explicit Vault ACLs.
5. Verify newly minted credentials remain nonrenewable; role changes/deletion should not affect revocation of *new* leases. Test revocation after plugin restart.
6. Verify updating the issuer while leases exist does not silently break revocation; document recovery path.

## Controlled Proxmox acceptance test **after** synthetic gate

1. Create temporary image and deploy users and isolated issuer identities on `overlord`, with audit-reviewed ACLs.
2. Verify whether a Proxmox API-token-authenticated issuer can create and delete tokens for the targeted account. Record exact API responses.
3. Test whether the newly generated target token can create a sibling token, extend the expiration, update ACLs or generate new credentials. **Do not proceed to production if the token can bypass expiry.**
4. Verify the image identity cannot perform VM deployment and the VM identity cannot modify image infrastructure, user ACLs, or the host's raw disks.
5. Generate a short-lived token; explicitly revoke its Vault lease and confirm it becomes unusable.
6. Simulate Vault being unavailable and confirm that native Proxmox expiration independently prevents use after expiry.
7. Confirm Proxmox certificates validate using the configured CA and hostname (no insecure TLS).
8. Verify two independent Vault mounts and issuer credentials with isolated Vault policies: `proxmox-images/` and `proxmox-vms/`.
9. Validate backup/recovery of the external plugin binary and checksum independently of the Vault Raft snapshot.
10. Establish an alert for token revocation failures and an orphan reconciliation procedure.

## No-production-deployment rule

Do not install the plugin on `vault01` with privileged issuer credentials, or connect it to one-click OpenTofu operations, until the **critical** self-mint and issuer-boundary tests are passed. A short native expiry is a limit on one token, **not a guarantee** that the identity cannot obtain a second token.
