# Security and documentation audit — 2026-11-07

**Scope:** Vault Proxmox secrets-engine plugin, its third-party Proxmox client integration, issuer/role/lease logic, build/release pipelines, end-to-end tests, and generic deployment/Hermes Host Operations documentation. This audit reviews the source implementation and disposable CI tests; it is **not** a penetration test or certification of a live Vault/Proxmox installation.

## Readiness assessment

| Stage | Assessment |
|---|---|
| Unit and simulated-Vault testing | Automated gates in GitHub Actions |
| Real Proxmox API behavior | Automated **PVE 9.2.2** disposable-container tests |
| Security hardening | Same-user issuer boundary; verified TLS; no arbitrary issuer headers/proxy on new issuance; deny redirects; sanitized errors; identity validation |
| Vulnerability scan | Pinned Go `govulncheck` added as a required CI job; review every finding before release |
| Real nonproduction integration trial | **Pending**: requires an operator-controlled Vault/Proxmox deployment and restricted account ACLs |
| Production authorization | **Conditional / not yet granted by this report**; complete the acceptance gates below |

## Review approach

The audit checked the issuer/role security boundary, Vault policy implications, Proxmox API semantics, secret exposure, transport settings, expiration/revocation behavior, third-party dependency supply chain, CI permissions, operational recovery, and documentation accuracy.

### Controls verified through implementation and tests

1. **No cross-user token issuance:** A Vault role may issue only for the exact Proxmox username/realm configured on its own mount. The equality check runs before the Proxmox API is called. An alternate overprivileged token issuer cannot bypass it through the plugin.
2. **Avoid global user-administration privileges:** Disposable Proxmox VE 9.2.2 tests proved that a non-root issuer with `PVEUserAdmin` on `/access` can create an authenticating `root@pam` API token. The supported replacement is one restricted same-user password issuer per mount.
3. **Finite, nonrenewable credentials:** Role TTL is bounded (1 minute to 24 hours), native expiration is set, and Vault's lease callback deletes the created token.
4. **Correct lease identity:** Newly issued leases retain target user, realm and token ID, so editing or deleting a Vault role does not redirect revocation to another account.
5. **Secret redaction:** Vault `config` reads omit issuer passwords and API-token secrets. Historical `http_headers` and `proxy_server` fields are now redacted rather than echoed, because a legacy setting could contain embedded authentication data.
6. **Transport hardening:** New issuer config and credential issuance reject `insecure_skip_tls_verify=true`, custom HTTP headers and proxy servers. Normal TLS trust or a specifically configured CA chain is required.
7. **Redirect prohibition:** HTTP clients do not automatically follow API redirects, preventing unintended forwarding of issuer authentication credentials.
8. **Context and sensitive errors:** Fresh issuer login respects the Vault request context and has an explicit timeout; authentication/create/revoke errors use sanitized caller-visible messages rather than raw upstream error bodies.
9. **Account identity validation:** User/realm character restrictions reject ambiguous Proxmox account separators, URL path characters and control characters.
10. **CI isolation:** Real-Proxmox tests use a digest-pinned third-party test image only on a disposable GitHub-hosted runner; its privileged test container binds Proxmox HTTPS to loopback and receives no live secrets.

### Test evidence and limitations

| Verification | Automated evidence | Remaining limitation |
|---|---|---|
| Go unit, race, build, vet, module graph | GitHub "Go validation" | Static and unit checks do not cover untested integrations |
| Real Vault plugin registration/leases | GitHub "Ephemeral Vault plugin integration test" | Vault runs in ephemeral development mode |
| Token creation, read permission, self-mint denial, revoke, native expiry | GitHub "Real Proxmox API integration" | PVE 9.2.2 container is not a complete production Proxmox cluster |
| Identity restriction, TLS hardening, error redaction and redirect behavior | New unit/regression cases | Changes must remain gated by CI and actual endpoint acceptance |
| Public vulnerability database scan | `govulncheck` (pinned version) | Only known vulnerabilities, reachable-code heuristics; not a substitute for reviewing advisories and libraries |

## Dependency audit finding and remediation

The newly introduced `govulncheck` gate initially found **five reachable
HTTP/2 vulnerabilities** in the transitive `golang.org/x/net v0.59.0`
dependency (`GO-2026-6603`, `GO-2026-6610`, `GO-2026-6611`,
`GO-2026-6612`, `GO-2026-6617`). Upstream fixes are available in
`golang.org/x/net v0.60.0`. The repository was upgraded to that version,
and its `go.sum` checksums were updated from published Go module sums.
The follow-up pinned `govulncheck` scan **passed**.

- [Go vulnerability report GO-2026-6603](https://pkg.go.dev/vuln/GO-2026-6603)
- [GitHub-hosted Go vulnerability gate](../../.github/workflows/validate-go.yml)

This is a snapshot of **known** vulnerabilities on the audit date, not a
guarantee that new advisories will not appear. Keep scanning on every code
change and ahead of each production binary release.

## Release workflow gate

The tag-triggered [release workflow](../../.github/workflows/release.yml)
now separates a read-only **verify** job from the job holding
`contents: write` for GitHub release publication. Before GoReleaser can
publish a tag, the candidate commit must be reachable from `main`, module
checksums and module graph must pass, race tests and `go vet` must succeed,
and the pinned `govulncheck` scan must report no known reachable
vulnerabilities. The publishing job runs **only after** verification passes.

This gate improves release discipline but does **not** replace protected
branch/tag permissions, review requirements or signing and independent
verification of release artifacts. Apply those repository settings separately.

## Residual risks and explicit production gates

| Severity | Finding / residual risk | Required release action |
|---|---|---|
| High | **Proxmox rights are inherited from the account, not individually scoped per issued token** | Verify every effective permission of each restricted account on actual target clusters; do not use globally privileged accounts |
| High | A token with user-management rights may create replacement tokens despite its TTL | Against the intended PVE version and actual account ACLs, attempt sibling token creation, token updates, user management and privilege modification; expect denial |
| High | The issuer password persists in Vault beyond generated token leases | Restrict `config` Vault policies, protect storage/backups/unseal, document rotation/incident response and avoid exposing the password to agents |
| High | An overly broad Kubernetes ServiceAccount/Vault role exposes the credentials endpoint to unauthorized pods or callers | Verify JWT audience, namespace/name binding, short Vault token TTL, exact policy, mTLS/CA, deny-by-default ingress and tool caller authorization |
| Medium | A crashed workload or network failure may leave a token until native Proxmox expiration | Implement cleanup/alerting and test revoke/expiry during Vault or PVE outages; consider orphan-token reconciliation |
| Medium | Every `creds/<role>` read mutates Proxmox token inventory | Apply Vault issuance rate limits, instrument token creation/revoke, and bound MCP request concurrency |
| Medium | Changing issuer identity or authentication mode while leases remain outstanding may break revocation | Clear or independently inspect outstanding leases before rotating identities; test rotation during the live trial |
| Medium | Current CI exercises only a disposable PVE 9.2.2 API stack and Vault 1.21.4 dev server | Exercise supported actual Vault/PVE versions, certificate renewal, plugin reload, restart, and recovery |
| Medium | The TLS/proxy/header hardening changes how legacy unsafe configs behave | Migrate TLS trust and remove overrides **before** upgrading; historical revocation support remains, but new issuance is blocked |
| Low | Test-only third-party PVE image runs privileged and has public fixture credentials | Keep on ephemeral GitHub-hosted runner only; pin/review digest; never expose its port externally or attach repository/production secrets |
| Low | Released binaries, tags and source dependency graph can drift | Require code review, audited dependencies, immutable release digests, CI success and rollback artifact preservation |

## Hermes Host Operations review

[Hermes integration](../hermes-host-operations.md) describes the intended pattern:

- The **trusted, typed MCP backend** (not the Hermes LLM) obtains a short-lived Vault service token using its own Kubernetes ServiceAccount.
- Vault policy permits only one `<mount>/creds/<role>` read; no `config`, `sys/plugins` or broad lease-admin access.
- MCP fetches a temporary Proxmox API token, performs the allowed API operation and returns **sanitized schema-bound results**.
- The MCP revokes its **own Vault service token**, cascading revocation of the generated Proxmox lease. Native expiry backs up failed cleanup.
- Proxmox API credentials **do not replace SSH keys or host-level Linux privilege controls**. SSH transport, forced commands and exact sudoers policy remain separate.
- The long-lived account password is held by Vault; it must never be put in Hermes, Kubernetes manifests or source control.

The current repository **does not implement the Hermes Host Operations MCP application**. This guide specifies a secure integration contract. Implement and test the MCP side separately before enabling it.

## Acceptance procedure

### Gate A — code and provenance

- [ ] Latest branch passes **all** Go, race, Vault E2E, real-Proxmox E2E, documentation and vulnerability-scan CI checks.
- [ ] No known actionable reachable vulnerabilities remain; record exceptions with approved rationale and expiry.
- [ ] Binary is built from a reviewed commit and installed with verified checksum on every Vault node.
- [ ] TLS trust works with a real valid certificate/CA; production disables TLS bypass and custom request headers/proxy.

### Gate B — isolated real integration

- [ ] Dedicated PVE-realm users exist with no global `PVEUserAdmin` or equivalent broad user-management privileges.
- [ ] Vault mounts each use `auth_method=password` and issue only for their own user/realm.
- [ ] A non-admin test token can perform only the intended approved inventory or deployment action and fails all unauthorized operations.
- [ ] Test direct Proxmox native expiration, Vault automatic expiration, explicit revoke, repeated revoke and failed revoke recovery.
- [ ] Test password rotation, mount restart and plugin upgrade/rollback with leases outstanding.
- [ ] Confirm Vault audit devices and Proxmox logs never expose authentication secrets.
- [ ] Confirm rejected cross-user issuance makes **no network token-creation request**.
- [ ] Validate actual ingress/egress firewall policy between Vault and Proxmox, and test cert hostname/CA mismatch.

### Gate C — Hermes integration and operations

- [ ] The MCP backend authenticates via a narrowly bound, audience-restricted service-account JWT.
- [ ] The Hermes agent never sees Vault tokens, Proxmox API token secrets or issuer passwords.
- [ ] Expose only typed, audited, paginated and output-limited MCP tools; no arbitrary shell or generic REST forwarding.
- [ ] A separate Vault auth session per operation avoids accidentally revoking a shared lease during another operation.
- [ ] Revoke-self cleanup succeeds; failure and crash paths rely on native expiry and alert operators.
- [ ] Separate Proxmox credentials from SSH host-operation authentication and isolate different capability domains.

## Final disposition

**Ready for a controlled real-infrastructure integration trial after all automated gates pass. Production is not approved solely by this code audit.** Promote the exact reviewed build only after Gates A–C relevant to the intended deployment are evidenced, the open residual risks are explicitly accepted, and an operational rollback/recovery process is verified.

A green CI run supports confidence in a *specific configuration and version*; it does not prove an arbitrary Proxmox account's ACL is safe for general-purpose automation.
