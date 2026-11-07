# Development, testing and release guide

This guide is for contributors and operators building or validating this Vault Proxmox secrets-engine plugin **before** an external-system integration test.

## Source layout

| Path | Responsibility |
|---|---|
| `cmd/vault-plugin-secrets-proxmox/main.go` | Vault external-plugin executable and SDK entry point |
| `backend.go` | Logical backend setup, path registration, issuer client cache |
| `path_config.go` | Issuer configuration, validation, storage and read behavior |
| `path_roles.go` | Vault role CRUD, finite TTL and inherited-privilege acknowledgement |
| `path_credentials.go` | Dynamic credential issuance, native expiry and Vault lease metadata |
| `proxmox_api_token.go` | Proxmox create/delete API interface and Vault revoke callback |
| `client.go` | HTTPS Proxmox connection and issuer token authentication |
| `*_test.go` | Unit, mock HTTPS Proxmox API, and optional acceptance tests |
| `.github/workflows/validate-go.yml` | GitHub Actions validation |
| `.github/workflows/release.yml` | Version-tag-triggered release workflow |
| `.goreleaser.yaml` | GoReleaser v2 build and artifact configuration |

## Toolchain and dependencies

The `go.mod` module targets Go 1.26.2 or newer, and CI uses **Go 1.27.3**. Build with a version compatible with your chosen release and the module's transitive requirements.

Direct dependencies include the HashiCorp Vault SDK/API, the Telmate Proxmox API client, Go HCL logging, UUID generation and Testify. Versions are pinned in `go.mod` and checksums in `go.sum`; **do not hand-edit checksum entries**.

After cloning:

```sh
go version
go mod verify
go mod tidy -diff
go test ./...
go test -race ./...
go vet ./...
```

Run a Linux build for a Vault node:

```sh
mkdir -p dist
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -o dist/vault-plugin-secrets-proxmox \
  ./cmd/vault-plugin-secrets-proxmox

sha256sum dist/vault-plugin-secrets-proxmox
```

Build/target architecture must match the Vault node. The supplied release configuration currently produces `linux/amd64`.

## Testing strategy

### Automated tests

`go test ./...` covers validation, role management, native expiration and independent revocation metadata. The synthetic HTTPS Proxmox server checks issuer authentication, custom CA verification, typed Proxmox API token creation/deletion, and Vault dynamic-secret/revocation callbacks. The test creates **no real Proxmox accounts or tokens**.

`go test -race ./...` checks for Go data races during covered paths. Passing it does not prove concurrency safety for untested runtime conditions.

### Acceptance tests (opt-in and potentially mutating)

The historical acceptance suite is gated behind `VAULT_ACC=1` and depends on additional `VAULT_PROXMOX_*` environment variables. **Never set `VAULT_ACC=1` in ordinary CI or against production Proxmox.** These tests can create and delete tokens and may leave credentials behind if cleanup fails. Before executing, review `backend_test.go`, use dedicated disposable accounts, verify all target IDs, and obtain explicit authorization from the environment owner.

Separate acceptance into two gates:

1. **Vault dev instance + mock Proxmox HTTPS service**: plugin binary registration, mount creation, issuer configuration, role definition, Vault lease creation and revoke callbacks. Exercise token/role policies and plugin restarts.
2. **Disposable real Proxmox test**: verify restricted issuer token creation/deletion for a distinct user, target-token self-mint behavior, expired token denial and independent token revocation. Stop if the target token can mint replacement tokens or the issuer needs excessive privileges.

The second gate is required before production integration. See [Security](security.md#pre-production-acceptance-checklist).

## Mock-test development

- Use `httptest.NewTLSServer` or an equivalent isolated HTTPS server; do not disable TLS verification to make tests pass.
- Validate exact API method, expected `/api2/json` path, issuer authorization header, finite `expire` and expected privilege-separation mode.
- Treat response token secrets as sensitive even in logs; use fixed mock strings only.
- Include idempotent token deletion, API 403, 5xx, network failures, bad PEM, role deletion and changes to issuer credentials.
- When adding a new feature, add a failure-path test and a documentation update to [Configuration](configuration.md).

## Coding and contribution practices

- Keep the Vault SDK layer separate from Proxmox API operations and preserve context cancellation.
- Use Vault logical storage for plugin configuration; never introduce plaintext local config files for issuer credentials.
- Validate user-provided role fields, URL, TLS settings and duration **before** side-effectful Proxmox API requests.
- Do not log authentication headers, issuer secrets, returned token secrets or raw Vault responses.
- Use fail-closed error handling for token create/delete and avoid marking a lease revoked when the Proxmox delete actually failed.
- Maintain backward compatibility for existing leases where possible. Lease internal metadata is versioned operational state, not disposable scratch data.
- Avoid increasing permissions silently: new capability must remain opt-in and must be justified by Proxmox ACL behavior.

## Dependency updates

Use a fresh branch and document why each dependency changes:

```sh
go get github.com/hashicorp/vault/sdk@<REVIEWED_VERSION>
go get github.com/hashicorp/vault/api@<REVIEWED_VERSION>
go mod tidy
go mod verify
go test ./...
go test -race ./...
go vet ./...
```

The version placeholders above are explanatory; use an actual reviewed release when running them. Read transitive updates and API-breaking changes, especially in the Proxmox client and Vault SDK. Commit **both** `go.mod` and `go.sum`.

## Release process

The release workflow triggers on `v*` tags; release tags are not equivalent to a production approval. Review and merge CI validation, code review, release metadata and the security acceptance gate before tagging.

Useful local checks:

```sh
goreleaser check
goreleaser release --snapshot --clean
```

Pin release artifact digests and retain the exact immutable binary for rollback. Register with Vault only after confirming its SHA-256 matches the audited build. For plugin installation, see [Deployment](deployment.md#5-install-checksum-and-register-the-plugin). For upgrades, see [Operations](operations.md#plugin-upgrades--versioned-reversible).

## Documentation expectations

- Keep README links and end-to-end deployment commands synchronized with real plugin paths and fields.
- Use reserved example domains (`example.invalid`), placeholder users and explicitly redacted credentials.
- Do not include personal hostnames, addresses, local network layout, infrastructure credentials or environment-specific automation in shared docs.
- Mark unfinished functionality as unsupported; never describe planned per-token ACL assignment or orphan reconciliation as implemented.

## External references

- [Vault plugin SDK and plugin registration](https://developer.hashicorp.com/vault/docs/plugins/register)
- [Vault plugin upgrades](https://developer.hashicorp.com/vault/docs/plugins/upgrade)
- [Proxmox VE API and access control](https://pve.proxmox.com/pve-docs/pveum.html)
