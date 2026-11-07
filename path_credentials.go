package proxmox

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCredentials(b *proxmoxBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role",
				Required:    true,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathCredentialsRead,
		},
		HelpSynopsis:    pathCredentialsHelpSyn,
		HelpDescription: pathCredentialsHelpDesc,
	}
}

// Proxmox stores expiration as a Unix timestamp with one-second
// resolution. Round upward so the native expiration never precedes
// Vault's finite lease lifetime.
func nativeTokenExpiration(now time.Time, ttl time.Duration) (int64, error) {
	if ttl < minRoleTTL || ttl > maxRoleTTL {
		return 0, fmt.Errorf("refusing to create a token with invalid ttl %s", ttl)
	}
	deadline := now.Add(ttl)
	if deadline.Nanosecond() != 0 {
		deadline = deadline.Truncate(time.Second).Add(time.Second)
	}
	if deadline.Unix() <= now.Unix() {
		return 0, fmt.Errorf("token expiration must be in the future")
	}
	return deadline.Unix(), nil
}

func (b *proxmoxBackend) createToken(ctx context.Context, s logical.Storage, role *proxmoxRoleEntry) (*proxmoxToken, error) {
	// Check all limits before any Proxmox API request.
	if err := validateRoleLifetime(role); err != nil {
		return nil, err
	}
	expire, err := nativeTokenExpiration(time.Now(), role.TTL)
	if err != nil {
		return nil, err
	}
	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if err := validateIssuerTarget(config, role.User, role.Realm); err != nil {
		return nil, err
	}
	client, err := b.getClient(ctx, s)
	if err != nil {
		return nil, err
	}

	// Issued tokens inherit only the dedicated Proxmox user's permissions.
	// Fine-grained per-token ACL assignment is not yet implemented.
	token, err := createToken(ctx, client, role.User, role.Realm, expire, false)
	if err != nil {
		return nil, fmt.Errorf("error creating Proxmox API token for role %q: %w", role.Name, err)
	}
	if token == nil {
		return nil, fmt.Errorf("Proxmox API returned no token")
	}
	return token, nil
}

func (b *proxmoxBackend) createUserCreds(ctx context.Context, req *logical.Request, role *proxmoxRoleEntry) (*logical.Response, error) {
	token, err := b.createToken(ctx, req.Storage, role)
	if err != nil {
		return nil, err
	}
	tokenIDFull := fmt.Sprintf("%s@%s!%s", role.User, role.Realm, token.TokenID)

	resp := b.Secret(proxmoxTokenType).Response(map[string]interface{}{
		"token_id":      token.TokenID,
		"token_id_full": tokenIDFull,
		"secret":        token.Secret,
	}, map[string]interface{}{
		"token_id": token.TokenID,
		"role":     role.Name, // retained solely for old-lease compatibility
		"user":     role.User, // immutable issuance identity for revocation
		"realm":    role.Realm,
	})

	resp.Secret.TTL = role.TTL
	// Vault lease renewals are disabled: extending the lease would otherwise
	// outlast the independently enforced Proxmox token expiration.
	resp.Secret.MaxTTL = role.TTL
	resp.Secret.Renewable = false
	return resp, nil
}

func (b *proxmoxBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	role, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}
	if role == nil {
		return nil, fmt.Errorf("role %q does not exist", name)
	}
	return b.createUserCreds(ctx, req, role)
}

const pathCredentialsHelpSyn = "Generate a finite-lived Proxmox API token from a role."
const pathCredentialsHelpDesc = "Each read creates a new non-renewable, natively expiring Proxmox API token."
