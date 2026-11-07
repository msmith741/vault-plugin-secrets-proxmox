package proxmox

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	pxapi "github.com/Telmate/proxmox-api-go/proxmox"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	proxmoxTokenType = "proxmox_api_token"
)

type proxmoxToken struct {
	TokenID string `json:"token_id"`
	Secret  string `json:"secret"`
}

func (b *proxmoxBackend) proxmoxToken() *framework.Secret {
	return &framework.Secret{
		Type: proxmoxTokenType,
		Fields: map[string]*framework.FieldSchema{
			"token_id": {
				Type:        framework.TypeString,
				Description: "The user-specific token identifier (excl user and realm)",
			},
			"secret": {
				Type:        framework.TypeString,
				Description: "The secret API token value used for authentication",
			},
		},
		Revoke: b.tokenRevoke,
	}
}

// revocationIdentity prefers the user and realm captured when the token
// was issued. This remains correct even if the Vault role is updated or
// deleted after issuance. Older leases fall back to the original role lookup.
func (b *proxmoxBackend) revocationIdentity(
	ctx context.Context, storage logical.Storage, data map[string]interface{},
) (string, string, string, error) {
	id, ok := data["token_id"].(string)
	if !ok || id == "" {
		return "", "", "", fmt.Errorf("lease is missing token_id")
	}
	user, userOK := data["user"].(string)
	realm, realmOK := data["realm"].(string)
	if userOK || realmOK {
		if user == "" || realm == "" {
			return "", "", "", fmt.Errorf("lease has incomplete Proxmox identity")
		}
		return user, realm, id, nil
	}
	// Existing unexpired leases from the upstream plugin contain only
	// the role name. They can still be revoked while that role exists.
	roleName, ok := data["role"].(string)
	if !ok || roleName == "" {
		return "", "", "", fmt.Errorf("legacy lease is missing role")
	}
	role, err := b.getRole(ctx, storage, roleName)
	if err != nil {
		return "", "", "", err
	}
	if role == nil || role.User == "" || role.Realm == "" {
		return "", "", "", fmt.Errorf("cannot revoke legacy token: role %q is missing", roleName)
	}
	return role.User, role.Realm, id, nil
}

func (b *proxmoxBackend) tokenRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if req.Secret == nil {
		return nil, fmt.Errorf("cannot revoke token: missing lease secret")
	}
	user, realm, tokenID, err := b.revocationIdentity(ctx, req.Storage, req.Secret.InternalData)
	if err != nil {
		return nil, err
	}
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting client: %w", err)
	}
	if err := deleteToken(ctx, client, user, realm, tokenID); err != nil {
		return nil, fmt.Errorf("Proxmox token revoke failed; check Proxmox audit logs")
	}
	return nil, nil
}

func createToken(ctx context.Context, c *proxmoxClient, user string, realm string, expire int64, privsep bool) (*proxmoxToken, error) {
	if len(user) == 0 {
		return nil, errors.New("error creating token: no user provided")
	}

	if len(realm) == 0 {
		return nil, errors.New("error creating token: no realm provided")
	}

	rawTokenId := uuid.New().String()
	// Proxmox API wants token IDs to start with a latter (regexp (?^:[A-Za-z][A-Za-z0-9\.\-_]+)) so lets remap the entire thing
	tokenId := strings.NewReplacer("0", "g", "1", "h", "2", "i", "3", "j", "4", "k", "5", "l", "6", "m", "7", "n", "8", "o", "9", "p").Replace(rawTokenId)

	if expire <= time.Now().Unix() {
		return nil, errors.New("refusing to create a Proxmox token without a future native expiration")
	}
	comment := "Managed by Vault"
	expiration := uint(expire)
	secret, err := c.New().ApiToken.Create(ctx, pxapi.UserID{Name: user, Realm: realm}, pxapi.ApiTokenConfig{
		Name:                pxapi.ApiTokenName(tokenId),
		Comment:             &comment,
		Expiration:          &expiration,
		PrivilegeSeparation: &privsep,
	})
	if err != nil {
		return nil, fmt.Errorf("error from API when creating token: %w", err)
	}

	return &proxmoxToken{
		TokenID: tokenId,
		Secret:  secret.String(),
	}, nil
}

func deleteToken(ctx context.Context, c *proxmoxClient, user string, realm string, tokenID string) error {
	_, err := c.New().ApiToken.Delete(ctx, pxapi.ApiTokenID{
		User:      pxapi.UserID{Name: user, Realm: realm},
		TokenName: pxapi.ApiTokenName(tokenID),
	})
	return err
}
