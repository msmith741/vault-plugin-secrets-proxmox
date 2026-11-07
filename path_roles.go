package proxmox

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	defaultRoleTTL    = 30 * time.Minute
	defaultRoleMaxTTL = time.Hour
	minRoleTTL        = time.Minute
	maxRoleTTL        = 24 * time.Hour
)

// validateRoleLifetime fails closed for legacy roles without explicit
// lifetimes. Issuance must never generate non-expiring Proxmox tokens.
func validateRoleLifetime(r *proxmoxRoleEntry) error {
	if r == nil || r.User == "" || r.Realm == "" {
		return fmt.Errorf("role requires a Proxmox user and realm")
	}
	if r.TTL < minRoleTTL {
		return fmt.Errorf("role ttl must be at least %s", minRoleTTL)
	}
	if r.MaxTTL < r.TTL {
		return fmt.Errorf("role max_ttl must be greater than or equal to ttl")
	}
	if r.MaxTTL > maxRoleTTL {
		return fmt.Errorf("role max_ttl must not exceed %s", maxRoleTTL)
	}
	return nil
}

type proxmoxRoleEntry struct {
	Name   string        `json:"name"`
	User   string        `json:"user"`
	Realm  string        `json:"realm"`
	TTL    time.Duration `json:"ttl"`
	MaxTTL time.Duration `json:"max_ttl"`

	//SeparatedPrivileges bool          `json:"separated_privileges"`
}

func (r *proxmoxRoleEntry) toResponseData() map[string]interface{} {
	respData := map[string]interface{}{
		"name":    r.Name,
		"user":    r.User,
		"realm":   r.Realm,
		"ttl":     r.TTL.Seconds(),
		"max_ttl": r.MaxTTL.Seconds(),

		//"separated_privileges": r.SeparatedPrivileges,
	}
	return respData
}

func pathRole(b *proxmoxBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "role/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role",
					Required:    true,
				},
				"user": {
					Type:        framework.TypeString,
					Description: "User in Proxmox this role will impersonate",
					Required:    true,
				},
				"realm": {
					Type:        framework.TypeString,
					Description: "Realm of the user in Proxmox, e.g. pam",
					Required:    true,
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Required finite lease lifetime; defaults to 30 minutes for new roles (minimum 1 minute).",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum allowed role lifetime; defaults to 1 hour for new roles (maximum 24 hours).",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRolesRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRolesDelete,
				},
			},
			HelpSynopsis:    pathRoleHelpSynopsis,
			HelpDescription: pathRoleHelpDescription,
		},
		{
			Pattern: "role/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRolesList,
				},
			},
			HelpSynopsis:    pathRoleListHelpSynopsis,
			HelpDescription: pathRoleListHelpDescription,
		},
	}
}

func (b *proxmoxBackend) getRole(ctx context.Context, s logical.Storage, name string) (*proxmoxRoleEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("missing role name")
	}

	entry, err := s.Get(ctx, "role/"+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var role proxmoxRoleEntry

	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}

	return &role, nil
}

func (b *proxmoxBackend) pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := b.getRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: entry.toResponseData(),
	}, nil
}

func setRole(ctx context.Context, s logical.Storage, name string, roleEntry *proxmoxRoleEntry) error {
	entry, err := logical.StorageEntryJSON("role/"+name, roleEntry)
	if err != nil {
		return err
	}

	if entry == nil {
		return fmt.Errorf("failed to create storage entry for role")
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

func (b *proxmoxBackend) pathRolesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing role name"), nil
	}

	roleEntry, err := b.getRole(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}

	if roleEntry == nil {
		roleEntry = &proxmoxRoleEntry{
			Name:   name.(string),
			TTL:    defaultRoleTTL,
			MaxTTL: defaultRoleMaxTTL,
		}
	}

	createOperation := (req.Operation == logical.CreateOperation)

	user, ok := d.GetOk("user")
	ok = ok && len(user.(string)) > 0
	if ok {
		roleEntry.User = user.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing user in role")
	}

	realm, ok := d.GetOk("realm")
	ok = ok && len(realm.(string)) > 0
	if ok {
		roleEntry.Realm = realm.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing realm in role")
	}

	if ttlRaw, ok := d.GetOk("ttl"); ok {
		roleEntry.TTL = time.Duration(ttlRaw.(int)) * time.Second
	}
	if maxTTLRaw, ok := d.GetOk("max_ttl"); ok {
		roleEntry.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	}

	if err := validateRoleLifetime(roleEntry); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if err := setRole(ctx, req.Storage, name.(string), roleEntry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *proxmoxBackend) pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "role/"+d.Get("name").(string))
	if err != nil {
		return nil, fmt.Errorf("error deleting role: %w", err)
	}

	return nil, nil
}

func (b *proxmoxBackend) pathRolesList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

const (
	pathRoleHelpSynopsis    = `Manages the Vault role for generating Proxmox API tokens.`
	pathRoleHelpDescription = `
This path allows you to read and write roles used to generate Proxmox tokens.
`

	pathRoleListHelpSynopsis    = `List the existing roles in Proxmox backend`
	pathRoleListHelpDescription = `Roles will be listed by the role name.`
)
