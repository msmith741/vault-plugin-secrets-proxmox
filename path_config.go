package proxmox

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	neturl "net/url"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configStoragePath = "config"
)

type proxmoxConfig struct {
	User               string        `json:"user"`
	Realm              string        `json:"realm"`
	ApiTokenID         string        `json:"token_id"`
	ApiTokenSecret     string        `json:"token_secret"`
	AuthMethod         string        `json:"auth_method"`
	Password           string        `json:"password"`
	ApiURL             string        `json:"proxmox_url"`
	SkipCertValidation bool          `json:"insecure_skip_tls_verify"`
	HTTPHeaders        string        `json:"http_headers"`
	ProxyServer        string        `json:"proxy_server"`
	TaskTimeout        time.Duration `json:"timeout"`
	CACertPEM          string        `json:"ca_cert_pem"`
}

// authMethod preserves decoding of existing token-backed mount configs.
// New production mounts should use password authentication with a dedicated
// non-admin PVE-realm user (the same identity that owns issued tokens).
func authMethod(c *proxmoxConfig) string {
	if c != nil && c.AuthMethod != "" {
		return c.AuthMethod
	}
	return "token"
}

// No cross-user token issuance is permitted by this plugin. Granting
// PVEUserAdmin at /access permits minting root@pam tokens on PVE 9.2.2.
func validateIssuerTarget(c *proxmoxConfig, user, realm string) error {
	if c == nil {
		return fmt.Errorf("issuer is not configured")
	}
	if c.User != user || c.Realm != realm {
		return fmt.Errorf("cross-user token issuance is disabled: configure a separate Vault mount with issuer matching the target user")
	}
	if c.User == "root" && c.Realm == "pam" {
		return fmt.Errorf("root@pam issuer is prohibited for dynamic token issuance")
	}
	return nil
}

// Validate the privileged issuer endpoint before it can be persisted.
func validateConfig(c *proxmoxConfig) error {
	if c == nil {
		return fmt.Errorf("issuer configuration is missing")
	}
	if strings.TrimSpace(c.User) == "" || strings.TrimSpace(c.Realm) == "" {
		return fmt.Errorf("issuer user and realm must be set")
	}
	switch authMethod(c) {
	case "token":
		if strings.TrimSpace(c.ApiTokenID) == "" || strings.TrimSpace(c.ApiTokenSecret) == "" {
			return fmt.Errorf("issuer token_id and token_secret must be set for token authentication")
		}
		if c.Password != "" {
			return fmt.Errorf("password and token authentication must not be combined")
		}
	case "password":
		if c.Password == "" {
			return fmt.Errorf("issuer password is required for password authentication")
		}
		if c.ApiTokenID != "" || c.ApiTokenSecret != "" {
			return fmt.Errorf("issuer API token credentials must not be combined with password authentication")
		}
	default:
		return fmt.Errorf("auth_method must be token or password")
	}
	endpoint, err := neturl.Parse(c.ApiURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" ||
		endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		endpoint.Path != "/api2/json" || endpoint.Opaque != "" {
		return fmt.Errorf("proxmox_url must be an HTTPS URL ending in /api2/json, without credentials, query or fragment")
	}
	if c.TaskTimeout < time.Second || c.TaskTimeout > 5*time.Minute {
		return fmt.Errorf("timeout must be between 1 and 300 seconds")
	}
	if c.CACertPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(c.CACertPEM)) {
			return fmt.Errorf("ca_cert_pem must contain at least one PEM certificate")
		}
	}
	return nil
}

func pathConfig(b *proxmoxBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"user": {
				Type:        framework.TypeString,
				Description: "User that configured API token is for, e.g. root",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "User",
				},
			},
			"realm": {
				Type:        framework.TypeString,
				Description: "Realm of the user that configured API token is for, e.g. pam",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Realm",
				},
			},
			"auth_method": {
				Type: framework.TypeString,
				Description: "Issuer authentication: password (same-user self-service, recommended) or token (same-user only). Existing token mounts remain compatible.",
			},
			"password": {
				Type: framework.TypeString,
				Description: "Secret password for dedicated Proxmox user, used for per-request session tickets. Required with auth_method=password.",
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Issuer password",
					Sensitive: true,
				},
			},
			"token_id": {
				Type:        framework.TypeString,
				Description: "API Token ID for auth_method=token (without username and realm).",
				Required:    false,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "API Token ID",
					Sensitive: true,
				},
			},
			"token_secret": {
				Type:        framework.TypeString,
				Description: "API token secret for auth_method=token; do not set with password authentication.",
				Required:    false,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "API Token Secret",
					Sensitive: true,
				},
			},
			"proxmox_url": {
				Type:        framework.TypeString,
				Description: "https://host.fqdn:8006/api2/json",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "API Endpoint URL",
				},
			},
			"insecure_skip_tls_verify": {
				Type:        framework.TypeBool,
				Description: "By default, every TLS connection is verified to be secure. This option allows Vault to proceed and operate on servers considered insecure. For example if you're connecting to a remote host and you do not have the CA cert that issued the proxmox api url's certificate.",
				Required:    false,
				Default:     false,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Skip TLS Verify",
				},
			},
			"ca_cert_pem": {
				Type:        framework.TypeString,
				Description: "Optional PEM-encoded certificate authorities for the Proxmox HTTPS endpoint.",
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Proxmox CA certificates",
					Sensitive: true,
				},
			},
			"http_headers": {
				Type:        framework.TypeString,
				Description: "Set custom http headers e.g. Key,Value,Key1,Value1",
				Required:    false,
				Default:     "",
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "HTTP Headers",
				},
			},
			"proxy_server": {
				Type:        framework.TypeString,
				Description: "Proxy Server passed to Api client(useful for debugging). Syntax: http://proxy:port",
				Required:    false,
				Default:     "",
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Proxy Server",
				},
			},
			"timeout": {
				Type:        framework.TypeInt,
				Description: "How many seconds to wait for operations for api-client, default is 2m",
				Required:    false,
				Default:     120,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Task Timeout",
				},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
			},
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    pathConfigHelpSynopsis,
		HelpDescription: pathConfigHelpDescription,
	}
}

func (b *proxmoxBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}

func (b *proxmoxBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	c, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"user":                     c.User,
			"realm":                    c.Realm,
			"token_id":                 c.ApiTokenID,
			"auth_method":              authMethod(c),
			"proxmox_url":              c.ApiURL,
			"insecure_skip_tls_verify": c.SkipCertValidation,
			"http_headers":             c.HTTPHeaders,
			"proxy_server":             c.ProxyServer,
			"timeout":                  int(c.TaskTimeout.Seconds()),
		},
	}, nil
}

func (b *proxmoxBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	createOperation := (req.Operation == logical.CreateOperation)

	if config == nil {
		if !createOperation {
			return nil, errors.New("config not found during update operation")
		}
		config = new(proxmoxConfig)
	}

	if user, ok := data.GetOk("user"); ok {
		config.User = user.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing user in configuration")
	}

	if realm, ok := data.GetOk("realm"); ok {
		config.Realm = realm.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing realm in configuration")
	}

	if mode, ok := data.GetOk("auth_method"); ok {
		next := mode.(string)
		if next != authMethod(config) {
			switch next {
			case "password":
				config.ApiTokenID = ""
				config.ApiTokenSecret = ""
			case "token":
				config.Password = ""
			}
		}
		config.AuthMethod = next
	}
	if password, ok := data.GetOk("password"); ok {
		config.Password = password.(string)
	}
	if tokenID, ok := data.GetOk("token_id"); ok {
		config.ApiTokenID = tokenID.(string)
	}
	if tokenSecret, ok := data.GetOk("token_secret"); ok {
		config.ApiTokenSecret = tokenSecret.(string)
	}

	apiURL, ok := data.GetOk("proxmox_url")
	ok = ok && len(apiURL.(string)) > 0
	if ok {
		config.ApiURL = apiURL.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing proxmox_url in configuration")
	}

	if skipCert, ok := data.GetOk("insecure_skip_tls_verify"); ok {
		config.SkipCertValidation = skipCert.(bool)
	} else if !ok && createOperation {
		config.SkipCertValidation = data.GetDefaultOrZero("insecure_skip_tls_verify").(bool)
	}

	if httpHeaders, ok := data.GetOk("http_headers"); ok {
		config.HTTPHeaders = httpHeaders.(string)
	} else if !ok && createOperation {
		config.HTTPHeaders = data.GetDefaultOrZero("http_headers").(string)
	}

	if proxyServer, ok := data.GetOk("proxy_server"); ok {
		config.ProxyServer = proxyServer.(string)
	} else if !ok && createOperation {
		config.ProxyServer = data.GetDefaultOrZero("proxy_server").(string)
	}

	if ca, ok := data.GetOk("ca_cert_pem"); ok {
		config.CACertPEM = ca.(string)
	}
	if taskTimeout, ok := data.GetOk("timeout"); ok {
		config.TaskTimeout = time.Duration(taskTimeout.(int)) * time.Second
	} else if !ok && createOperation {
		config.TaskTimeout = time.Duration(data.GetDefaultOrZero("timeout").(int)) * time.Second
	}

	if err := validateConfig(config); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.reset()

	return nil, nil
}

func (b *proxmoxBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, configStoragePath)

	if err == nil {
		b.reset()
	}

	return nil, err
}

func getConfig(ctx context.Context, s logical.Storage) (*proxmoxConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := new(proxmoxConfig)
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading root configration: %w", err)
	}

	return config, nil
}

const pathConfigHelpSynopsis = `Configure the Proxmox backend.`

const pathConfigHelpDescription = `
The Proxmox secrets backend requires credentials for managing
API tokens using the Proxmox API.

You must sign in to your Proxmox cluster and create an API token and give that token to this secrets engine,
which will be used to mint new short lived tokens.`
