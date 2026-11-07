package proxmox

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	pxapi "github.com/Telmate/proxmox-api-go/proxmox"
)

type proxmoxClient struct {
	*pxapi.Client
}

func newClient(config *proxmoxConfig) (*proxmoxClient, error) {
	if config == nil {
		return nil, errors.New("client configuration was nil")
	}

	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid Proxmox issuer configuration: %w", err)
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if config.CACertPEM != "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM([]byte(config.CACertPEM)) {
			return nil, errors.New("Proxmox CA certificate is not valid PEM")
		}
		tlsConfig.RootCAs = roots
	}
	// Explicit legacy compatibility flag. Prefer ca_cert_pem.
	tlsConfig.InsecureSkipVerify = config.SkipCertValidation // #nosec G402 -- opt-in, administrator-only

	c, err := pxapi.NewClient(config.ApiURL, nil, config.HTTPHeaders, tlsConfig, config.ProxyServer, int(config.TaskTimeout.Seconds()), nil)
	if err != nil {
		return nil, err
	}

	if authMethod(config) == "password" {
		// Log in anew for every request operation; do not cache expiring PVE
		// tickets or persist the password outside Vault's protected storage.
		ctx, cancel := context.WithTimeout(context.Background(), config.TaskTimeout)
		defer cancel()
		if err := c.Login(ctx, config.User+"@"+config.Realm, config.Password, ""); err != nil {
			return nil, fmt.Errorf("Proxmox issuer login failed: %w", err)
		}
	} else {
		c.SetAPIToken(pxapi.ApiToken{
			ID: pxapi.ApiTokenID{
				User: pxapi.UserID{Name: config.User, Realm: config.Realm},
				TokenName: pxapi.ApiTokenName(config.ApiTokenID),
			},
			Secret: pxapi.ApiTokenSecret(config.ApiTokenSecret),
		})
	}
	return &proxmoxClient{c}, nil
}
