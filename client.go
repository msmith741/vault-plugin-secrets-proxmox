package proxmox

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"errors"

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

	c.SetAPIToken(pxapi.ApiToken{
		ID: pxapi.ApiTokenID{
			User:      pxapi.UserID{Name: config.User, Realm: config.Realm},
			TokenName: pxapi.ApiTokenName(config.ApiTokenID),
		},
		Secret: pxapi.ApiTokenSecret(config.ApiTokenSecret),
	})

	return &proxmoxClient{c}, nil
}
