package proxmox

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	pxapi "github.com/Telmate/proxmox-api-go/proxmox"
)

type proxmoxClient struct {
	*pxapi.Client
}

func newClient(config *proxmoxConfig) (*proxmoxClient, error) {
	return newClientWithContext(context.Background(), config)
}

func newClientWithContext(ctx context.Context, config *proxmoxConfig) (*proxmoxClient, error) {
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

	// Never allow Proxmox redirects to forward issuer credentials to a
	// different endpoint, even if a redirect targets a related hostname.
	var proxy func(*http.Request) (*url.URL, error)
	if config.ProxyServer != "" {
		parsed, err := url.ParseRequestURI(config.ProxyServer)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return nil, errors.New("invalid legacy Proxmox proxy URL")
		}
		proxy = http.ProxyURL(parsed)
	}
	httpClient := &http.Client{
		Timeout: config.TaskTimeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			DisableCompression: true,
			Proxy: proxy,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	c, err := pxapi.NewClient(config.ApiURL, httpClient, config.HTTPHeaders, tlsConfig, config.ProxyServer, int(config.TaskTimeout.Seconds()), nil)
	if err != nil {
		return nil, err
	}

	if authMethod(config) == "password" {
		// Log in anew for every request operation; do not cache expiring PVE
		// tickets or persist the password outside Vault's protected storage.
		loginCtx, cancel := context.WithTimeout(ctx, config.TaskTimeout)
		defer cancel()
		if err := c.Login(loginCtx, config.User+"@"+config.Realm, config.Password, ""); err != nil {
			// Upstream client errors may contain raw server response details.
			// Do not return issuer secrets to Vault callers or audit logs.
			return nil, errors.New("Proxmox issuer authentication failed; check endpoint, TLS, identity and audit logs")
		}
	} else {
		c.SetAPIToken(pxapi.ApiToken{
			ID: pxapi.ApiTokenID{
				User:      pxapi.UserID{Name: config.User, Realm: config.Realm},
				TokenName: pxapi.ApiTokenName(config.ApiTokenID),
			},
			Secret: pxapi.ApiTokenSecret(config.ApiTokenSecret),
		})
	}
	return &proxmoxClient{c}, nil
}
