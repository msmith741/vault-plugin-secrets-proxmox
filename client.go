package proxmox

import (
	"crypto/tls"
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

	if config.ApiTokenID == "" {
		return nil, errors.New("client api token was not defined")
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	if !config.SkipCertValidation {
		tlsConfig = nil
	}

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
