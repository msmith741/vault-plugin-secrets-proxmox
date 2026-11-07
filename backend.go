package proxmox

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type proxmoxBackend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *proxmoxClient
}

func backend() *proxmoxBackend {
	var b = proxmoxBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{},
			SealWrapStorage: []string{
				"config",
				"role/*",
			},
		},
		Paths: framework.PathAppend(
			pathRole(&b),
			[]*framework.Path{
				pathConfig(&b),
				pathCredentials(&b),
			},
		),
		Secrets: []*framework.Secret{
			b.proxmoxToken(),
		},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}
	return &b
}

func (b *proxmoxBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

func (b *proxmoxBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

func (b *proxmoxBackend) getClient(ctx context.Context, storage logical.Storage) (*proxmoxClient, error) {
	cfg, err := getConfig(ctx, storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, fmt.Errorf("Proxmox issuer is not configured")
	}
	if authMethod(cfg) == "password" {
		// Fresh ticket avoids reusing an expired PVE login session.
		return newClientWithContext(ctx, cfg)
	}
	b.lock.RLock()
	cached := b.client
	b.lock.RUnlock()
	if cached != nil {
		return cached, nil
	}

	b.lock.Lock()
	defer b.lock.Unlock()
	// Recheck after acquiring the write lock. Concurrent reads must not
	// overwrite a newly initialized client.
	if b.client != nil {
		return b.client, nil
	}
	config, err := getConfig(ctx, storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, fmt.Errorf("Proxmox issuer is not configured")
	}
	client, err := newClientWithContext(ctx, config)
	if err != nil {
		return nil, err
	}
	b.client = client
	return client, nil
}

const backendHelp = `
The Proxmox secrets backend dynamically generates API tokens for connecting to a Proxmox API endpoint.
After mounting this backend, credentials to manage Proxmox API tokens must be configured with the "config/" endpoints.
`
