package proxmox

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestRoleLifetimeValidation(t *testing.T) {
	cases := []struct {
		name string
		ttl  time.Duration
		max  time.Duration
		ok   bool
	}{
		{"default", 30 * time.Minute, time.Hour, true},
		{"minute", time.Minute, time.Minute, true},
		{"24 hours", time.Hour, 24 * time.Hour, true},
		{"legacy zero expiry", 0, time.Hour, false},
		{"missing max expiry", time.Minute, 0, false},
		{"too short", time.Second, time.Hour, false},
		{"ttl above max", time.Hour, 30 * time.Minute, false},
		{"unbounded max", time.Hour, 25 * time.Hour, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRoleLifetime(&proxmoxRoleEntry{User: "vm", Realm: "pve", TTL: tc.ttl, MaxTTL: tc.max})
			if (err == nil) != tc.ok {
				t.Fatalf("validateRoleLifetime() error = %v, want valid=%v", err, tc.ok)
			}
		})
	}
}

func TestRoleDefaultsAndRejectsZeroTTL(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/new-role",
		Storage:   storage,
		Data:      map[string]interface{}{"user": "vm", "realm": "pve"},
	}
	response, err := b.HandleRequest(ctx, req)
	if err != nil || response != nil {
		t.Fatalf("create role failed: response=%v err=%v", response, err)
	}
	role, err := b.getRole(ctx, storage, "new-role")
	if err != nil || role == nil {
		t.Fatalf("read role failed: role=%v err=%v", role, err)
	}
	if role.TTL != defaultRoleTTL || role.MaxTTL != defaultRoleMaxTTL {
		t.Fatalf("unexpected defaults: ttl=%s max=%s", role.TTL, role.MaxTTL)
	}
	// Simulate an existing role written by the older upstream plugin.
	role.TTL = 0
	if err := setRole(ctx, storage, "new-role", role); err != nil {
		t.Fatal(err)
	}
	_, err = b.createToken(ctx, storage, role)
	if err == nil {
		t.Fatal("zero-TTL legacy role should fail before contacting Proxmox")
	}
}

func TestNativeTokenExpirationAlwaysFinite(t *testing.T) {
	now := time.Date(2026, 11, 7, 10, 30, 0, 550000000, time.UTC)
	for _, ttl := range []time.Duration{time.Minute, 30 * time.Minute, 24 * time.Hour} {
		expires, err := nativeTokenExpiration(now, ttl)
		if err != nil {
			t.Fatal(err)
		}
		deadline := time.Unix(expires, 0)
		if deadline.Before(now.Add(ttl)) || deadline.After(now.Add(ttl+time.Second)) {
			t.Fatalf("expiry %s outside expected range", deadline)
		}
	}
	for _, ttl := range []time.Duration{0, time.Second, 25 * time.Hour} {
		if _, err := nativeTokenExpiration(now, ttl); err == nil {
			t.Fatalf("expected rejection of ttl %s", ttl)
		}
	}
}

func TestRevocationIdentitySurvivesRoleChanges(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()
	data := map[string]interface{}{
		"token_id": "vault-123",
		"user":     "tofu-vm",
		"realm":    "pve",
		"role":     "vm-deployer",
	}
	// The role was removed after issuance; new leases still revoke correctly.
	user, realm, token, err := b.revocationIdentity(ctx, storage, data)
	if err != nil || user != "tofu-vm" || realm != "pve" || token != "vault-123" {
		t.Fatalf("revocation snapshot mismatch: %s %s %s %v", user, realm, token, err)
	}
	// Old leases can fall back to their role while it still exists.
	if err := setRole(ctx, storage, "legacy", &proxmoxRoleEntry{
		Name: "legacy", User: "tofu-images", Realm: "pve",
		TTL: defaultRoleTTL, MaxTTL: defaultRoleMaxTTL,
	}); err != nil {
		t.Fatal(err)
	}
	user, realm, _, err = b.revocationIdentity(ctx, storage, map[string]interface{}{
		"token_id": "legacy-123", "role": "legacy",
	})
	if err != nil || user != "tofu-images" || realm != "pve" {
		t.Fatalf("legacy lookup: %q %q %v", user, realm, err)
	}
	if _, _, _, err = b.revocationIdentity(ctx, storage, map[string]interface{}{
		"token_id": "legacy-123", "role": "missing",
	}); err == nil {
		t.Fatal("missing legacy role should fail closed")
	}
	if _, _, _, err = b.revocationIdentity(ctx, storage, map[string]interface{}{
		"token_id": "partial", "user": "vm",
	}); err == nil {
		t.Fatal("partial issuance identity must fail closed")
	}
}

func TestCredentialLeaseIsNotRenewable(t *testing.T) {
	b, _ := getTestBackend(t)
	if b.proxmoxToken().Renew != nil {
		t.Fatal("renewal callback must be absent unless Proxmox expiration is extended atomically")
	}
}
