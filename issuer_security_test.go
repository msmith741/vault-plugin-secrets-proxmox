package proxmox

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestSameUserIssuerSecurityBoundary(t *testing.T) {
	cfg := &proxmoxConfig{User: "deployer", Realm: "pve"}
	for _, tc := range []struct {
		name, user, realm string
		allowed           bool
	}{
		{"same identity", "deployer", "pve", true},
		{"different user", "images", "pve", false},
		{"different realm", "deployer", "pam", false},
		{"root target", "root", "pam", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateIssuerTarget(cfg, tc.user, tc.realm)
			if (err == nil) != tc.allowed {
				t.Fatalf("validateIssuerTarget(%s@%s) err = %v", tc.user, tc.realm, err)
			}
		})
	}
	cfg.User, cfg.Realm = "root", "pam"
	if err := validateIssuerTarget(cfg, "root", "pam"); err == nil {
		t.Fatal("root@pam dynamic issuance must be prohibited")
	}
}

func TestIssuerAuthenticationModesAndMutualExclusion(t *testing.T) {
	cfg := &proxmoxConfig{
		User: "deployer", Realm: "pve",
		AuthMethod: "password", Password: "synthetic-password",
		ApiURL:      "https://pve.example.invalid:8006/api2/json",
		TaskTimeout: 30 * time.Second,
	}
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("valid per-user password issuer rejected: %v", err)
	}
	cfg.ApiTokenID = "legacy"
	cfg.ApiTokenSecret = "synthetic-token-secret"
	if err := validateConfig(cfg); err == nil {
		t.Fatal("password + token combination must be rejected")
	}
	cfg.ApiTokenID, cfg.ApiTokenSecret = "", ""
	cfg.Password = ""
	if err := validateConfig(cfg); err == nil {
		t.Fatal("empty issuer password must be rejected")
	}
	cfg.Password = "synthetic-password"
	cfg.AuthMethod = "unexpected"
	if err := validateConfig(cfg); err == nil {
		t.Fatal("unknown auth mode must be rejected")
	}
	cfg.AuthMethod = "token"
	cfg.Password = ""
	cfg.ApiTokenID, cfg.ApiTokenSecret = "bootstrap", "synthetic-token-secret"
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("legacy token mode must remain valid for revoking old leases: %v", err)
	}
	cfg.AuthMethod = ""
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("previously stored token configuration must still decode: %v", err)
	}
}

func TestVaultPasswordIssuerConfigDoesNotExposePassword(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()
	data := map[string]interface{}{
		"auth_method": "password", "user": "workload", "realm": "pve",
		"password":    "synthetic-not-real",
		"proxmox_url": "https://pve.example.invalid:8006/api2/json",
	}
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: storage, Data: data,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("issuer config write failed: resp=%v err=%v", resp, err)
	}
	read, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "config", Storage: storage,
	})
	if err != nil || read == nil || read.Data["auth_method"] != "password" {
		t.Fatalf("issuer config read failed: resp=%v err=%v", read, err)
	}
	if _, ok := read.Data["password"]; ok {
		t.Fatal("issuer password leaked in Vault config read")
	}
	// Rotation must update the secret without exposing it in the response.
	rotated, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: storage,
		Data: map[string]interface{}{"password": "rotated-synthetic-only"},
	})
	if err != nil || (rotated != nil && rotated.IsError()) {
		t.Fatalf("password rotation failed: response=%v error=%v", rotated, err)
	}
	afterRotation, err := getConfig(ctx, storage)
	if err != nil || afterRotation == nil || afterRotation.Password != "rotated-synthetic-only" {
		t.Fatalf("password rotation was not stored")
	}
	// Authentication-mode changes must erase secrets belonging to the old mode.
	switched, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: storage,
		Data: map[string]interface{}{
			"auth_method": "token", "token_id": "bootstrap",
			"token_secret": "synthetic-token",
		},
	})
	if err != nil || (switched != nil && switched.IsError()) {
		t.Fatalf("password to token mode switch failed: response=%v error=%v", switched, err)
	}
	tokenConfig, err := getConfig(ctx, storage)
	if err != nil || tokenConfig.Password != "" || authMethod(tokenConfig) != "token" {
		t.Fatalf("token mode retained a password or has wrong authentication mode")
	}
	switchedBack, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: storage,
		Data: map[string]interface{}{
			"auth_method": "password", "password": "new-synthetic-password",
		},
	})
	if err != nil || (switchedBack != nil && switchedBack.IsError()) {
		t.Fatalf("token to password switch failed: response=%v error=%v", switchedBack, err)
	}
	passwordConfig, err := getConfig(ctx, storage)
	if err != nil || passwordConfig.ApiTokenID != "" ||
		passwordConfig.ApiTokenSecret != "" || passwordConfig.Password != "new-synthetic-password" {
		t.Fatalf("password mode retained API-token credentials or wrong password")
	}
	cfg, err := getConfig(ctx, storage)
	if err != nil || cfg == nil || cfg.Password != "new-synthetic-password" {
		t.Fatal("issuer password was not held in Vault secret storage")
	}
}

func TestCrossUserCredentialReadFailsBeforeNetwork(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()
	cfg := &proxmoxConfig{
		User: "issuer", Realm: "pve", ApiTokenID: "bootstrap",
		ApiTokenSecret: "synthetic-only", AuthMethod: "token",
		ApiURL:      "https://nonexistent.example.invalid:8006/api2/json",
		TaskTimeout: 5 * time.Second,
	}
	entry, err := logical.StorageEntryJSON(configStoragePath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(ctx, entry); err != nil {
		t.Fatal(err)
	}
	role := &proxmoxRoleEntry{
		Name: "unsafe", User: "workload", Realm: "pve",
		TTL: 2 * time.Minute, MaxTTL: 5 * time.Minute,
		InheritUserPrivileges: true,
	}
	if err := setRole(ctx, storage, "unsafe", role); err != nil {
		t.Fatal(err)
	}
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/unsafe", Storage: storage,
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatalf("cross-user token issuance unexpectedly accepted: %#v", resp)
	}
	if err != nil && !strings.Contains(err.Error(), "cross-user") {
		t.Fatalf("wrong fail-closed reason: %v", err)
	}
}
