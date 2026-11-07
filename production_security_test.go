package proxmox

import (
	"context"
	"encoding/pem"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func auditIssuer() *proxmoxConfig {
	return &proxmoxConfig{
		User: "hermes-observer",
		Realm: "pve",
		AuthMethod: "token",
		ApiTokenID: "bootstrap",
		ApiTokenSecret: "synthetic-only",
		ApiURL: "https://pve.example.invalid:8006/api2/json",
		TaskTimeout: 10 * time.Second,
	}
}

func TestSecurityAuditRejectsUnsafeIssuerOverrides(t *testing.T) {
	for _, test := range []struct {
		name string
		set func(*proxmoxConfig)
	}{
		{"disable TLS verification", func(c *proxmoxConfig) { c.SkipCertValidation = true }},
		{"custom Authorization header", func(c *proxmoxConfig) { c.HTTPHeaders = "Authorization,synthetic-sensitive-header" }},
		{"custom proxy server", func(c *proxmoxConfig) { c.ProxyServer = "http://proxy.example.invalid:8080" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := auditIssuer()
			test.set(cfg)
			if err := validateIssuanceConfig(cfg); err == nil {
				t.Fatal("unsafe issuer was accepted for new credential issuance")
			}
			b, storage := getTestBackend(t)
			fields := map[string]interface{}{
				"user": cfg.User, "realm": cfg.Realm, "auth_method": "token",
				"token_id": cfg.ApiTokenID, "token_secret": cfg.ApiTokenSecret,
				"proxmox_url": cfg.ApiURL, "timeout": 10,
				"insecure_skip_tls_verify": cfg.SkipCertValidation,
				"http_headers": cfg.HTTPHeaders, "proxy_server": cfg.ProxyServer,
			}
			res, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.CreateOperation,
				Path: "config", Data: fields, Storage: storage,
			})
			if err == nil && (res == nil || !res.IsError()) {
				t.Fatal("unsafe Vault config write accepted")
			}
			stored, err := storage.Get(context.Background(), "config")
			if err != nil || stored != nil {
				t.Fatal("failed issuer write changed Vault storage")
			}
		})
	}
}

func TestSecurityAuditRedactsHistoricalHeadersAndProxy(t *testing.T) {
	b, storage := getTestBackend(t)
	cfg := auditIssuer()
	cfg.HTTPHeaders = "Authorization,synthetic-secret-here"
	cfg.ProxyServer = "http://synthetic-user:synthetic-pass@proxy.example.invalid:8080"
	raw, err := logical.StorageEntryJSON(configStoragePath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	res, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "config", Storage: storage,
	})
	if err != nil || res == nil || res.IsError() {
		t.Fatalf("redacted config read failed: %v", err)
	}
	for _, field := range []string{"http_headers", "proxy_server"} {
		value := res.Data[field].(string)
		if !strings.Contains(value, "redacted") || strings.Contains(value, "synthetic-") {
			t.Errorf("sensitive legacy %s was exposed: %q", field, value)
		}
	}
	if res.Data["token_secret"] != nil || res.Data["password"] != nil {
		t.Fatal("issuer credential was exposed in config read")
	}
}

func TestSecurityAuditIssuerIdentityEncoding(t *testing.T) {
	for _, test := range []struct {
		user, realm string
		allowed bool
	}{
		{"hermes-observer", "pve", true},
		{"reader.workload_1", "ldap-dev", true},
		{"a+b", "pve", true},
		{"user@pve", "pve", false},
		{"user/other", "pve", false},
		{"user", "pve/../../root", false},
		{"user", "pve!root", false},
		{"user\nheader:bad", "pve", false},
		{"", "pve", false},
		{"user", "", false},
	} {
		err := validatePVEIdentity(test.user, test.realm)
		if (err == nil) != test.allowed {
			t.Errorf("user=%q realm=%q allowed=%v err=%v", test.user, test.realm, test.allowed, err)
		}
	}
}

func TestSecurityAuditProxmoxRedirectNeverForwardsIssuerAuth(t *testing.T) {
	var redirected atomic.Int32
	dst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer dst.Close()

	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dst.URL+"/capture", http.StatusFound)
	}))
	defer source.Close()
	cfg := auditIssuer()
	cfg.ApiURL = source.URL + "/api2/json"
	cfg.CACertPEM = string(tlsCertPEM(t, source.TLS))
	client, err := newClientWithContext(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to create test issuer: %v", err)
	}
	_, err = createToken(context.Background(), client, cfg.User, cfg.Realm,
		time.Now().Add(5*time.Minute).Unix(), false)
	if err == nil {
		t.Fatal("redirected API call unexpectedly created token")
	}
	if redirected.Load() != 0 {
		t.Fatal("HTTP redirect forwarded issuer credentials to another endpoint")
	}
}

func tlsCertPEM(t *testing.T, c *tls.Config) []byte {
	t.Helper()
	if len(c.Certificates) == 0 {
		t.Fatal("test TLS endpoint has no certificates")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificates[0].Certificate[0]})
}
