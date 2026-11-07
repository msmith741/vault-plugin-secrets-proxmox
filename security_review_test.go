package proxmox

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestIssuerMustBeConfiguredBeforeUse(t *testing.T) {
	b, storage := getTestBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "config", Storage: storage,
	})
	if err != nil || resp != nil {
		t.Fatalf("unconfigured issuer read: response=%v error=%v", resp, err)
	}
	if _, err := b.getClient(context.Background(), storage); err == nil {
		t.Fatal("unconfigured issuer created an API client")
	}
}

func TestInvalidIssuerConfigNotPersisted(t *testing.T) {
	cases := []struct {
		name, field string
		value       interface{}
	}{
		{"HTTP", "proxmox_url", "http://pve.invalid:8006/api2/json"},
		{"wrong path", "proxmox_url", "https://pve.invalid:8006/"},
		{"userinfo", "proxmox_url", "https://name:password@pve.invalid:8006/api2/json"},
		{"query", "proxmox_url", "https://pve.invalid:8006/api2/json?x=1"},
		{"fragment", "proxmox_url", "https://pve.invalid:8006/api2/json#fragment"},
		{"empty secret", "token_secret", ""},
		{"bad CA", "ca_cert_pem", "not-pem"},
		{"zero timeout", "timeout", 0},
		{"oversized timeout", "timeout", 301},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, storage := getTestBackend(t)
			fields := map[string]interface{}{
				"user": "issuer", "realm": "pve", "token_id": "bootstrap",
				"token_secret": "mock-only-secret",
				"proxmox_url":  "https://pve.invalid:8006/api2/json",
			}
			fields[tc.field] = tc.value
			res, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.CreateOperation, Path: "config", Data: fields, Storage: storage,
			})
			if err == nil && (res == nil || !res.IsError()) {
				t.Fatalf("accepted invalid issuer settings: response=%v", res)
			}
			stored, err := getConfig(context.Background(), storage)
			if err != nil || stored != nil {
				t.Fatalf("invalid issuer persisted: config=%v err=%v", stored, err)
			}
		})
	}
}

func TestRolesRequireExplicitPrivilegeInheritance(t *testing.T) {
	role := proxmoxRoleEntry{
		User: "tofu-vm", Realm: "pve", TTL: 30 * time.Minute, MaxTTL: time.Hour,
	}
	if err := validateRoleLifetime(&role); err == nil {
		t.Fatal("unacknowledged privilege inheritance permitted")
	}
	role.InheritUserPrivileges = true
	if err := validateRoleLifetime(&role); err != nil {
		t.Fatalf("explicitly acknowledged role rejected: %v", err)
	}
	role.User, role.Realm = "root", "pam"
	if err := validateRoleLifetime(&role); err == nil {
		t.Fatal("root@pam API token issuance permitted")
	}
}

// This mock is deliberately not a live Proxmox integration test. It exercises
// Telmate's typed API client, TLS verification, expiry and delete semantics.
func TestProxmoxTokenLifecycleAgainstMockTLSAPI(t *testing.T) {
	var mu sync.Mutex
	var createCalls, deleteCalls int
	var issuedID string
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/access/users/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "PVEAPIToken=tofu-vm@pve!bootstrap=mock-issuer-secret" {
			http.Error(w, "unexpected issuer", http.StatusUnauthorized)
			return
		}
		prefix := "/api2/json/access/users/tofu-vm@pve/token/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.Error(w, "unexpected Proxmox path", http.StatusNotFound)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, prefix)
		if id == "" {
			http.Error(w, "missing ID", http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodPost:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "invalid form body", http.StatusBadRequest)
				return
			}
			params, err := neturl.ParseQuery(string(body))
			if err != nil {
				http.Error(w, "invalid form encoding", http.StatusBadRequest)
				return
			}
			exp, err := strconv.ParseInt(params.Get("expire"), 10, 64)
			if err != nil || exp <= time.Now().Unix() {
				t.Logf("missing expiry, form params=%v; content-type=%q", params, r.Header.Get("Content-Type"))
				http.Error(w, "native expiration missing", http.StatusBadRequest)
				return
			}
			if params.Get("privsep") != "0" {
				t.Logf("unexpected privilege mode: %q, form params=%v", params.Get("privsep"), params)
				http.Error(w, "unexpected privilege mode", http.StatusBadRequest)
				return
			}
			createCalls++
			issuedID = id
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"value":"mock-generated-secret"}}`))
		case http.MethodDelete:
			if id != issuedID {
				http.Error(w, "wrong token", http.StatusNotFound)
				return
			}
			deleteCalls++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":null}`))
		default:
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
		}
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	cert := server.Certificate()
	if cert == nil {
		t.Fatal("mock TLS server has no certificate")
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	cfg := &proxmoxConfig{
		User: "tofu-vm", Realm: "pve", ApiTokenID: "bootstrap",
		ApiTokenSecret: "mock-issuer-secret", ApiURL: server.URL + "/api2/json",
		CACertPEM: string(ca), TaskTimeout: 10 * time.Second,
	}
	// Without our private CA, connection should fail closed.
	withoutCA := *cfg
	withoutCA.CACertPEM = ""
	c1, err := newClient(&withoutCA)
	if err != nil {
		t.Fatal(err)
	}
	_, err = createToken(context.Background(), c1, "tofu-vm", "pve", time.Now().Add(10*time.Minute).Unix(), false)
	if err == nil {
		t.Fatal("untrusted TLS endpoint accepted without a CA")
	}
	c, err := newClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	token, err := createToken(context.Background(), c, "tofu-vm", "pve", time.Now().Add(10*time.Minute).Unix(), false)
	if err != nil {
		t.Fatalf("create against mock: %v", err)
	}
	if token == nil || token.TokenID == "" || token.Secret != "mock-generated-secret" {
		t.Fatalf("unexpected creation metadata or secret length: id=%q length=%d", token.TokenID, len(token.Secret))
	}
	if err := deleteToken(context.Background(), c, "tofu-vm", "pve", token.TokenID); err != nil {
		t.Fatalf("delete against mock: %v", err)
	}

	// Exercise the Vault dynamic-secret creation and revoke callbacks,
	// not just the raw Proxmox client methods. No role is persisted;
	// revocation must use the identity captured inside the lease.
	b, storage := getTestBackend(t)
	entry, err := logical.StorageEntryJSON(configStoragePath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	role := &proxmoxRoleEntry{
		Name: "vm-deployer", User: "tofu-vm", Realm: "pve",
		TTL: time.Minute, MaxTTL: time.Hour, InheritUserPrivileges: true,
	}
	response, err := b.createUserCreds(context.Background(), &logical.Request{Storage: storage}, role)
	if err != nil || response == nil || response.Secret == nil {
		t.Fatalf("Vault lease issuance failed: response=%v error=%v", response, err)
	}
	if response.Secret.Renewable || response.Secret.TTL != time.Minute {
		t.Fatalf("Vault lease has unsafe renewal or TTL: %#v", response.Secret)
	}
	if _, err := b.tokenRevoke(context.Background(), &logical.Request{
		Storage: storage, Secret: response.Secret,
	}, nil); err != nil {
		t.Fatalf("Vault revoke callback failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if createCalls != 2 || deleteCalls != 2 || response.Data["token_id"] != issuedID {
		t.Fatalf("unexpected create/delete calls: created=%d deleted=%d", createCalls, deleteCalls)
	}
}

func TestRootCAPEMAndURLValidation(t *testing.T) {
	cert, err := x509.SystemCertPool()
	if err != nil && cert != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"https://pve.example:8006/api2/json", "https://pve.example:8006/api2/json#frag"} {
		u, err := neturl.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		cfg := &proxmoxConfig{User: "issuer", Realm: "pve", ApiTokenID: "bootstrap", ApiTokenSecret: "mock", ApiURL: u.String(), TaskTimeout: time.Second}
		if (validateConfig(cfg) == nil) != (u.Fragment == "") {
			t.Fatal(fmt.Errorf("incorrect acceptance for %q", raw))
		}
	}
}
