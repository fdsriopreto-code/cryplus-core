package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fdsriopreto-code/cryplus-core/audit"
	"github.com/fdsriopreto-code/cryplus-core/envelope"
	"github.com/fdsriopreto-code/cryplus-core/keyring"
)

const (
	tokKeys  = "keys-token-0123456789abcdef0123456789abc"
	tokCrypt = "crypt-token-0123456789abcdef012345678901"
)

func exportServer(t *testing.T, enable bool) (*httptest.Server, *bytes.Buffer) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tokens.json")
	for _, e := range []struct {
		name, tok string
		roles     []string
		tenants   []string
	}{
		{"app-keys", tokKeys, []string{"crypt", "keys"}, []string{"acme-*"}},
		{"app-crypt", tokCrypt, []string{"crypt"}, []string{"*"}},
	} {
		if err := AppendService(path, e.name, e.tok, e.roles, e.tenants); err != nil {
			t.Fatal(err)
		}
	}
	auth, err := LoadAuthFile(path)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := keyring.NewMemory()
	var logbuf bytes.Buffer
	s := NewWithAuth(envelope.New(p, 0), audit.New(&logbuf), auth)
	if enable {
		s.EnableKeyExport()
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts, &logbuf
}

func TestKeyExportIsOffByDefault(t *testing.T) {
	ts, logbuf := exportServer(t, false)
	code, r := post(t, ts, "/v1/keys/tenant", tokKeys, map[string]any{"tenant": "acme-1"})
	if code != 403 || r["error"] != "key_export_disabled" {
		t.Fatalf("export must be disabled unless the operator turned it on: %d %v", code, r)
	}
	if code, r := post(t, ts, "/v1/keys/index", tokKeys, map[string]any{"tenant": "acme-1", "collection": "c", "field": "f"}); code != 403 || r["error"] != "key_export_disabled" {
		t.Fatalf("index export: %d %v", code, r)
	}
	if !strings.Contains(logbuf.String(), `"code":"key_export_disabled"`) {
		t.Fatal("the refused attempt must be audited")
	}
}

func TestKeyExportRequiresTheKeysRoleAndTenantAllowlist(t *testing.T) {
	ts, logbuf := exportServer(t, true)
	// a service with only crypt cannot fetch keys
	if code, r := post(t, ts, "/v1/keys/tenant", tokCrypt, map[string]any{"tenant": "acme-1"}); code != 403 || r["error"] != "role_forbidden" {
		t.Fatalf("crypt-only service got keys: %d %v", code, r)
	}
	// the keys service is limited to its tenants
	if code, r := post(t, ts, "/v1/keys/tenant", tokKeys, map[string]any{"tenant": "other-co"}); code != 403 || r["error"] != "tenant_forbidden" {
		t.Fatalf("allowlist bypassed: %d %v", code, r)
	}
	if code, _ := post(t, ts, "/v1/keys/tenant", tokKeys, map[string]any{}); code != 400 {
		t.Fatalf("missing tenant: %d", code)
	}
	if code, _ := post(t, ts, "/v1/keys/tenant", "nope-token-0123456789abcdef", map[string]any{"tenant": "acme-1"}); code != 401 {
		t.Fatalf("unauthenticated: %d", code)
	}
	code, r := post(t, ts, "/v1/keys/tenant", tokKeys, map[string]any{"tenant": "acme-1"})
	if code != 200 {
		t.Fatalf("export: %d %v", code, r)
	}
	key, _ := base64.StdEncoding.DecodeString(r["key"].(string))
	if len(key) != 32 || r["version"].(float64) != 1 || r["current"].(float64) != 1 {
		t.Fatalf("bad export: %v", r)
	}
	// different tenants get different keys; the same tenant a stable one
	_, r2 := post(t, ts, "/v1/keys/tenant", tokKeys, map[string]any{"tenant": "acme-2"})
	_, r3 := post(t, ts, "/v1/keys/tenant", tokKeys, map[string]any{"tenant": "acme-1"})
	if r["key"] == r2["key"] || r["key"] != r3["key"] {
		t.Fatal("tenant keys must be tenant-specific and stable")
	}
	// unknown version is an error, not a silent fallback
	if code, r := post(t, ts, "/v1/keys/tenant", tokKeys, map[string]any{"tenant": "acme-1", "version": 9}); code != 400 || r["error"] != "unknown_key_version" {
		t.Fatalf("unknown version: %d %v", code, r)
	}
	// every export is audited with the calling service, and the key itself never is
	l := logbuf.String()
	if !strings.Contains(l, `"op":"key_export"`) || !strings.Contains(l, `"service":"app-keys"`) {
		t.Fatalf("export not audited:\n%s", l)
	}
	if strings.Contains(l, r["key"].(string)) {
		t.Fatal("audit log leaked a key")
	}
}

func TestIndexKeyExportMatchesTheServiceBlindIndex(t *testing.T) {
	ts, _ := exportServer(t, true)
	ctx := map[string]any{"tenant": "acme-1", "collection": "Funcionario", "field": "cpf"}
	_, ex := post(t, ts, "/v1/keys/index", tokKeys, ctx)
	key, _ := base64.StdEncoding.DecodeString(ex["key"].(string))
	if len(key) != 32 {
		t.Fatalf("index key: %v", ex)
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte("12345678900"))
	local := "bi1." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))

	_, viaSvc := post(t, ts, "/v1/blind-index", tokCrypt, map[string]any{"context": ctx, "data": b64("12345678900")})
	if viaSvc["data"] != local {
		t.Fatalf("locally computed blind index differs from the service's:\n local %s\n svc   %v", local, viaSvc["data"])
	}
	if code, _ := post(t, ts, "/v1/keys/index", tokKeys, map[string]any{"tenant": "other-co", "collection": "c", "field": "f"}); code != 403 {
		t.Fatalf("index key allowlist: %d", code)
	}
}
