package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fdsriopreto-code/cryplus-core/audit"
	"github.com/fdsriopreto-code/cryplus-core/envelope"
	"github.com/fdsriopreto-code/cryplus-core/keyring"
)

const (
	tokApp    = "app-token-0123456789abcdef0123456789abcdef"
	tokBackup = "backup-token-0123456789abcdef0123456789"
	tokAdmin  = "admin-token-0123456789abcdef0123456789ab"
)

func setupAuth(t *testing.T) (*httptest.Server, string, *bytes.Buffer) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tokens.json")
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(AppendService(path, "operax-api", tokApp, []string{"crypt"}, []string{"*"}))
	must(AppendService(path, "backup-job", tokBackup, []string{"crypt"}, []string{"__platform__", "backup:*"}))
	must(AppendService(path, "ops", tokAdmin, []string{"admin"}, []string{"*"}))
	auth, err := LoadAuthFile(path)
	must(err)
	p, _ := keyring.NewMemory()
	var logbuf bytes.Buffer
	ts := httptest.NewServer(NewWithAuth(envelope.New(p, 0), audit.New(&logbuf), auth).Handler())
	t.Cleanup(ts.Close)
	return ts, path, &logbuf
}

func TestTokensFileStoresOnlyHashes(t *testing.T) {
	_, path, _ := setupAuth(t)
	raw, _ := os.ReadFile(path)
	for _, tok := range []string{tokApp, tokBackup, tokAdmin} {
		if strings.Contains(string(raw), tok) {
			t.Fatal("tokens file contains a usable token in the clear")
		}
		if !strings.Contains(string(raw), HashToken(tok)) {
			t.Fatal("hash missing")
		}
	}
}

func TestRolesAreEnforced(t *testing.T) {
	ts, _, _ := setupAuth(t)
	c := map[string]any{"tenant": "acme", "collection": "U", "field": "f"}
	body := map[string]any{"context": c, "data": b64("x")}

	if code, _ := post(t, ts, "/v1/encrypt", tokApp, body); code != 200 {
		t.Fatalf("crypt service must encrypt, got %d", code)
	}
	// a crypt-only service cannot rotate or list keys
	if code, r := post(t, ts, "/v1/keys/rotate", tokApp, nil); code != 403 || r["error"] != "role_forbidden" {
		t.Fatalf("crypt service rotated keys: %d %v", code, r)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/v1/keys", nil)
	req.Header.Set("Authorization", "Bearer "+tokApp)
	if res, _ := http.DefaultClient.Do(req); res.StatusCode != 403 {
		t.Fatalf("crypt service listed keys: %d", res.StatusCode)
	}
	// an admin-only service cannot touch data
	if code, _ := post(t, ts, "/v1/encrypt", tokAdmin, body); code != 403 {
		t.Fatalf("admin-only service encrypted data: %d", code)
	}
	if code, _ := post(t, ts, "/v1/keys/rotate", tokAdmin, nil); code != 200 {
		t.Fatalf("admin must rotate: %d", code)
	}
}

func TestTenantAllowlist(t *testing.T) {
	ts, _, logbuf := setupAuth(t)
	enc := func(tok, tenant string) (int, map[string]any) {
		return post(t, ts, "/v1/encrypt", tok, map[string]any{"context": map[string]any{"tenant": tenant}, "data": b64("x")})
	}
	if code, _ := enc(tokBackup, "__platform__"); code != 200 {
		t.Fatalf("allowed exact tenant refused: %d", code)
	}
	if code, _ := enc(tokBackup, "backup:2026-11"); code != 200 {
		t.Fatalf("allowed prefix tenant refused: %d", code)
	}
	for _, bad := range []string{"acme", "backup", "xbackup:1", ""} {
		if code, r := enc(tokBackup, bad); code == 200 {
			t.Fatalf("backup-job reached tenant %q", bad)
		} else if bad != "" && r["error"] != "tenant_forbidden" {
			t.Fatalf("tenant %q: %v", bad, r)
		}
	}
	// the same restriction applies inside batches (per item) and on streams
	code, out := post(t, ts, "/v1/batch", tokBackup, map[string]any{"ops": []map[string]any{
		{"op": "encrypt", "context": map[string]any{"tenant": "__platform__"}, "data": b64("a")},
		{"op": "encrypt", "context": map[string]any{"tenant": "acme"}, "data": b64("b")},
	}})
	r := out["results"].([]any)
	if code != 200 || r[0].(map[string]any)["error"] != nil || r[1].(map[string]any)["error"] != "tenant_forbidden" {
		t.Fatalf("batch allowlist: %d %v", code, out)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/v1/stream/encrypt", strings.NewReader("data"))
	req.Header.Set("Authorization", "Bearer "+tokBackup)
	req.Header.Set("X-Cryplus-Tenant", "acme")
	if res, _ := http.DefaultClient.Do(req); res.StatusCode != 403 {
		t.Fatalf("stream bypassed the tenant allowlist: %d", res.StatusCode)
	}
	// the audit trail names the service that was refused
	if l := logbuf.String(); !strings.Contains(l, `"service":"backup-job"`) || !strings.Contains(l, `"code":"tenant_forbidden"`) {
		t.Fatalf("audit lacks service/denial:\n%s", l)
	}
}

func TestUnknownTokenAndPrefixTricks(t *testing.T) {
	ts, _, _ := setupAuth(t)
	for _, tok := range []string{"", "nope", tokApp + "x", tokApp[:len(tokApp)-1], strings.ToUpper(tokApp)} {
		if code, _ := post(t, ts, "/v1/encrypt", tok, map[string]any{}); code != 401 {
			t.Fatalf("token %q accepted (%d)", tok, code)
		}
	}
}

func TestRevocationByReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	AppendService(path, "a", tokApp, []string{"crypt"}, []string{"*"})
	AppendService(path, "b", tokBackup, []string{"crypt"}, []string{"*"})
	auth, err := LoadAuthFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reloaded := make(chan int, 4)
	errs := make(chan error, 4)
	go auth.Poll(ctx, 20*time.Millisecond, func(e error) { errs <- e }, func(n int) { reloaded <- n })

	if auth.Identify(tokBackup) == nil {
		t.Fatal("b should be valid")
	}
	// revoke b by removing it from the file
	var tf tokensFile
	raw, _ := os.ReadFile(path)
	json.Unmarshal(raw, &tf)
	tf.Services = tf.Services[:1]
	raw, _ = json.Marshal(tf)
	os.WriteFile(path, raw, 0o600)
	os.Chtimes(path, time.Now().Add(time.Minute), time.Now().Add(time.Minute))
	select {
	case n := <-reloaded:
		if n != 1 {
			t.Fatalf("n=%d", n)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("tokens file was not reloaded")
	}
	if auth.Identify(tokBackup) != nil {
		t.Fatal("revoked token still works")
	}
	if auth.Identify(tokApp) == nil {
		t.Fatal("remaining token broke")
	}

	// a corrupt file must NOT lock everyone out: previous valid set stays in force
	os.WriteFile(path, []byte("{not json"), 0o600)
	os.Chtimes(path, time.Now().Add(2*time.Minute), time.Now().Add(2*time.Minute))
	select {
	case <-errs:
	case <-time.After(3 * time.Second):
		t.Fatal("corrupt tokens file went unreported")
	}
	if auth.Identify(tokApp) == nil {
		t.Fatal("corrupt tokens file locked out a valid service")
	}
}

func TestTokensFileValidation(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "t.json")
		os.WriteFile(p, []byte(s), 0o600)
		return p
	}
	h := HashToken(tokApp)
	bad := map[string]string{
		"empty":          `{"services":[]}`,
		"unknown role":   `{"services":[{"name":"a","token_sha256":"` + h + `","roles":["root"],"tenants":["*"]}]}`,
		"no roles":       `{"services":[{"name":"a","token_sha256":"` + h + `","roles":[],"tenants":["*"]}]}`,
		"no tenants":     `{"services":[{"name":"a","token_sha256":"` + h + `","roles":["crypt"]}]}`,
		"bad hash":       `{"services":[{"name":"a","token_sha256":"abc","roles":["crypt"],"tenants":["*"]}]}`,
		"duplicate name": `{"services":[{"name":"a","token_sha256":"` + h + `","roles":["crypt"],"tenants":["*"]},{"name":"a","token_sha256":"` + h + `","roles":["crypt"],"tenants":["*"]}]}`,
		"unknown field":  `{"services":[{"name":"a","token":"plain","token_sha256":"` + h + `","roles":["crypt"],"tenants":["*"]}]}`,
	}
	for name, content := range bad {
		if _, err := LoadAuthFile(write(content)); err == nil {
			t.Fatalf("%s: invalid tokens file accepted", name)
		}
	}
	if err := AppendService(filepath.Join(dir, "x.json"), "a", tokApp, []string{"crypt"}, []string{"*"}); err != nil {
		t.Fatal(err)
	}
	if err := AppendService(filepath.Join(dir, "x.json"), "a", tokApp, []string{"crypt"}, []string{"*"}); err == nil {
		t.Fatal("duplicate service name accepted by AppendService")
	}
}

func TestFollowerCannotRotateOverHTTP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	if _, err := keyring.OpenLocal(path); err != nil {
		t.Fatal(err)
	}
	f, err := keyring.OpenFollower(context.Background(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := New(envelope.New(f, 0), nil, tok)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	code, r := post(t, ts, "/v1/keys/rotate", tok, nil)
	if code != 409 || r["error"] != "read_only_instance" {
		t.Fatalf("follower rotate: %d %v", code, r)
	}
}
