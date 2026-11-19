package server

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fdsriopreto-code/cryplus-core/audit"
	"github.com/fdsriopreto-code/cryplus-core/envelope"
	"github.com/fdsriopreto-code/cryplus-core/keyring"
)

const tok = "test-token-0123456789"

func setup(t *testing.T) (*httptest.Server, *bytes.Buffer) {
	t.Helper()
	p, _ := keyring.NewMemory()
	var log bytes.Buffer
	s, err := New(envelope.New(p, 0), audit.New(&log), tok)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts, &log
}

func post(t *testing.T, ts *httptest.Server, path, token string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", ts.URL+path, bytes.NewReader(b))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestAuthRequired(t *testing.T) {
	ts, _ := setup(t)
	for _, tk := range []string{"", "wrong-token-0123456789", tok + "x"} {
		if code, _ := post(t, ts, "/v1/encrypt", tk, map[string]any{}); code != 401 {
			t.Fatalf("token %q: status %d, want 401", tk, code)
		}
	}
	res, _ := http.Get(ts.URL + "/healthz")
	if res.StatusCode != 200 {
		t.Fatal("healthz must be open")
	}
	if _, err := New(nil, nil, "short"); err == nil {
		t.Fatal("short token accepted")
	}
}

func TestEncryptDecryptHTTP(t *testing.T) {
	ts, logbuf := setup(t)
	c := map[string]any{"tenant": "acme", "collection": "User", "field": "cpf"}
	code, enc := post(t, ts, "/v1/encrypt", tok, map[string]any{"context": c, "data": b64("123.456.789-00")})
	if code != 200 {
		t.Fatalf("encrypt: %d %v", code, enc)
	}
	ct := enc["data"].(string)
	code, dec := post(t, ts, "/v1/decrypt", tok, map[string]any{"context": c, "data": ct})
	if code != 200 || dec["data"] != b64("123.456.789-00") {
		t.Fatalf("decrypt: %d %v", code, dec)
	}
	// wrong tenant -> 403, generic error, no detail
	bad := map[string]any{"tenant": "evil", "collection": "User", "field": "cpf"}
	code, e := post(t, ts, "/v1/decrypt", tok, map[string]any{"context": bad, "data": ct})
	if code != 403 || e["error"] != "decryption_failed" {
		t.Fatalf("cross-tenant: %d %v", code, e)
	}
	// audit has entries and never leaks plaintext/ciphertext
	l := logbuf.String()
	if !strings.Contains(l, `"op":"encrypt"`) || !strings.Contains(l, `"code":"decryption_failed"`) {
		t.Fatalf("audit incomplete:\n%s", l)
	}
	if strings.Contains(l, ct) || strings.Contains(l, "123.456") || strings.Contains(l, b64("123.456.789-00")) {
		t.Fatal("audit log leaked data")
	}
}

func TestBatchPartialFailure(t *testing.T) {
	ts, _ := setup(t)
	c := map[string]any{"tenant": "acme", "collection": "U", "field": "f"}
	_, enc := post(t, ts, "/v1/encrypt", tok, map[string]any{"context": c, "data": b64("a")})
	code, out := post(t, ts, "/v1/batch", tok, map[string]any{"ops": []map[string]any{
		{"op": "decrypt", "context": c, "data": enc["data"]},
		{"op": "decrypt", "context": c, "data": "cp1.garbage"},
		{"op": "encrypt", "context": map[string]any{}, "data": b64("x")},
		{"op": "blind", "context": c, "data": b64("v")},
		{"op": "nope", "context": c},
	}})
	if code != 200 {
		t.Fatal(code)
	}
	r := out["results"].([]any)
	get := func(i int, k string) any { return r[i].(map[string]any)[k] }
	if get(0, "data") != b64("a") {
		t.Fatalf("item0 %v", r[0])
	}
	if get(1, "error") != "malformed_ciphertext" || get(2, "error") != "tenant_required" || get(4, "error") != "bad_op" {
		t.Fatalf("errors wrong: %v", r)
	}
	if !strings.HasPrefix(get(3, "data").(string), "bi1.") {
		t.Fatalf("blind: %v", r[3])
	}
}

func TestRejectsUnknownFields(t *testing.T) {
	ts, _ := setup(t)
	code, _ := post(t, ts, "/v1/encrypt", tok, map[string]any{"context": map[string]any{"tenant": "a"}, "data": "", "evil": 1})
	if code != 400 {
		t.Fatalf("got %d", code)
	}
}

func TestKeysAndRotateAndRewrap(t *testing.T) {
	ts, _ := setup(t)
	c := map[string]any{"tenant": "acme", "collection": "U", "field": "f"}
	_, enc := post(t, ts, "/v1/encrypt", tok, map[string]any{"context": c, "data": b64("keep")})
	if code, r := post(t, ts, "/v1/keys/rotate", tok, nil); code != 200 || r["version"].(float64) != 2 {
		t.Fatalf("rotate: %d %v", code, r)
	}
	code, rw := post(t, ts, "/v1/rewrap", tok, map[string]any{"context": c, "data": enc["data"]})
	if code != 200 || rw["changed"] != true {
		t.Fatalf("rewrap: %d %v", code, rw)
	}
	_, dec := post(t, ts, "/v1/decrypt", tok, map[string]any{"context": c, "data": rw["data"]})
	if dec["data"] != b64("keep") {
		t.Fatalf("after rewrap: %v", dec)
	}
}

func streamReq(t *testing.T, ts *httptest.Server, path, tenant string, body io.Reader) (*http.Response, error) {
	req, _ := http.NewRequest("POST", ts.URL+path, body)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-Cryplus-Tenant", tenant)
	req.Header.Set("X-Cryplus-Collection", "files")
	req.Header.Set("X-Cryplus-Field", "blob")
	return http.DefaultClient.Do(req)
}

func TestStreamOverHTTP(t *testing.T) {
	ts, _ := setup(t)
	data := make([]byte, 300_000)
	rand.Read(data)
	res, err := streamReq(t, ts, "/v1/stream/encrypt", "acme", bytes.NewReader(data))
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("enc: %v %v", err, res)
	}
	enc, _ := io.ReadAll(res.Body)
	if bytes.Contains(enc, data[1000:1064]) {
		t.Fatal("plaintext visible in encrypted stream")
	}
	res, err = streamReq(t, ts, "/v1/stream/decrypt", "acme", bytes.NewReader(enc))
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("dec: %v", err)
	}
	got, err := io.ReadAll(res.Body)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("stream roundtrip: %v", err)
	}
	// wrong tenant -> refused before any plaintext
	res, _ = streamReq(t, ts, "/v1/stream/decrypt", "evil", bytes.NewReader(enc))
	if res.StatusCode != 403 {
		t.Fatalf("cross-tenant stream: %d", res.StatusCode)
	}
	// corrupted late chunk: transfer must error, not return clean short data
	bad := append([]byte(nil), enc...)
	bad[len(bad)-10] ^= 1
	res, _ = streamReq(t, ts, "/v1/stream/decrypt", "acme", bytes.NewReader(bad))
	got, err = io.ReadAll(res.Body)
	if err == nil && len(got) == len(data) {
		t.Fatal("corrupted stream decrypted cleanly")
	}
	if err == nil {
		t.Fatalf("truncated plaintext delivered without error (%d bytes)", len(got))
	}
}

func TestRefusesPublicBind(t *testing.T) {
	p, _ := keyring.NewMemory()
	s, _ := New(envelope.New(p, 0), nil, tok)
	if err := s.Serve(t.Context(), "0.0.0.0:0", ServeOptions{}); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("want loopback refusal, got %v", err)
	}
}

func TestEmptyPlaintextRoundTripKeepsDataField(t *testing.T) {
	ts, _ := setup(t)
	c := map[string]any{"tenant": "acme", "collection": "U", "field": "f"}
	_, enc := post(t, ts, "/v1/encrypt", tok, map[string]any{"context": c, "data": ""})
	_, dec := post(t, ts, "/v1/decrypt", tok, map[string]any{"context": c, "data": enc["data"]})
	v, ok := dec["data"]
	if !ok || v != "" {
		t.Fatalf("empty plaintext must come back as \"data\":\"\", got %v (present=%v)", v, ok)
	}
}
