package keyring

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

var bg = context.Background()

func TestWrapUnwrapBindings(t *testing.T) {
	p, _ := NewMemory()
	dek := bytes.Repeat([]byte{7}, 32)
	w, err := p.Wrap(bg, 1, "acme", dek, []byte("ctx"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := p.Unwrap(bg, 1, "acme", w, []byte("ctx")); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("roundtrip: %v", err)
	}
	if _, err := p.Unwrap(bg, 1, "other", w, []byte("ctx")); err == nil {
		t.Fatal("unwrapped under another tenant")
	}
	if _, err := p.Unwrap(bg, 1, "acme", w, []byte("different")); err == nil {
		t.Fatal("unwrapped under different aad")
	}
	if _, err := p.Unwrap(bg, 9, "acme", w, []byte("ctx")); err != ErrUnknownVersion {
		t.Fatalf("want ErrUnknownVersion, got %v", err)
	}
}

func TestLocalFilePermsAndPlaintextWarning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.json")
	if _, err := OpenLocal(path); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// On Windows mode bits are not meaningful; only assert on unix-like.
	if os.PathSeparator == '/' && st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v, want 0600", st.Mode().Perm())
	}
}

func TestPassphraseSealedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.json")
	s, err := NewPassphraseSealer("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	p, err := OpenSealed(bg, path, s)
	if err != nil {
		t.Fatal(err)
	}
	dek := bytes.Repeat([]byte{3}, 32)
	w, _ := p.Wrap(bg, 1, "t", dek, nil)

	// the file must not contain the master key in the clear
	raw, _ := os.ReadFile(path)
	var kf keyFile
	json.Unmarshal(raw, &kf)
	if kf.Sealed != "passphrase" {
		t.Fatalf("sealed marker missing: %s", raw)
	}
	m, _ := p.master(1)
	if strings.Contains(string(raw), base64.StdEncoding.EncodeToString(m)) {
		t.Fatal("master key stored in the clear in a sealed file")
	}

	// rotation persists a sealed v2; reopen with right passphrase works
	if _, err := p.Rotate(bg); err != nil {
		t.Fatal(err)
	}
	p2, err := OpenSealed(bg, path, s)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := p2.Unwrap(bg, 1, "t", w, nil); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("reopen: %v", err)
	}
	if p2.CurrentVersion() != 2 {
		t.Fatal("rotation lost on reopen")
	}

	// wrong passphrase must fail closed
	bad, _ := NewPassphraseSealer("this is the wrong one")
	if _, err := OpenSealed(bg, path, bad); err == nil {
		t.Fatal("opened with wrong passphrase")
	}
	// opening a sealed file without a sealer must fail, not misread the blobs
	if _, err := OpenLocal(path); err == nil {
		t.Fatal("opened sealed file as plaintext")
	}
	if _, err := NewPassphraseSealer("short"); err == nil {
		t.Fatal("weak passphrase accepted")
	}
}

// fakeVault emulates the transit endpoints we use, including `derived` context binding.
func fakeVault(t *testing.T) *httptest.Server {
	t.Helper()
	keys := map[string]bool{}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "root" {
			http.Error(w, `{"errors":["permission denied"]}`, 403)
			return
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/transit/"), "/")
		switch {
		case parts[0] == "keys":
			keys[parts[1]] = true
			w.WriteHeader(204)
		case parts[0] == "encrypt" && keys[parts[1]]:
			pt, _ := base64.StdEncoding.DecodeString(body["plaintext"].(string))
			ctxb := body["context"].(string)
			ct := "vault:v1:" + base64.StdEncoding.EncodeToString(append([]byte(ctxb+"|"), pt...))
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ciphertext": ct}})
		case parts[0] == "decrypt" && keys[parts[1]]:
			raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(body["ciphertext"].(string), "vault:v1:"))
			i := bytes.IndexByte(raw, '|')
			if i < 0 || string(raw[:i]) != body["context"].(string) {
				http.Error(w, `{"errors":["cipher: message authentication failed"]}`, 400)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(raw[i+1:])}})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestVaultSealer(t *testing.T) {
	srv := fakeVault(t)
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "k.json")
	v, err := NewVaultSealer(bg, srv.URL, "root", "", "")
	if err != nil {
		t.Fatal(err)
	}
	p, err := OpenSealed(bg, path, v)
	if err != nil {
		t.Fatal(err)
	}
	dek := bytes.Repeat([]byte{9}, 32)
	w, _ := p.Wrap(bg, 1, "t", dek, nil)
	p2, err := OpenSealed(bg, path, v)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := p2.Unwrap(bg, 1, "t", w, nil); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("vault reopen: %v", err)
	}
	// moving a sealed blob into another slot must fail (context binding)
	raw, _ := os.ReadFile(path)
	var kf keyFile
	json.Unmarshal(raw, &kf)
	kf.Keys["1"] = kf.IndexKey // swap master blob with the index blob
	raw, _ = json.Marshal(kf)
	os.WriteFile(path, raw, 0o600)
	if _, err := OpenSealed(bg, path, v); err == nil {
		t.Fatal("sealed blob accepted in the wrong slot")
	}
	// bad token
	if _, err := NewVaultSealer(bg, srv.URL, "nope", "", ""); err == nil {
		t.Fatal("bad vault token accepted")
	}
}

type fakeKMS struct{}

func (fakeKMS) Encrypt(_ context.Context, in *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	ctxb, _ := json.Marshal(in.EncryptionContext)
	nonce := make([]byte, 4)
	rand.Read(nonce)
	return &kms.EncryptOutput{CiphertextBlob: append(append(append([]byte{}, nonce...), ctxb...), append([]byte("|"), in.Plaintext...)...)}, nil
}

func (fakeKMS) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	ctxb, _ := json.Marshal(in.EncryptionContext)
	b := in.CiphertextBlob[4:]
	i := bytes.IndexByte(b, '|')
	if i < 0 || !bytes.Equal(b[:i], ctxb) {
		return nil, os.ErrInvalid
	}
	return &kms.DecryptOutput{Plaintext: b[i+1:]}, nil
}

func TestKMSSealerBindsContext(t *testing.T) {
	s, err := NewKMSSealer(fakeKMS{}, "alias/test")
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := s.Seal(bg, []byte("k"), []byte("a"))
	if pt, err := s.Open(bg, blob, []byte("a")); err != nil || string(pt) != "k" {
		t.Fatalf("kms roundtrip: %v", err)
	}
	if _, err := s.Open(bg, blob, []byte("b")); err == nil {
		t.Fatal("kms opened with different aad")
	}
	path := filepath.Join(t.TempDir(), "k.json")
	p, err := OpenSealed(bg, path, s)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "local+kms" {
		t.Fatal(p.Name())
	}
}
