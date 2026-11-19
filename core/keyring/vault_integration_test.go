package keyring

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// Runs only against a real Vault: CRYPLUS_TEST_VAULT_ADDR / CRYPLUS_TEST_VAULT_TOKEN
// (transit engine must be enabled at "transit/").
func TestVaultRealIntegration(t *testing.T) {
	addr, tok := os.Getenv("CRYPLUS_TEST_VAULT_ADDR"), os.Getenv("CRYPLUS_TEST_VAULT_TOKEN")
	if addr == "" {
		t.Skip("CRYPLUS_TEST_VAULT_ADDR not set")
	}
	keyName := "cryplus-it-" + filepath.Base(t.TempDir())
	v, err := NewVaultSealer(bg, addr, tok, "", keyName)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "k.json")
	p, err := OpenSealed(bg, path, v)
	if err != nil {
		t.Fatal(err)
	}
	dek := bytes.Repeat([]byte{5}, 32)
	w, err := p.Wrap(bg, 1, "t", dek, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Rotate(bg); err != nil {
		t.Fatal(err)
	}
	// reopen from disk: keys are unsealed by the real Vault
	p2, err := OpenSealed(bg, path, v)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := p2.Unwrap(bg, 1, "t", w, nil); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("reopen via real vault: %v", err)
	}
	if p2.CurrentVersion() != 2 {
		t.Fatalf("current=%d", p2.CurrentVersion())
	}
	// a blob moved into the wrong slot must be rejected by Vault's context binding
	if _, err := v.Open(bg, p2.blobs[1], masterAAD(2)); err == nil {
		t.Fatal("real Vault opened a blob under the wrong context")
	}
	// revoked/invalid token -> cannot unseal at all (the point of Vault sealing)
	bad, err := NewVaultSealer(bg, addr, "not-a-token", "", keyName)
	if err == nil {
		if _, err := OpenSealed(bg, path, bad); err == nil {
			t.Fatal("opened key file with an invalid Vault token")
		}
	}
}
