package keyring

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Sealer protects master keys at rest. The sealed blob is what is written
// to disk; the plaintext master key only ever lives in process memory.
type Sealer interface {
	Name() string
	Seal(ctx context.Context, plaintext, aad []byte) ([]byte, error)
	Open(ctx context.Context, blob, aad []byte) ([]byte, error)
}

// ---- passphrase (Argon2id) -------------------------------------------------

// PassphraseSealer seals with a key derived from a passphrase using
// Argon2id (time=3, memory=64 MiB, threads=4), fresh random salt per blob.
type PassphraseSealer struct{ pass []byte }

func NewPassphraseSealer(passphrase string) (*PassphraseSealer, error) {
	if len(passphrase) < 12 {
		return nil, errors.New("keyring: passphrase must be at least 12 characters")
	}
	return &PassphraseSealer{pass: []byte(passphrase)}, nil
}

func (p *PassphraseSealer) Name() string { return "passphrase" }

func (p *PassphraseSealer) derive(salt []byte) []byte {
	return argon2.IDKey(p.pass, salt, 3, 64*1024, 4, 32)
}

// blob = salt(16) || nonce(24) || ciphertext
func (p *PassphraseSealer) Seal(_ context.Context, pt, aad []byte) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	a, err := chacha20poly1305.NewX(p.derive(salt))
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := append(append([]byte{}, salt...), nonce...)
	return a.Seal(out, nonce, pt, aad), nil
}

func (p *PassphraseSealer) Open(_ context.Context, blob, aad []byte) ([]byte, error) {
	if len(blob) < 16+24+16 {
		return nil, errors.New("sealed blob too short")
	}
	a, err := chacha20poly1305.NewX(p.derive(blob[:16]))
	if err != nil {
		return nil, err
	}
	pt, err := a.Open(nil, blob[16:40], blob[40:], aad)
	if err != nil {
		return nil, errors.New("wrong passphrase or corrupted key file")
	}
	return pt, nil
}

// ---- HashiCorp Vault transit -----------------------------------------------

// VaultSealer seals master keys with a Vault transit key. The transit key
// never leaves Vault; revoking the Vault token or key makes the key file
// useless.
type VaultSealer struct {
	addr, token, mount, key string
	hc                      *http.Client
}

// NewVaultSealer connects and ensures the transit key exists (derived=true
// so the caller aad is cryptographically bound via Vault's context).
func NewVaultSealer(ctx context.Context, addr, token, mount, key string) (*VaultSealer, error) {
	if mount == "" {
		mount = "transit"
	}
	if key == "" {
		key = "cryplus"
	}
	v := &VaultSealer{addr: strings.TrimRight(addr, "/"), token: token, mount: mount, key: key,
		hc: &http.Client{Timeout: 15 * time.Second}}
	body := map[string]any{"type": "aes256-gcm96", "derived": true}
	if _, err := v.call(ctx, "POST", fmt.Sprintf("/v1/%s/keys/%s", mount, url.PathEscape(key)), body); err != nil {
		return nil, fmt.Errorf("vault: ensure key: %w", err)
	}
	return v, nil
}

// NewVaultFromEnv builds the provider the CLI exposes: VAULT_ADDR,
// VAULT_TOKEN, CRYPLUS_VAULT_MOUNT, CRYPLUS_VAULT_KEY, CRYPLUS_KEYFILE.
func NewVaultFromEnv(follower bool) (Provider, error) {
	addr, tok := os.Getenv("VAULT_ADDR"), os.Getenv("VAULT_TOKEN")
	if addr == "" || tok == "" {
		return nil, errors.New("set VAULT_ADDR and VAULT_TOKEN")
	}
	ctx := context.Background()
	s, err := NewVaultSealer(ctx, addr, tok, os.Getenv("CRYPLUS_VAULT_MOUNT"), os.Getenv("CRYPLUS_VAULT_KEY"))
	if err != nil {
		return nil, err
	}
	return open(ctx, envOr("CRYPLUS_KEYFILE", "cryplus-keys.vault.json"), s, follower)
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func (v *VaultSealer) Name() string { return "vault" }

func (v *VaultSealer) call(ctx context.Context, method, path string, body any) (map[string]any, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, v.addr+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", v.token)
	req.Header.Set("Content-Type", "application/json")
	res, err := v.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode/100 != 2 {
		return nil, fmt.Errorf("vault %s %s: HTTP %d: %s", method, path, res.StatusCode, strings.TrimSpace(string(raw)))
	}
	out := map[string]any{}
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (v *VaultSealer) dataString(res map[string]any, field string) (string, error) {
	d, _ := res["data"].(map[string]any)
	s, _ := d[field].(string)
	if s == "" {
		return "", fmt.Errorf("vault: response missing %q", field)
	}
	return s, nil
}

func (v *VaultSealer) Seal(ctx context.Context, pt, aad []byte) ([]byte, error) {
	res, err := v.call(ctx, "POST", fmt.Sprintf("/v1/%s/encrypt/%s", v.mount, url.PathEscape(v.key)), map[string]any{
		"plaintext": base64.StdEncoding.EncodeToString(pt),
		"context":   base64.StdEncoding.EncodeToString(aad),
	})
	if err != nil {
		return nil, err
	}
	ct, err := v.dataString(res, "ciphertext")
	return []byte(ct), err
}

func (v *VaultSealer) Open(ctx context.Context, blob, aad []byte) ([]byte, error) {
	res, err := v.call(ctx, "POST", fmt.Sprintf("/v1/%s/decrypt/%s", v.mount, url.PathEscape(v.key)), map[string]any{
		"ciphertext": string(blob),
		"context":    base64.StdEncoding.EncodeToString(aad),
	})
	if err != nil {
		return nil, err
	}
	s, err := v.dataString(res, "plaintext")
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(s)
}
