// Package keyring defines where Key Encryption Keys (KEKs) live and how
// data keys (DEKs) are wrapped and unwrapped.
//
// A Provider never sees plaintext application data: it only wraps/unwraps
// small 32-byte data keys. Every wrap is scoped to a tenant, so a tenant's
// data keys cannot be unwrapped under another tenant's identity.
package keyring

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

var (
	// ErrUnknownVersion is returned when a ciphertext references a KEK
	// version this provider does not hold.
	ErrUnknownVersion = errors.New("keyring: unknown key version")
	// ErrUnwrap is returned when a wrapped key fails authentication. It is
	// deliberately generic.
	ErrUnwrap = errors.New("keyring: unwrap failed")
)

// KeyVersion describes one KEK version for status output.
type KeyVersion struct {
	Version   uint32    `json:"version"`
	Current   bool      `json:"current"`
	CreatedAt time.Time `json:"created_at,omitempty"`
}

// Provider wraps and unwraps data keys and supplies blind-index keys.
type Provider interface {
	Name() string
	// CurrentVersion is the KEK version used for new wraps.
	CurrentVersion() uint32
	// Wrap encrypts dek under the tenant-scoped KEK of the given version.
	// aad is bound to the wrapped key and must be supplied again on Unwrap.
	Wrap(ctx context.Context, version uint32, tenant string, dek, aad []byte) ([]byte, error)
	Unwrap(ctx context.Context, version uint32, tenant string, wrapped, aad []byte) ([]byte, error)
	// IndexKey returns a 32-byte key for HMAC blind indexes, scoped to
	// tenant and field. It is stable across KEK rotations.
	IndexKey(ctx context.Context, tenant, field string) ([]byte, error)
	// Rotate creates a new KEK version and makes it current.
	Rotate(ctx context.Context) (uint32, error)
	Status() []KeyVersion
}

func lp(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

// wrapAAD builds the associated data for a wrap operation so the wrapped key
// is bound to its KEK version, tenant and caller-supplied context.
func wrapAAD(version uint32, tenant string, aad []byte) []byte {
	out := []byte("cryplus/wrap/v1")
	var v [4]byte
	binary.BigEndian.PutUint32(v[:], version)
	out = append(out, v[:]...)
	out = append(out, lp([]byte(tenant))...)
	out = append(out, lp(aad)...)
	return out
}

func hkdf32(secret []byte, info string) ([]byte, error) {
	out := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, secret, nil, []byte(info)), out); err != nil {
		return nil, err
	}
	return out, nil
}

// tenantKEK derives the per-tenant key from a master key.
func tenantKEK(master []byte, tenant string) ([]byte, error) {
	return hkdf32(master, "cryplus/kek/v1\x00"+tenant)
}

func indexKeyFrom(secret []byte, tenant, field string) ([]byte, error) {
	return hkdf32(secret, "cryplus/idx/v1\x00"+tenant+"\x00"+field)
}

// aeadWrap seals dek with XChaCha20-Poly1305. Output: nonce || ciphertext.
func aeadWrap(key, dek, aad []byte, rand io.Reader) ([]byte, error) {
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, a.NonceSize(), a.NonceSize()+len(dek)+a.Overhead())
	if _, err := io.ReadFull(rand, nonce); err != nil {
		return nil, err
	}
	return a.Seal(nonce, nonce, dek, aad), nil
}

func aeadUnwrap(key, wrapped, aad []byte) ([]byte, error) {
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(wrapped) < a.NonceSize()+a.Overhead() {
		return nil, ErrUnwrap
	}
	nonce, ct := wrapped[:a.NonceSize()], wrapped[a.NonceSize():]
	pt, err := a.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrUnwrap
	}
	return pt, nil
}

// Exporter is implemented by providers that can hand out a tenant-scoped key to a trusted client
// (so it can encrypt locally with a short-lived cache). Remote HSM-style providers would not implement it.
type Exporter interface {
	// ExportTenantKEK returns the 32-byte KEK for (version, tenant). version 0 means the current version.
	// It returns the version actually used.
	ExportTenantKEK(ctx context.Context, version uint32, tenant string) (key []byte, used uint32, err error)
}
