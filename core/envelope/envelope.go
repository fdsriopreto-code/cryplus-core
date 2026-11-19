// Package envelope implements per-record envelope encryption.
//
// Every Encrypt call generates a fresh 32-byte data key (DEK), encrypts the
// plaintext with it using an AEAD, and stores the DEK wrapped by the
// tenant-scoped KEK next to the ciphertext. Rotating the KEK therefore only
// re-wraps small DEKs (see Rewrap); the bulk data is never touched.
//
// Wire format (before text encoding):
//
//	[0]      format version (1)
//	[1]      algorithm id (1 = XChaCha20-Poly1305, 2 = AES-256-GCM)
//	[2:6]    KEK version, big endian
//	[6:8]    wrapped DEK length, big endian
//	[8:8+n]  wrapped DEK
//	[..]     nonce
//	[..]     ciphertext || tag
//
// The data AAD binds format, algorithm and the caller Context (tenant,
// collection, field, record id) so a ciphertext cannot be replayed into a
// different field or tenant. KEK version and wrapped DEK are deliberately
// outside the data AAD, which is what makes Rewrap possible.
package envelope

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/fdsriopreto-code/cryplus-core/keyring"
	"golang.org/x/crypto/chacha20poly1305"
)

// Algorithm identifies the AEAD used for the payload.
type Algorithm byte

const (
	XChaCha20Poly1305 Algorithm = 1
	AES256GCM         Algorithm = 2
)

const (
	formatV1   = 1
	textPrefix = "cp1."
	indexPref  = "bi1."
)

var (
	ErrFormat  = errors.New("envelope: malformed ciphertext")
	ErrDecrypt = errors.New("envelope: decryption failed")
	ErrContext = errors.New("envelope: tenant is required")
)

// Context scopes a ciphertext. Tenant is mandatory; the others narrow the
// binding. The same Context must be supplied to decrypt.
type Context struct {
	Tenant     string `json:"tenant"`
	Collection string `json:"collection,omitempty"`
	Field      string `json:"field,omitempty"`
	RecordID   string `json:"recordId,omitempty"`
}

func lp(b string) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

// AAD is the canonical, length-prefixed encoding of the context.
func (c Context) AAD() []byte {
	var out []byte
	out = append(out, lp(c.Tenant)...)
	out = append(out, lp(c.Collection)...)
	out = append(out, lp(c.Field)...)
	out = append(out, lp(c.RecordID)...)
	return out
}

func (c Context) validate() error {
	if c.Tenant == "" {
		return ErrContext
	}
	return nil
}

// Service performs envelope operations against a keyring Provider.
type Service struct {
	Provider keyring.Provider
	Alg      Algorithm
	Rand     io.Reader // defaults to crypto/rand
}

func New(p keyring.Provider, alg Algorithm) *Service {
	if alg == 0 {
		alg = XChaCha20Poly1305
	}
	return &Service{Provider: p, Alg: alg}
}

func (s *Service) rng() io.Reader {
	if s.Rand != nil {
		return s.Rand
	}
	return rand.Reader
}

func newAEAD(alg Algorithm, key []byte) (cipher.AEAD, error) {
	switch alg {
	case XChaCha20Poly1305:
		return chacha20poly1305.NewX(key)
	case AES256GCM:
		b, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(b)
	}
	return nil, fmt.Errorf("envelope: unknown algorithm %d", alg)
}

func dataAAD(alg Algorithm, c Context) []byte {
	out := []byte{'c', 'p', '/', 'd', formatV1, byte(alg)}
	return append(out, c.AAD()...)
}

// Encrypt returns the text form ("cp1.<base64url>") of the envelope.
func (s *Service) Encrypt(ctx context.Context, c Context, plaintext []byte) (string, error) {
	if err := c.validate(); err != nil {
		return "", err
	}
	dek := make([]byte, 32)
	if _, err := io.ReadFull(s.rng(), dek); err != nil {
		return "", err
	}
	defer zero(dek)

	ver := s.Provider.CurrentVersion()
	wrapped, err := s.Provider.Wrap(ctx, ver, c.Tenant, dek, c.AAD())
	if err != nil {
		return "", err
	}
	aead, err := newAEAD(s.Alg, dek)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(s.rng(), nonce); err != nil {
		return "", err
	}
	buf := make([]byte, 0, 8+len(wrapped)+len(nonce)+len(plaintext)+aead.Overhead())
	buf = append(buf, formatV1, byte(s.Alg))
	buf = binary.BigEndian.AppendUint32(buf, ver)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(wrapped)))
	buf = append(buf, wrapped...)
	buf = append(buf, nonce...)
	buf = aead.Seal(buf, nonce, plaintext, dataAAD(s.Alg, c))
	return textPrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

type parsed struct {
	alg     Algorithm
	kekVer  uint32
	wrapped []byte
	nonce   []byte
	ct      []byte
}

func parse(text string) (*parsed, error) {
	if !strings.HasPrefix(text, textPrefix) {
		return nil, ErrFormat
	}
	raw, err := base64.RawURLEncoding.DecodeString(text[len(textPrefix):])
	if err != nil || len(raw) < 8 || raw[0] != formatV1 {
		return nil, ErrFormat
	}
	p := &parsed{alg: Algorithm(raw[1]), kekVer: binary.BigEndian.Uint32(raw[2:6])}
	wl := int(binary.BigEndian.Uint16(raw[6:8]))
	if len(raw) < 8+wl {
		return nil, ErrFormat
	}
	p.wrapped = raw[8 : 8+wl]
	rest := raw[8+wl:]
	ns := 0
	switch p.alg {
	case XChaCha20Poly1305:
		ns = chacha20poly1305.NonceSizeX
	case AES256GCM:
		ns = 12
	default:
		return nil, ErrFormat
	}
	if len(rest) < ns+16 {
		return nil, ErrFormat
	}
	p.nonce, p.ct = rest[:ns], rest[ns:]
	return p, nil
}

// Info is the non-secret metadata readable from a ciphertext without keys.
type Info struct {
	Algorithm  Algorithm
	KEKVersion uint32
}

// Inspect reads metadata from a ciphertext without decrypting it. Use it to
// find rows still encrypted under an old KEK version.
func Inspect(text string) (Info, error) {
	p, err := parse(text)
	if err != nil {
		return Info{}, err
	}
	return Info{Algorithm: p.alg, KEKVersion: p.kekVer}, nil
}

// IsCiphertext reports whether text looks like an envelope produced here.
func IsCiphertext(text string) bool {
	_, err := parse(text)
	return err == nil
}

func (s *Service) openDEK(ctx context.Context, c Context, p *parsed) ([]byte, error) {
	dek, err := s.Provider.Unwrap(ctx, p.kekVer, c.Tenant, p.wrapped, c.AAD())
	if err != nil {
		return nil, ErrDecrypt
	}
	return dek, nil
}

// Decrypt verifies and decrypts a ciphertext. Every failure mode collapses
// into ErrDecrypt so callers (and attackers) cannot tell a bad key from a
// bad context from tampering.
func (s *Service) Decrypt(ctx context.Context, c Context, text string) ([]byte, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	p, err := parse(text)
	if err != nil {
		return nil, err
	}
	dek, err := s.openDEK(ctx, c, p)
	if err != nil {
		return nil, err
	}
	defer zero(dek)
	aead, err := newAEAD(p.alg, dek)
	if err != nil {
		return nil, ErrDecrypt
	}
	pt, err := aead.Open(nil, p.nonce, p.ct, dataAAD(p.alg, c))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// Rewrap moves a ciphertext to the current KEK version by re-wrapping its
// DEK. The payload bytes are unchanged. changed is false when the input was
// already on the current version (the input is returned as is).
func (s *Service) Rewrap(ctx context.Context, c Context, text string) (out string, changed bool, err error) {
	if err := c.validate(); err != nil {
		return "", false, err
	}
	p, err := parse(text)
	if err != nil {
		return "", false, err
	}
	cur := s.Provider.CurrentVersion()
	if p.kekVer == cur {
		return text, false, nil
	}
	dek, err := s.openDEK(ctx, c, p)
	if err != nil {
		return "", false, err
	}
	defer zero(dek)
	// Prove the DEK actually opens this payload before we move it, so a
	// corrupt row is reported instead of silently re-wrapped.
	aead, err := newAEAD(p.alg, dek)
	if err != nil {
		return "", false, ErrDecrypt
	}
	if _, err := aead.Open(nil, p.nonce, p.ct, dataAAD(p.alg, c)); err != nil {
		return "", false, ErrDecrypt
	}
	wrapped, err := s.Provider.Wrap(ctx, cur, c.Tenant, dek, c.AAD())
	if err != nil {
		return "", false, err
	}
	buf := make([]byte, 0, 8+len(wrapped)+len(p.nonce)+len(p.ct))
	buf = append(buf, formatV1, byte(p.alg))
	buf = binary.BigEndian.AppendUint32(buf, cur)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(wrapped)))
	buf = append(buf, wrapped...)
	buf = append(buf, p.nonce...)
	buf = append(buf, p.ct...)
	return textPrefix + base64.RawURLEncoding.EncodeToString(buf), true, nil
}

// BlindIndex returns a deterministic keyed hash of value for equality
// search over encrypted columns. It is scoped to tenant, collection and
// field, so equal values in different fields or tenants produce different
// indexes. It reveals equality (and frequency) of values, nothing else;
// do not use it for low-entropy fields such as booleans.
func (s *Service) BlindIndex(ctx context.Context, c Context, value []byte) (string, error) {
	if err := c.validate(); err != nil {
		return "", err
	}
	key, err := s.Provider.IndexKey(ctx, c.Tenant, c.Collection+"\x00"+c.Field)
	if err != nil {
		return "", err
	}
	defer zero(key)
	m := hmac.New(sha256.New, key)
	m.Write(value)
	return indexPref + base64.RawURLEncoding.EncodeToString(m.Sum(nil)), nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
