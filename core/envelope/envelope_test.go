package envelope

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fdsriopreto-code/cryplus-core/keyring"
)

var bg = context.Background()

func svc(t *testing.T, alg Algorithm) *Service {
	t.Helper()
	p, err := keyring.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	return New(p, alg)
}

var ctxA = Context{Tenant: "acme", Collection: "User", Field: "cpf"}

func TestRoundTripBothAlgorithms(t *testing.T) {
	for _, alg := range []Algorithm{XChaCha20Poly1305, AES256GCM} {
		s := svc(t, alg)
		for _, msg := range [][]byte{{}, []byte("123.456.789-00"), bytes.Repeat([]byte{0xAB}, 100_000)} {
			ct, err := s.Encrypt(bg, ctxA, msg)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(ct, "cp1.") {
				t.Fatalf("missing prefix: %q", ct)
			}
			pt, err := s.Decrypt(bg, ctxA, ct)
			if err != nil || !bytes.Equal(pt, msg) {
				t.Fatalf("alg %d: roundtrip failed: %v", alg, err)
			}
		}
	}
}

func TestSamePlaintextDifferentCiphertext(t *testing.T) {
	s := svc(t, 0)
	a, _ := s.Encrypt(bg, ctxA, []byte("x"))
	b, _ := s.Encrypt(bg, ctxA, []byte("x"))
	if a == b {
		t.Fatal("encryption is deterministic: DEK/nonce reuse")
	}
}

func TestContextBinding(t *testing.T) {
	s := svc(t, 0)
	ct, _ := s.Encrypt(bg, ctxA, []byte("secret"))
	bad := []Context{
		{Tenant: "other", Collection: "User", Field: "cpf"},
		{Tenant: "acme", Collection: "Order", Field: "cpf"},
		{Tenant: "acme", Collection: "User", Field: "phone"},
		{Tenant: "acme", Collection: "User", Field: "cpf", RecordID: "42"},
	}
	for _, c := range bad {
		if _, err := s.Decrypt(bg, c, ct); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("ctx %+v decrypted a foreign ciphertext (err=%v)", c, err)
		}
	}
}

func TestTamperAnywhereFails(t *testing.T) {
	s := svc(t, 0)
	ct, _ := s.Encrypt(bg, ctxA, []byte("secret"))
	raw, _ := base64.RawURLEncoding.DecodeString(ct[4:])
	for i := 2; i < len(raw); i++ { // skip version+alg (format errors, tested separately)
		mod := append([]byte(nil), raw...)
		mod[i] ^= 1
		txt := "cp1." + base64.RawURLEncoding.EncodeToString(mod)
		if _, err := s.Decrypt(bg, ctxA, txt); err == nil {
			t.Fatalf("flipping byte %d went undetected", i)
		}
	}
}

func TestMalformed(t *testing.T) {
	s := svc(t, 0)
	for _, in := range []string{"", "plain", "cp1.", "cp1.!!!", "cp1.AAAA", "cp2." + strings.Repeat("A", 80)} {
		if _, err := s.Decrypt(bg, ctxA, in); err == nil {
			t.Fatalf("accepted %q", in)
		}
	}
	if _, err := s.Encrypt(bg, Context{}, []byte("x")); !errors.Is(err, ErrContext) {
		t.Fatal("empty tenant must be rejected")
	}
}

func TestRotationRewrapKeepsData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	p, err := keyring.OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	s := New(p, 0)
	ct1, _ := s.Encrypt(bg, ctxA, []byte("old data"))
	if i, _ := Inspect(ct1); i.KEKVersion != 1 {
		t.Fatalf("want v1, got %d", i.KEKVersion)
	}
	if v, err := p.Rotate(bg); err != nil || v != 2 {
		t.Fatalf("rotate: %v %d", err, v)
	}
	// old ciphertext still readable after rotation
	if pt, err := s.Decrypt(bg, ctxA, ct1); err != nil || string(pt) != "old data" {
		t.Fatalf("old ct unreadable after rotate: %v", err)
	}
	ct2, changed, err := s.Rewrap(bg, ctxA, ct1)
	if err != nil || !changed {
		t.Fatalf("rewrap: %v changed=%v", err, changed)
	}
	if i, _ := Inspect(ct2); i.KEKVersion != 2 {
		t.Fatalf("rewrap did not move to v2")
	}
	// payload (the part after the wrapped key) must be byte-identical
	r1, _ := base64.RawURLEncoding.DecodeString(ct1[4:])
	r2, _ := base64.RawURLEncoding.DecodeString(ct2[4:])
	if !bytes.Equal(r1[len(r1)-30:], r2[len(r2)-30:]) {
		t.Fatal("rewrap must not touch payload bytes")
	}
	if _, changed, _ := s.Rewrap(bg, ctxA, ct2); changed {
		t.Fatal("rewrap should be idempotent")
	}
	// reopen from disk: both versions survive, new ct decrypts
	p2, err := keyring.OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	s2 := New(p2, 0)
	if pt, err := s2.Decrypt(bg, ctxA, ct2); err != nil || string(pt) != "old data" {
		t.Fatalf("after reload: %v", err)
	}
	if pt, err := s2.Decrypt(bg, ctxA, ct1); err != nil || string(pt) != "old data" {
		t.Fatalf("v1 lost after reload: %v", err)
	}
}

func TestRewrapRejectsCorruptRow(t *testing.T) {
	s := svc(t, 0)
	ct, _ := s.Encrypt(bg, ctxA, []byte("data"))
	if _, err := s.Provider.Rotate(bg); err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(ct[4:])
	raw[len(raw)-1] ^= 1
	if _, _, err := s.Rewrap(bg, ctxA, "cp1."+base64.RawURLEncoding.EncodeToString(raw)); err == nil {
		t.Fatal("rewrap must refuse to move a corrupt payload")
	}
}

func TestTenantIsolation(t *testing.T) {
	s := svc(t, 0)
	ca := Context{Tenant: "A", Collection: "U", Field: "f"}
	cb := Context{Tenant: "B", Collection: "U", Field: "f"}
	ct, _ := s.Encrypt(bg, ca, []byte("a-secret"))
	if _, err := s.Decrypt(bg, cb, ct); err == nil {
		t.Fatal("tenant B decrypted tenant A data")
	}
	ia, _ := s.BlindIndex(bg, ca, []byte("v"))
	ib, _ := s.BlindIndex(bg, cb, []byte("v"))
	if ia == ib {
		t.Fatal("blind index must differ across tenants")
	}
}

func TestBlindIndex(t *testing.T) {
	s := svc(t, 0)
	a1, _ := s.BlindIndex(bg, ctxA, []byte("111"))
	a2, _ := s.BlindIndex(bg, ctxA, []byte("111"))
	b, _ := s.BlindIndex(bg, ctxA, []byte("222"))
	other, _ := s.BlindIndex(bg, Context{Tenant: "acme", Collection: "User", Field: "phone"}, []byte("111"))
	if a1 != a2 {
		t.Fatal("blind index must be deterministic")
	}
	if a1 == b || a1 == other {
		t.Fatal("blind index collided across values/fields")
	}
	// blind index must be stable across KEK rotation
	if _, err := s.Provider.Rotate(bg); err != nil {
		t.Fatal(err)
	}
	a3, _ := s.BlindIndex(bg, ctxA, []byte("111"))
	if a1 != a3 {
		t.Fatal("rotation changed blind index")
	}
}

func encStream(t *testing.T, s *Service, c Context, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := s.EncryptWriter(bg, c, &out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func decStream(s *Service, c Context, enc []byte) ([]byte, error) {
	r, err := s.DecryptReader(bg, c, bytes.NewReader(enc))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func TestStreamSizes(t *testing.T) {
	for _, alg := range []Algorithm{XChaCha20Poly1305, AES256GCM} {
		s := svc(t, alg)
		for _, n := range []int{0, 1, DefaultChunk - 1, DefaultChunk, DefaultChunk + 1, 3 * DefaultChunk, 3*DefaultChunk + 17} {
			data := make([]byte, n)
			rand.Read(data)
			got, err := decStream(s, ctxA, encStream(t, s, ctxA, data))
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("alg %d size %d: %v", alg, n, err)
			}
		}
	}
}

func TestStreamSmallWritesAndReads(t *testing.T) {
	s := svc(t, 0)
	data := make([]byte, 200_000)
	rand.Read(data)
	var out bytes.Buffer
	w, _ := s.EncryptWriter(bg, ctxA, &out)
	for i := 0; i < len(data); i += 777 {
		end := i + 777
		if end > len(data) {
			end = len(data)
		}
		w.Write(data[i:end])
	}
	w.Close()
	r, _ := s.DecryptReader(bg, ctxA, &out)
	var got bytes.Buffer
	buf := make([]byte, 13)
	for {
		n, err := r.Read(buf)
		got.Write(buf[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(got.Bytes(), data) {
		t.Fatal("mismatch")
	}
}

func TestStreamAttacks(t *testing.T) {
	s := svc(t, 0)
	data := make([]byte, 3*DefaultChunk+500)
	rand.Read(data)
	enc := encStream(t, s, ctxA, data)
	over := 16 // poly1305 tag
	hdr := len(enc) - (3*(DefaultChunk+over) + 500 + over)
	chunkLen := DefaultChunk + over

	t.Run("truncate at chunk boundary", func(t *testing.T) {
		if _, err := decStream(s, ctxA, enc[:hdr+2*chunkLen]); err == nil {
			t.Fatal("truncation at chunk boundary went undetected")
		}
	})
	t.Run("truncate mid chunk", func(t *testing.T) {
		if _, err := decStream(s, ctxA, enc[:len(enc)-5]); err == nil {
			t.Fatal("mid-chunk truncation went undetected")
		}
	})
	t.Run("header only", func(t *testing.T) {
		if _, err := decStream(s, ctxA, enc[:hdr]); err == nil {
			t.Fatal("header-only stream accepted")
		}
	})
	t.Run("reorder chunks", func(t *testing.T) {
		m := append([]byte(nil), enc...)
		c0 := append([]byte(nil), m[hdr:hdr+chunkLen]...)
		copy(m[hdr:hdr+chunkLen], m[hdr+chunkLen:hdr+2*chunkLen])
		copy(m[hdr+chunkLen:hdr+2*chunkLen], c0)
		if _, err := decStream(s, ctxA, m); err == nil {
			t.Fatal("reordering went undetected")
		}
	})
	t.Run("append garbage", func(t *testing.T) {
		if _, err := decStream(s, ctxA, append(append([]byte(nil), enc...), 1, 2, 3)); err == nil {
			t.Fatal("trailing data accepted")
		}
	})
	t.Run("flip every region", func(t *testing.T) {
		for _, i := range []int{hdr + 3, hdr + chunkLen + 9, len(enc) - 1} {
			m := append([]byte(nil), enc...)
			m[i] ^= 0x80
			if _, err := decStream(s, ctxA, m); err == nil {
				t.Fatalf("flip at %d undetected", i)
			}
		}
	})
	t.Run("wrong context", func(t *testing.T) {
		if _, err := decStream(s, Context{Tenant: "evil", Collection: "User", Field: "cpf"}, enc); err == nil {
			t.Fatal("wrong tenant decrypted stream")
		}
		if _, err := decStream(s, Context{Tenant: "acme", Collection: "User", Field: "other"}, enc); err == nil {
			t.Fatal("wrong field decrypted stream")
		}
	})
}

func TestStreamRewrapHeader(t *testing.T) {
	s := svc(t, 0)
	data := make([]byte, 150_000)
	rand.Read(data)
	enc := encStream(t, s, ctxA, data)
	if _, err := s.Provider.Rotate(bg); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	changed, err := s.RewrapStreamHeader(bg, ctxA, bytes.NewReader(enc), &out)
	if err != nil || !changed {
		t.Fatalf("rewrap: %v %v", err, changed)
	}
	got, err := decStream(s, ctxA, out.Bytes())
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("decrypt after rewrap: %v", err)
	}
}
