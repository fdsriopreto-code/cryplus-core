package keyring

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Local keeps master keys in a JSON key file (mode 0600). It is meant for
// development and single-node deployments; use Vault or KMS when the key
// file would sit on the same disk as the data it protects.
type Local struct {
	mu       sync.RWMutex
	path     string // empty = in-memory
	keys     map[uint32][]byte
	created  map[uint32]time.Time
	current  uint32
	indexKey []byte

	// Optional at-rest sealing of the key file (passphrase, Vault, KMS).
	sealer    Sealer
	blobs     map[uint32][]byte // sealed form of each master key
	indexBlob []byte
}

type keyFile struct {
	Current  uint32            `json:"current"`
	Sealed   string            `json:"sealed,omitempty"`
	Keys     map[string]string `json:"keys"`
	Created  map[string]string `json:"created_at"`
	IndexKey string            `json:"index_key"`
}

func masterAAD(v uint32) []byte { return []byte("cryplus/master/" + strconv.FormatUint(uint64(v), 10)) }

var indexAAD = []byte("cryplus/index")

// NewMemory returns an ephemeral provider with a single fresh key. Data
// encrypted with it is unrecoverable after the process exits.
func NewMemory() (*Local, error) {
	l := &Local{keys: map[uint32][]byte{}, created: map[uint32]time.Time{}, blobs: map[uint32][]byte{}}
	if err := l.addKeyLocked(); err != nil {
		return nil, err
	}
	l.indexKey = make([]byte, 32)
	if _, err := rand.Read(l.indexKey); err != nil {
		return nil, err
	}
	return l, nil
}

// OpenLocal loads the key file at path, creating it with a fresh key
// version 1 when it does not exist yet.
func OpenLocal(path string) (*Local, error) {
	return OpenSealed(context.Background(), path, nil)
}

// OpenSealed is OpenLocal with the master keys sealed at rest by sealer
// (nil = stored in the clear, 0600). The unsealed keys live only in memory.
func OpenSealed(ctx context.Context, path string, sealer Sealer) (*Local, error) {
	l := &Local{path: path, sealer: sealer, keys: map[uint32][]byte{}, created: map[uint32]time.Time{}, blobs: map[uint32][]byte{}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := l.addKeyLocked(); err != nil {
			return nil, err
		}
		l.indexKey = make([]byte, 32)
		if _, err := rand.Read(l.indexKey); err != nil {
			return nil, err
		}
		if err := l.sealAllLocked(ctx); err != nil {
			return nil, err
		}
		if err := l.saveLocked(); err != nil {
			return nil, err
		}
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		return nil, fmt.Errorf("keyring: parse %s: %w", path, err)
	}
	want := ""
	if sealer != nil {
		want = sealer.Name()
	}
	if kf.Sealed != want {
		return nil, fmt.Errorf("keyring: key file sealed=%q but provider configured for sealed=%q", kf.Sealed, want)
	}
	for k, v := range kf.Keys {
		n, err := strconv.ParseUint(k, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("keyring: bad version %q", k)
		}
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("keyring: key v%s is not base64", k)
		}
		if sealer != nil {
			l.blobs[uint32(n)] = b
			if b, err = sealer.Open(ctx, b, masterAAD(uint32(n))); err != nil {
				return nil, fmt.Errorf("keyring: cannot unseal key v%s: %w", k, err)
			}
		}
		if len(b) != 32 {
			return nil, fmt.Errorf("keyring: key v%s is not 32 bytes", k)
		}
		l.keys[uint32(n)] = b
		if ts, ok := kf.Created[k]; ok {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				l.created[uint32(n)] = t
			}
		}
	}
	l.current = kf.Current
	if _, ok := l.keys[l.current]; !ok {
		return nil, errors.New("keyring: current version missing from key file")
	}
	ik, err := base64.StdEncoding.DecodeString(kf.IndexKey)
	if err != nil {
		return nil, errors.New("keyring: index_key is not base64")
	}
	if sealer != nil {
		l.indexBlob = ik
		if ik, err = sealer.Open(ctx, ik, indexAAD); err != nil {
			return nil, fmt.Errorf("keyring: cannot unseal index key: %w", err)
		}
	}
	if len(ik) != 32 {
		return nil, errors.New("keyring: index_key must be 32 bytes")
	}
	l.indexKey = ik
	return l, nil
}

// sealAllLocked seals any key that has no sealed blob yet.
func (l *Local) sealAllLocked(ctx context.Context) error {
	if l.sealer == nil {
		return nil
	}
	for v, k := range l.keys {
		if _, ok := l.blobs[v]; ok {
			continue
		}
		b, err := l.sealer.Seal(ctx, k, masterAAD(v))
		if err != nil {
			return fmt.Errorf("keyring: seal key v%d: %w", v, err)
		}
		l.blobs[v] = b
	}
	if l.indexBlob == nil {
		b, err := l.sealer.Seal(ctx, l.indexKey, indexAAD)
		if err != nil {
			return fmt.Errorf("keyring: seal index key: %w", err)
		}
		l.indexBlob = b
	}
	return nil
}

func (l *Local) addKeyLocked() error {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return err
	}
	var next uint32 = 1
	for v := range l.keys {
		if v >= next {
			next = v + 1
		}
	}
	l.keys[next] = k
	l.created[next] = time.Now().UTC()
	l.current = next
	return nil
}

func (l *Local) saveLocked() error {
	if l.path == "" {
		return nil
	}
	kf := keyFile{
		Current:  l.current,
		Keys:     map[string]string{},
		Created:  map[string]string{},
		IndexKey: base64.StdEncoding.EncodeToString(l.indexKey),
	}
	if l.sealer != nil {
		kf.Sealed = l.sealer.Name()
		kf.IndexKey = base64.StdEncoding.EncodeToString(l.indexBlob)
	}
	for v, k := range l.keys {
		s := strconv.FormatUint(uint64(v), 10)
		if l.sealer != nil {
			kf.Keys[s] = base64.StdEncoding.EncodeToString(l.blobs[v])
		} else {
			kf.Keys[s] = base64.StdEncoding.EncodeToString(k)
		}
		kf.Created[s] = l.created[v].Format(time.RFC3339)
	}
	raw, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(l.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".keys-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), l.path)
}

func (l *Local) Name() string {
	if l.sealer != nil {
		return "local+" + l.sealer.Name()
	}
	return "local"
}

func (l *Local) CurrentVersion() uint32 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.current
}

func (l *Local) master(version uint32) ([]byte, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	m, ok := l.keys[version]
	if !ok {
		return nil, ErrUnknownVersion
	}
	return m, nil
}

func (l *Local) Wrap(_ context.Context, version uint32, tenant string, dek, aad []byte) ([]byte, error) {
	m, err := l.master(version)
	if err != nil {
		return nil, err
	}
	k, err := tenantKEK(m, tenant)
	if err != nil {
		return nil, err
	}
	return aeadWrap(k, dek, wrapAAD(version, tenant, aad), rand.Reader)
}

func (l *Local) Unwrap(_ context.Context, version uint32, tenant string, wrapped, aad []byte) ([]byte, error) {
	m, err := l.master(version)
	if err != nil {
		return nil, err
	}
	k, err := tenantKEK(m, tenant)
	if err != nil {
		return nil, err
	}
	return aeadUnwrap(k, wrapped, wrapAAD(version, tenant, aad))
}

func (l *Local) IndexKey(_ context.Context, tenant, field string) ([]byte, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return indexKeyFrom(l.indexKey, tenant, field)
}

func (l *Local) Rotate(ctx context.Context) (uint32, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	prevCur := l.current
	if err := l.addKeyLocked(); err != nil {
		return 0, err
	}
	err := l.sealAllLocked(ctx)
	if err == nil {
		err = l.saveLocked()
	}
	if err != nil {
		// roll back so memory and disk agree
		delete(l.keys, l.current)
		delete(l.created, l.current)
		delete(l.blobs, l.current)
		l.current = prevCur
		return 0, err
	}
	return l.current, nil
}

func (l *Local) Status() []KeyVersion {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]KeyVersion, 0, len(l.keys))
	for v := range l.keys {
		out = append(out, KeyVersion{Version: v, Current: v == l.current, CreatedAt: l.created[v]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out
}
