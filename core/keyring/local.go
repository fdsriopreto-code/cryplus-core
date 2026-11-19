package keyring

import (
	"bytes"
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

// Local keeps master keys in a JSON key file (mode 0600), optionally sealed
// at rest by a Sealer (passphrase, Vault, KMS).
//
// Several cryplus-core instances may share one key file (shared volume):
//
//   - exactly one "leader" rotates keys; the others run as followers
//     (SetFollower) and pick up new versions through Reload;
//   - Reload only ever ADDS versions. A file that changes or removes an
//     existing key, rolls the current version back, or changes the index
//     key is rejected, so a corrupted or tampered file cannot silently
//     replace keys that already encrypted data;
//   - Rotate takes a lock file and re-reads the file under it, so two
//     concurrent rotations cannot mint the same version number twice.
type Local struct {
	mu       sync.RWMutex
	path     string // empty = in-memory
	keys     map[uint32][]byte
	created  map[uint32]time.Time
	current  uint32
	indexKey []byte
	follower bool

	// Optional at-rest sealing of the key file.
	sealer    Sealer
	blobs     map[uint32][]byte // sealed form of each master key
	indexBlob []byte

	// last observed file state, for cheap change detection
	lastMod  time.Time
	lastSize int64
}

// ErrReadOnly is returned by Rotate on a follower instance.
var ErrReadOnly = errors.New("keyring: this instance is a follower and cannot rotate keys")

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
	return open(ctx, path, sealer, false)
}

// OpenFollower opens an existing key file read-only. It never creates the
// file and cannot rotate; call Reload (or run PollReload) to follow the leader.
func OpenFollower(ctx context.Context, path string, sealer Sealer) (*Local, error) {
	return open(ctx, path, sealer, true)
}

func open(ctx context.Context, path string, sealer Sealer, follower bool) (*Local, error) {
	l := &Local{path: path, sealer: sealer, follower: follower,
		keys: map[uint32][]byte{}, created: map[uint32]time.Time{}, blobs: map[uint32][]byte{}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if follower {
			return nil, fmt.Errorf("keyring: follower needs an existing key file at %s (start the leader first)", path)
		}
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
		l.observeLocked()
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	pf, err := l.parse(raw)
	if err != nil {
		return nil, err
	}
	for v, e := range pf.keys {
		k, err := l.unsealEntry(ctx, v, e)
		if err != nil {
			return nil, err
		}
		l.keys[v] = k
		l.created[v] = pf.created[v]
		if l.sealer != nil {
			l.blobs[v] = e
		}
	}
	l.current = pf.current
	ik, err := l.unsealIndex(ctx, pf.indexRaw)
	if err != nil {
		return nil, err
	}
	l.indexKey = ik
	if l.sealer != nil {
		l.indexBlob = pf.indexRaw
	}
	l.observeLocked()
	return l, nil
}

// parsed is a key file decoded but not yet unsealed.
type parsed struct {
	current  uint32
	keys     map[uint32][]byte // raw: the key itself, or the sealed blob
	created  map[uint32]time.Time
	indexRaw []byte
}

func (l *Local) parse(raw []byte) (*parsed, error) {
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		return nil, fmt.Errorf("keyring: parse %s: %w", l.path, err)
	}
	want := ""
	if l.sealer != nil {
		want = l.sealer.Name()
	}
	if kf.Sealed != want {
		return nil, fmt.Errorf("keyring: key file sealed=%q but provider configured for sealed=%q", kf.Sealed, want)
	}
	pf := &parsed{current: kf.Current, keys: map[uint32][]byte{}, created: map[uint32]time.Time{}}
	for k, v := range kf.Keys {
		n, err := strconv.ParseUint(k, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("keyring: bad version %q", k)
		}
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("keyring: key v%s is not base64", k)
		}
		pf.keys[uint32(n)] = b
		if ts, ok := kf.Created[k]; ok {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				pf.created[uint32(n)] = t
			}
		}
	}
	if _, ok := pf.keys[pf.current]; !ok {
		return nil, errors.New("keyring: current version missing from key file")
	}
	ik, err := base64.StdEncoding.DecodeString(kf.IndexKey)
	if err != nil {
		return nil, errors.New("keyring: index_key is not base64")
	}
	pf.indexRaw = ik
	return pf, nil
}

func (l *Local) unsealEntry(ctx context.Context, v uint32, e []byte) ([]byte, error) {
	k := e
	if l.sealer != nil {
		var err error
		if k, err = l.sealer.Open(ctx, e, masterAAD(v)); err != nil {
			return nil, fmt.Errorf("keyring: cannot unseal key v%d: %w", v, err)
		}
	}
	if len(k) != 32 {
		return nil, fmt.Errorf("keyring: key v%d is not 32 bytes", v)
	}
	return k, nil
}

func (l *Local) unsealIndex(ctx context.Context, raw []byte) ([]byte, error) {
	ik := raw
	if l.sealer != nil {
		var err error
		if ik, err = l.sealer.Open(ctx, raw, indexAAD); err != nil {
			return nil, fmt.Errorf("keyring: cannot unseal index key: %w", err)
		}
	}
	if len(ik) != 32 {
		return nil, errors.New("keyring: index_key must be 32 bytes")
	}
	return ik, nil
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
	if err := os.Rename(tmp.Name(), l.path); err != nil {
		return err
	}
	l.observeLocked()
	return nil
}

func (l *Local) observeLocked() {
	if l.path == "" {
		return
	}
	if st, err := os.Stat(l.path); err == nil {
		l.lastMod, l.lastSize = st.ModTime(), st.Size()
	}
}

// ---- reload (followers and leaders both) ------------------------------------

// Reload re-reads the key file if it changed and adopts new versions. It
// reports whether anything new was adopted. Safe to call concurrently and often.
func (l *Local) Reload(ctx context.Context) (bool, error) {
	if l.path == "" {
		return false, nil
	}
	st, err := os.Stat(l.path)
	if err != nil {
		return false, err
	}
	l.mu.RLock()
	same := st.ModTime().Equal(l.lastMod) && st.Size() == l.lastSize
	l.mu.RUnlock()
	if same {
		return false, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.reloadLocked(ctx)
}

func (l *Local) reloadLocked(ctx context.Context) (bool, error) {
	raw, err := os.ReadFile(l.path)
	if err != nil {
		return false, err
	}
	pf, err := l.parse(raw)
	if err != nil {
		return false, err
	}
	// Never let the file rewrite history.
	for v, k := range l.keys {
		e, ok := pf.keys[v]
		if !ok {
			return false, fmt.Errorf("keyring: reload rejected: key v%d disappeared from the file", v)
		}
		if l.sealer != nil {
			if !bytes.Equal(e, l.blobs[v]) {
				return false, fmt.Errorf("keyring: reload rejected: sealed key v%d changed", v)
			}
		} else if !bytes.Equal(e, k) {
			return false, fmt.Errorf("keyring: reload rejected: key v%d changed", v)
		}
	}
	if l.sealer != nil {
		if !bytes.Equal(pf.indexRaw, l.indexBlob) {
			return false, errors.New("keyring: reload rejected: index key changed")
		}
	} else if !bytes.Equal(pf.indexRaw, l.indexKey) {
		return false, errors.New("keyring: reload rejected: index key changed")
	}
	if pf.current < l.current {
		return false, fmt.Errorf("keyring: reload rejected: current version would go back from v%d to v%d", l.current, pf.current)
	}
	changed := false
	for v, e := range pf.keys {
		if _, ok := l.keys[v]; ok {
			continue
		}
		k, err := l.unsealEntry(ctx, v, e)
		if err != nil {
			return false, err
		}
		l.keys[v] = k
		l.created[v] = pf.created[v]
		if l.sealer != nil {
			l.blobs[v] = e
		}
		changed = true
	}
	if pf.current != l.current {
		l.current = pf.current
		changed = true
	}
	l.observeLocked()
	return changed, nil
}

// PollReload calls Reload every interval until ctx ends. onChange (optional)
// is told about adopted versions and about rejected files.
func (l *Local) PollReload(ctx context.Context, every time.Duration, onEvent func(changed bool, err error)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			changed, err := l.Reload(ctx)
			if onEvent != nil && (changed || err != nil) {
				onEvent(changed, err)
			}
		}
	}
}

// SetFollower marks this instance read-only for key rotation.
func (l *Local) SetFollower(b bool) {
	l.mu.Lock()
	l.follower = b
	l.mu.Unlock()
}

// ---- file lock for rotation ---------------------------------------------------

const lockStale = 30 * time.Second

func acquireLock(path string) (func(), error) {
	lock := path + ".lock"
	deadline := time.Now().Add(10 * time.Second)
	for {
		f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			fmt.Fprintf(f, "%d\n", os.Getpid())
			f.Close()
			return func() { os.Remove(lock) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if st, serr := os.Stat(lock); serr == nil && time.Since(st.ModTime()) > lockStale {
			os.Remove(lock) // stale lock from a crashed rotation
			continue
		}
		if time.Now().After(deadline) {
			return nil, errors.New("keyring: timed out waiting for the key file lock")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// ---- provider interface -----------------------------------------------------

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
	m, ok := l.keys[version]
	l.mu.RUnlock()
	if ok {
		return m, nil
	}
	// A ciphertext can reference a version minted by the leader a moment ago:
	// try one reload before giving up.
	if l.path != "" {
		if _, err := l.Reload(context.Background()); err == nil {
			l.mu.RLock()
			m, ok = l.keys[version]
			l.mu.RUnlock()
			if ok {
				return m, nil
			}
		}
	}
	return nil, ErrUnknownVersion
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
	l.mu.RLock()
	follower := l.follower
	l.mu.RUnlock()
	if follower {
		return 0, ErrReadOnly
	}
	if l.path != "" {
		unlock, err := acquireLock(l.path)
		if err != nil {
			return 0, err
		}
		defer unlock()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.path != "" {
		// Under the lock, see anything another process wrote, so the new
		// version number is really the next one.
		if _, err := l.reloadLocked(ctx); err != nil {
			return 0, err
		}
	}
	prevCur := l.current
	if err := l.addKeyLocked(); err != nil {
		return 0, err
	}
	err := l.sealAllLocked(ctx)
	if err == nil {
		err = l.saveLocked()
	}
	if err != nil {
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

// ExportTenantKEK implements Exporter.
func (l *Local) ExportTenantKEK(_ context.Context, version uint32, tenant string) ([]byte, uint32, error) {
	if version == 0 {
		version = l.CurrentVersion()
	}
	m, err := l.master(version)
	if err != nil {
		return nil, 0, err
	}
	k, err := tenantKEK(m, tenant)
	return k, version, err
}
