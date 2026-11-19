package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Roles.
const (
	RoleCrypt = "crypt" // encrypt, decrypt, blind index, rewrap, batch, streams
	RoleAdmin = "admin" // key status and rotation
	RoleKeys  = "keys"  // may fetch tenant keys to cache them in the SDK (needs --allow-key-export on the server)
)

// Service is one authenticated caller (e.g. "operax-api", "backup-job").
type Service struct {
	Name    string
	Roles   map[string]bool
	Tenants []string // "*", exact ids, or "prefix*"
}

func (s *Service) AllowsTenant(t string) bool {
	for _, p := range s.Tenants {
		switch {
		case p == "*":
			return true
		case strings.HasSuffix(p, "*") && strings.HasPrefix(t, strings.TrimSuffix(p, "*")):
			return true
		case p == t:
			return true
		}
	}
	return false
}

type entry struct {
	svc  *Service
	hash [32]byte
}

// Auth maps bearer tokens to services. Only SHA-256 hashes of tokens are ever
// stored, so a leaked tokens file does not leak usable credentials. Tokens are
// meant to be 256-bit random values (see `cryplus-core token new`), for which a
// plain hash is the right construction.
type Auth struct {
	mu      sync.RWMutex
	entries []entry

	path    string
	lastMod time.Time
	lastSz  int64
}

type tokensFile struct {
	Services []struct {
		Name        string   `json:"name"`
		TokenSHA256 string   `json:"token_sha256"`
		Roles       []string `json:"roles"`
		Tenants     []string `json:"tenants"`
	} `json:"services"`
}

// NewSingleTokenAuth is the simple mode: one shared token, all roles, all tenants.
func NewSingleTokenAuth(token string) (*Auth, error) {
	if len(token) < 16 {
		return nil, errors.New("server: token must be at least 16 characters")
	}
	a := &Auth{}
	a.entries = []entry{{
		svc:  &Service{Name: "default", Roles: map[string]bool{RoleCrypt: true, RoleAdmin: true, RoleKeys: true}, Tenants: []string{"*"}},
		hash: sha256.Sum256([]byte(token)),
	}}
	return a, nil
}

// LoadAuthFile reads a tokens file (see tokensFile) and keeps watching it
// through Poll, so adding or revoking a service needs no restart.
func LoadAuthFile(path string) (*Auth, error) {
	a := &Auth{path: path}
	if err := a.reload(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Auth) reload() error {
	raw, err := os.ReadFile(a.path)
	if err != nil {
		return err
	}
	var tf tokensFile
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&tf); err != nil {
		return fmt.Errorf("tokens file: %w", err)
	}
	if len(tf.Services) == 0 {
		return errors.New("tokens file: no services defined")
	}
	var es []entry
	names := map[string]bool{}
	for _, s := range tf.Services {
		if s.Name == "" || names[s.Name] {
			return fmt.Errorf("tokens file: service name %q is empty or duplicated", s.Name)
		}
		names[s.Name] = true
		h, err := hex.DecodeString(s.TokenSHA256)
		if err != nil || len(h) != 32 {
			return fmt.Errorf("tokens file: %s: token_sha256 must be 64 hex chars", s.Name)
		}
		svc := &Service{Name: s.Name, Roles: map[string]bool{}, Tenants: s.Tenants}
		for _, r := range s.Roles {
			if r != RoleCrypt && r != RoleAdmin && r != RoleKeys {
				return fmt.Errorf("tokens file: %s: unknown role %q", s.Name, r)
			}
			svc.Roles[r] = true
		}
		if len(svc.Roles) == 0 {
			return fmt.Errorf("tokens file: %s: needs at least one role", s.Name)
		}
		if len(svc.Tenants) == 0 {
			return fmt.Errorf("tokens file: %s: tenants must be listed explicitly (use [\"*\"] for all)", s.Name)
		}
		var e entry
		e.svc = svc
		copy(e.hash[:], h)
		es = append(es, e)
	}
	st, _ := os.Stat(a.path)
	a.mu.Lock()
	a.entries = es
	if st != nil {
		a.lastMod, a.lastSz = st.ModTime(), st.Size()
	}
	a.mu.Unlock()
	return nil
}

// Poll re-reads the tokens file when it changes. A broken file is reported via
// onErr and the previous, valid set stays in force.
func (a *Auth) Poll(ctx context.Context, every time.Duration, onErr func(error), onReload func(n int)) {
	if a.path == "" {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			st, err := os.Stat(a.path)
			if err != nil {
				if onErr != nil {
					onErr(err)
				}
				continue
			}
			a.mu.RLock()
			same := st.ModTime().Equal(a.lastMod) && st.Size() == a.lastSz
			a.mu.RUnlock()
			if same {
				continue
			}
			if err := a.reload(); err != nil {
				if onErr != nil {
					onErr(err)
				}
				// remember the bad state so we do not spam, but keep serving the old set
				a.mu.Lock()
				a.lastMod, a.lastSz = st.ModTime(), st.Size()
				a.mu.Unlock()
				continue
			}
			if onReload != nil {
				a.mu.RLock()
				n := len(a.entries)
				a.mu.RUnlock()
				onReload(n)
			}
		}
	}
}

// Identify returns the service owning token, or nil. It compares against every
// entry in constant time so response timing does not reveal which one matched.
func (a *Auth) Identify(token string) *Service {
	h := sha256.Sum256([]byte(token))
	a.mu.RLock()
	defer a.mu.RUnlock()
	var found *Service
	for i := range a.entries {
		if subtle.ConstantTimeCompare(h[:], a.entries[i].hash[:]) == 1 {
			found = a.entries[i].svc
		}
	}
	return found
}

// HashToken returns the hex SHA-256 to put in a tokens file.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// AppendService adds a service to the tokens file at path (creating it, mode
// 0600). Only the SHA-256 of token is written.
func AppendService(path, name, token string, roles, tenants []string) error {
	var tf tokensFile
	if raw, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(raw, &tf); err != nil {
			return fmt.Errorf("tokens file: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, s := range tf.Services {
		if s.Name == name {
			return fmt.Errorf("service %q already exists in %s", name, path)
		}
	}
	tf.Services = append(tf.Services, struct {
		Name        string   `json:"name"`
		TokenSHA256 string   `json:"token_sha256"`
		Roles       []string `json:"roles"`
		Tenants     []string `json:"tenants"`
	}{name, HashToken(token), roles, tenants})
	raw, err := json.MarshalIndent(tf, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
