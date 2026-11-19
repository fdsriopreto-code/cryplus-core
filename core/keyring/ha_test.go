package keyring

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func twoInstances(t *testing.T, sealer Sealer) (leader, follower *Local, path string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "keys.json")
	leader, err := OpenSealed(bg, path, sealer)
	if err != nil {
		t.Fatal(err)
	}
	follower, err = OpenFollower(bg, path, sealer)
	if err != nil {
		t.Fatal(err)
	}
	return leader, follower, path
}

func TestFollowerPicksUpLeaderRotation(t *testing.T) {
	for name, mk := range map[string]func() Sealer{
		"plain":      func() Sealer { return nil },
		"passphrase": func() Sealer { s, _ := NewPassphraseSealer("a long enough passphrase"); return s },
	} {
		t.Run(name, func(t *testing.T) {
			leader, follower, _ := twoInstances(t, mk())
			dek := bytes.Repeat([]byte{4}, 32)

			if _, err := follower.Rotate(bg); !errors.Is(err, ErrReadOnly) {
				t.Fatalf("follower rotate must be refused, got %v", err)
			}
			if _, err := leader.Rotate(bg); err != nil {
				t.Fatal(err)
			}
			// Wrap under the NEW version on the leader; the follower has not reloaded yet.
			w2, err := leader.Wrap(bg, 2, "t", dek, nil)
			if err != nil {
				t.Fatal(err)
			}
			// Unwrap on the follower triggers one on-demand reload for the unknown version.
			got, err := follower.Unwrap(bg, 2, "t", w2, nil)
			if err != nil || !bytes.Equal(got, dek) {
				t.Fatalf("follower could not read v2 written by the leader: %v", err)
			}
			if follower.CurrentVersion() != 2 {
				t.Fatalf("follower current=%d want 2", follower.CurrentVersion())
			}
			// Index keys agree across instances (blind index must be identical everywhere).
			a, _ := leader.IndexKey(bg, "t", "f")
			b, _ := follower.IndexKey(bg, "t", "f")
			if !bytes.Equal(a, b) {
				t.Fatal("instances disagree on the blind index key")
			}
		})
	}
}

func TestFollowerRefusesToCreateKeyFile(t *testing.T) {
	_, err := OpenFollower(bg, filepath.Join(t.TempDir(), "missing.json"), nil)
	if err == nil || !strings.Contains(err.Error(), "leader") {
		t.Fatalf("want 'start the leader first', got %v", err)
	}
}

func TestReloadRejectsRewrittenHistory(t *testing.T) {
	leader, follower, path := twoInstances(t, nil)
	if _, err := leader.Rotate(bg); err != nil {
		t.Fatal(err)
	}
	if _, err := follower.Reload(bg); err != nil {
		t.Fatal(err)
	}
	orig, _ := os.ReadFile(path)
	var kf keyFile
	json.Unmarshal(orig, &kf)

	write := func(mut func(*keyFile)) {
		var c keyFile
		json.Unmarshal(orig, &c)
		mut(&c)
		raw, _ := json.Marshal(c)
		os.WriteFile(path, raw, 0o600)
		// make sure the mtime/size observably changed
		os.Chtimes(path, time.Now().Add(time.Minute), time.Now().Add(time.Minute))
	}

	cases := map[string]func(*keyFile){
		"replaced key v1":     func(c *keyFile) { c.Keys["1"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)) },
		"removed key v1":      func(c *keyFile) { delete(c.Keys, "1") },
		"rolled back current": func(c *keyFile) { c.Current = 1 },
		"changed index key":   func(c *keyFile) { c.IndexKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)) },
	}
	for name, mut := range cases {
		write(mut)
		before := follower.CurrentVersion()
		changed, err := follower.Reload(bg)
		if err == nil || changed {
			t.Fatalf("%s: reload must be rejected (changed=%v err=%v)", name, changed, err)
		}
		if follower.CurrentVersion() != before {
			t.Fatalf("%s: state changed despite rejection", name)
		}
		// and the instance keeps serving with the keys it already trusts
		w, err := follower.Wrap(bg, 1, "t", bytes.Repeat([]byte{1}, 32), nil)
		if err != nil {
			t.Fatalf("%s: wrap failed after rejected reload: %v", name, err)
		}
		if _, err := leader.Unwrap(bg, 1, "t", w, nil); err != nil {
			t.Fatalf("%s: keys diverged: %v", name, err)
		}
	}
}

func TestConcurrentRotationNeverReusesAVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	a, err := OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := OpenLocal(path) // a second LEADER by mistake: the lock must still protect us
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	versions := make(chan uint32, 20)
	for _, p := range []*Local{a, b} {
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(p *Local) {
				defer wg.Done()
				v, err := p.Rotate(bg)
				if err != nil {
					t.Error(err)
					return
				}
				versions <- v
			}(p)
		}
	}
	wg.Wait()
	close(versions)
	seen := map[uint32]bool{}
	for v := range versions {
		if seen[v] {
			t.Fatalf("version %d minted twice: two different keys under one number", v)
		}
		seen[v] = true
	}
	if len(seen) != 10 {
		t.Fatalf("expected 10 distinct versions, got %d", len(seen))
	}
	// the file on disk is consistent and complete
	c, err := OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.CurrentVersion() != 11 || len(c.Status()) != 11 {
		t.Fatalf("final state: current=%d versions=%d", c.CurrentVersion(), len(c.Status()))
	}
	if _, err := os.Stat(path + ".lock"); err == nil {
		t.Fatal("lock file left behind")
	}
}

func TestStaleLockIsBroken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	l, _ := OpenLocal(path)
	os.WriteFile(path+".lock", []byte("999999\n"), 0o600)
	old := time.Now().Add(-2 * lockStale)
	os.Chtimes(path+".lock", old, old)
	if _, err := l.Rotate(bg); err != nil {
		t.Fatalf("a crashed rotation's stale lock must not wedge rotation forever: %v", err)
	}
}

func TestPollReloadAdoptsInBackground(t *testing.T) {
	leader, follower, _ := twoInstances(t, nil)
	ctx, cancel := contextWithCancel()
	defer cancel()
	got := make(chan bool, 4)
	go follower.PollReload(ctx, 20*time.Millisecond, func(changed bool, err error) {
		if changed {
			got <- true
		}
	})
	if _, err := leader.Rotate(bg); err != nil {
		t.Fatal(err)
	}
	select {
	case <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("follower did not adopt the rotation in the background")
	}
	if follower.CurrentVersion() != 2 {
		t.Fatalf("current=%d", follower.CurrentVersion())
	}
}

func contextWithCancel() (context.Context, context.CancelFunc) {
	return context.WithCancel(context.Background())
}
