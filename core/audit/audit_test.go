package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func lines(b *bytes.Buffer) []string {
	var out []string
	for _, l := range strings.Split(b.String(), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func TestDefaultLogsEverything(t *testing.T) {
	var b bytes.Buffer
	l := New(&b)
	for i := 0; i < 5; i++ {
		l.Log(Event{Op: "decrypt", OK: true})
	}
	if n := len(lines(&b)); n != 5 {
		t.Fatalf("got %d lines", n)
	}
}

func TestDeniedLevelKeepsFailuresAndAdminEvents(t *testing.T) {
	var b bytes.Buffer
	l := NewWithOptions(&b, Options{Level: "denied"})
	l.Log(Event{Op: "decrypt", OK: true})
	l.Log(Event{Op: "encrypt", OK: true})
	l.Log(Event{Op: "stream_decrypt", OK: true})
	l.Log(Event{Op: "decrypt", OK: false, Code: "decryption_failed"})
	l.Log(Event{Op: "rotate", OK: true})
	l.Log(Event{Op: "key_export", OK: true})
	l.Log(Event{Op: "auth", OK: false, Code: "unauthorized"})
	got := lines(&b)
	if len(got) != 4 {
		t.Fatalf("want failures + rotate + key_export (4), got %d:\n%s", len(got), b.String())
	}
	for _, l := range got {
		if strings.Contains(l, `"op":"encrypt"`) || (strings.Contains(l, `"op":"decrypt"`) && strings.Contains(l, `"ok":true`)) {
			t.Fatalf("a successful data operation was logged: %s", l)
		}
	}
}

func TestSamplingThinsOnlySuccessfulDataOperations(t *testing.T) {
	var b bytes.Buffer
	l := NewWithOptions(&b, Options{SampleEvery: 10})
	for i := 0; i < 100; i++ {
		l.Log(Event{Op: "decrypt", OK: true})
	}
	for i := 0; i < 7; i++ {
		l.Log(Event{Op: "decrypt", OK: false, Code: "decryption_failed"})
		l.Log(Event{Op: "key_export", OK: true})
	}
	ok, failed, admin := 0, 0, 0
	for _, ln := range lines(&b) {
		switch {
		case strings.Contains(ln, "key_export"):
			admin++
		case strings.Contains(ln, `"ok":false`):
			failed++
		default:
			ok++
		}
	}
	if ok != 10 || failed != 7 || admin != 7 {
		t.Fatalf("sampled ok=%d (want 10), failures=%d (want 7, never sampled), admin=%d (want 7)", ok, failed, admin)
	}
}

func TestRotatingFileBoundsDiskUse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	r, err := OpenRotating(path, 1000, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	l := New(r)
	for i := 0; i < 200; i++ {
		l.Log(Event{Op: "decrypt", Tenant: "acme", OK: true})
	}
	var total int64
	files, _ := filepath.Glob(path + "*")
	for _, f := range files {
		st, _ := os.Stat(f)
		total += st.Size()
		if st.Size() > 1100 {
			t.Fatalf("%s is %d bytes, over the limit", f, st.Size())
		}
	}
	if len(files) != 4 { // current + 3 kept
		t.Fatalf("want 4 files (current + keep=3), got %d: %v", len(files), files)
	}
	if total > 4*1100 {
		t.Fatalf("retention not bounded: %d bytes", total)
	}
	if _, err := os.Stat(path + ".4"); err == nil {
		t.Fatal("kept more files than asked")
	}
}

func TestRotatingFileIsSafeUnderConcurrencyAndResumesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	os.WriteFile(path, bytes.Repeat([]byte("x"), 400), 0o600)
	r, err := OpenRotating(path, 100_000, 2)
	if err != nil {
		t.Fatal(err)
	}
	l := New(r)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				l.Log(Event{Op: "decrypt", OK: true})
			}
		}()
	}
	wg.Wait()
	r.Close()
	raw, _ := os.ReadFile(path)
	if got := bytes.Count(raw, []byte("\n")); got != 800 {
		t.Fatalf("lost or merged lines under concurrency: %d", got)
	}
	if !bytes.HasPrefix(raw, bytes.Repeat([]byte("x"), 400)) {
		t.Fatal("existing content must be appended to, not replaced")
	}
}
