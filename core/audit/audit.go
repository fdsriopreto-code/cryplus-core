// Package audit writes a JSON-lines trail of every key-using operation.
// It records who/what/when, never plaintext, ciphertext or key material.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

type Event struct {
	Time       time.Time `json:"ts"`
	Op         string    `json:"op"`
	Service    string    `json:"service,omitempty"`
	Tenant     string    `json:"tenant,omitempty"`
	Collection string    `json:"collection,omitempty"`
	Field      string    `json:"field,omitempty"`
	KEKVersion uint32    `json:"kek_version,omitempty"`
	Count      int       `json:"count,omitempty"`
	OK         bool      `json:"ok"`
	Code       string    `json:"code,omitempty"`
	Remote     string    `json:"remote,omitempty"`
}

// Options controls volume. The defaults log everything.
type Options struct {
	// Level "all" (default) logs every event. "denied" logs failures and administrative events (rotation, key export)
	// and drops successful encrypt/decrypt/blind/rewrap/stream operations.
	Level string
	// SampleEvery > 1 logs only one in N SUCCESSFUL data operations. Failures and administrative events are never sampled.
	SampleEvery uint64
}

// dataOps are the high-volume operations that Level/SampleEvery may thin out.
var dataOps = map[string]bool{
	"encrypt": true, "decrypt": true, "blind": true, "rewrap": true,
	"stream_encrypt": true, "stream_decrypt": true, "stream_rewrap": true,
}

type Logger struct {
	mu   sync.Mutex
	w    io.Writer
	opts Options
	n    atomic.Uint64
}

// New returns a Logger writing to w. A nil w discards events.
func New(w io.Writer) *Logger { return &Logger{w: w} }

// NewWithOptions is New with volume control.
func NewWithOptions(w io.Writer, o Options) *Logger { return &Logger{w: w, opts: o} }

func (l *Logger) Log(e Event) {
	if l == nil || l.w == nil {
		return
	}
	// Never thin out anything that failed or changed keys: that is what the trail is for.
	if e.OK && dataOps[e.Op] {
		if l.opts.Level == "denied" {
			return
		}
		if l.opts.SampleEvery > 1 && l.n.Add(1)%l.opts.SampleEvery != 0 {
			return
		}
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.w.Write(append(b, '\n'))
}

// RotatingFile is an append-only file that rolls over when it would exceed maxBytes, keeping `keep` old files
// (path.1 is the newest). Retention is therefore bounded by maxBytes * (keep+1).
type RotatingFile struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	keep     int
	f        *os.File
	size     int64
}

func OpenRotating(path string, maxBytes int64, keep int) (*RotatingFile, error) {
	r := &RotatingFile{path: path, maxBytes: maxBytes, keep: keep}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RotatingFile) open() error {
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(r.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, st.Size()
	return nil
}

func (r *RotatingFile) rotate() error {
	r.f.Close()
	if r.keep <= 0 {
		os.Remove(r.path)
	} else {
		os.Remove(fmt.Sprintf("%s.%d", r.path, r.keep))
		for i := r.keep - 1; i >= 1; i-- {
			os.Rename(fmt.Sprintf("%s.%d", r.path, i), fmt.Sprintf("%s.%d", r.path, i+1))
		}
		os.Rename(r.path, r.path+".1")
	}
	return r.open()
}

func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.maxBytes > 0 && r.size > 0 && r.size+int64(len(p)) > r.maxBytes {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}
