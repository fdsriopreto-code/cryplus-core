// Package audit writes a JSON-lines trail of every key-using operation.
// It records who/what/when, never plaintext, ciphertext or key material.
package audit

import (
	"encoding/json"
	"io"
	"sync"
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

type Logger struct {
	mu sync.Mutex
	w  io.Writer
}

// New returns a Logger writing to w. A nil w discards events.
func New(w io.Writer) *Logger { return &Logger{w: w} }

func (l *Logger) Log(e Event) {
	if l == nil || l.w == nil {
		return
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
