// Package server exposes the envelope service over a local HTTP API so any
// language can use it through a thin SDK. All routes except /healthz require
// a bearer token.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/fdsriopreto-code/cryplus-core/audit"
	"github.com/fdsriopreto-code/cryplus-core/envelope"
	"github.com/fdsriopreto-code/cryplus-core/keyring"
)

const (
	maxJSONBody = 32 << 20 // 32 MiB per JSON request
	maxBatchOps = 10_000
)

type Server struct {
	Svc   *envelope.Service
	Audit *audit.Logger
	Token string
	mux   *http.ServeMux
}

func New(svc *envelope.Service, a *audit.Logger, token string) (*Server, error) {
	if len(token) < 16 {
		return nil, errors.New("server: token must be at least 16 characters")
	}
	s := &Server{Svc: svc, Audit: a, Token: token, mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "provider": svc.Provider.Name()})
	})
	s.mux.HandleFunc("POST /v1/encrypt", s.auth(s.single("encrypt")))
	s.mux.HandleFunc("POST /v1/decrypt", s.auth(s.single("decrypt")))
	s.mux.HandleFunc("POST /v1/blind-index", s.auth(s.single("blind")))
	s.mux.HandleFunc("POST /v1/rewrap", s.auth(s.single("rewrap")))
	s.mux.HandleFunc("POST /v1/batch", s.auth(s.batch))
	s.mux.HandleFunc("GET /v1/keys", s.auth(s.keys))
	s.mux.HandleFunc("POST /v1/keys/rotate", s.auth(s.rotate))
	s.mux.HandleFunc("POST /v1/stream/encrypt", s.auth(s.streamEncrypt))
	s.mux.HandleFunc("POST /v1/stream/decrypt", s.auth(s.streamDecrypt))
	s.mux.HandleFunc("POST /v1/stream/rewrap", s.auth(s.streamRewrap))
	return s, nil
}

func (s *Server) Handler() http.Handler { return s.mux }

// Serve runs the API on addr. Refuses non-loopback addresses unless allowRemote.
func (s *Server) Serve(ctx context.Context, addr string, allowRemote bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); !allowRemote && (host != "localhost" && (ip == nil || !ip.IsLoopback())) {
		return errors.New("server: refusing to listen on a non-loopback address without --allow-remote")
	}
	srv := &http.Server{
		Addr: addr, Handler: s.mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
		sc, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(sc)
	case err := <-errc:
		return err
	}
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	want := []byte(s.Token)
	return func(w http.ResponseWriter, r *http.Request) {
		got := []byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if subtle.ConstantTimeCompare(got, want) != 1 {
			s.Audit.Log(audit.Event{Op: "auth", OK: false, Code: "unauthorized", Remote: r.RemoteAddr})
			writeErr(w, 401, "unauthorized")
			return
		}
		next(w, r)
	}
}

type opReq struct {
	Op      string           `json:"op,omitempty"`
	Context envelope.Context `json:"context"`
	Data    string           `json:"data,omitempty"` // b64 plaintext, or ciphertext text
}

type opRes struct {
	Data    string `json:"data"`
	Changed bool   `json:"changed,omitempty"`
	Error   string `json:"error,omitempty"`
}

func (s *Server) run(ctx context.Context, remote string, rq opReq) opRes {
	var res opRes
	var err error
	c := rq.Context
	switch rq.Op {
	case "encrypt":
		var pt []byte
		if pt, err = base64.StdEncoding.DecodeString(rq.Data); err == nil {
			res.Data, err = s.Svc.Encrypt(ctx, c, pt)
		}
	case "decrypt":
		var pt []byte
		if pt, err = s.Svc.Decrypt(ctx, c, rq.Data); err == nil {
			res.Data = base64.StdEncoding.EncodeToString(pt)
		}
	case "blind":
		var v []byte
		if v, err = base64.StdEncoding.DecodeString(rq.Data); err == nil {
			res.Data, err = s.Svc.BlindIndex(ctx, c, v)
		}
	case "rewrap":
		res.Data, res.Changed, err = s.Svc.Rewrap(ctx, c, rq.Data)
	default:
		err = errBadOp
	}
	code := ""
	if err != nil {
		code = errCode(err)
		res = opRes{Error: code}
	}
	ev := audit.Event{Op: rq.Op, Tenant: c.Tenant, Collection: c.Collection, Field: c.Field, OK: err == nil, Code: code, Remote: remoteHost(remote)}
	if err == nil && (rq.Op == "decrypt" || rq.Op == "rewrap") {
		if info, ierr := envelope.Inspect(rq.Data); ierr == nil {
			ev.KEKVersion = info.KEKVersion
		}
	}
	s.Audit.Log(ev)
	return res
}

var errBadOp = errors.New("bad_op")

func errCode(err error) string {
	switch {
	case errors.Is(err, envelope.ErrDecrypt):
		return "decryption_failed"
	case errors.Is(err, envelope.ErrFormat):
		return "malformed_ciphertext"
	case errors.Is(err, envelope.ErrContext):
		return "tenant_required"
	case errors.Is(err, errBadOp):
		return "bad_op"
	case errors.Is(err, keyring.ErrUnknownVersion):
		return "unknown_key_version"
	}
	var b64 base64.CorruptInputError
	if errors.As(err, &b64) {
		return "bad_base64"
	}
	return "internal_error"
}

func (s *Server) single(op string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var rq opReq
		if !readJSON(w, r, &rq) {
			return
		}
		rq.Op = op
		res := s.run(r.Context(), r.RemoteAddr, rq)
		if res.Error != "" {
			writeJSON(w, statusFor(res.Error), res)
			return
		}
		writeJSON(w, 200, res)
	}
}

func statusFor(code string) int {
	switch code {
	case "decryption_failed":
		return 403
	case "internal_error":
		return 500
	}
	return 400
}

func (s *Server) batch(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Ops []opReq `json:"ops"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if len(in.Ops) > maxBatchOps {
		writeErr(w, 400, "batch_too_large")
		return
	}
	out := make([]opRes, len(in.Ops))
	for i, op := range in.Ops {
		out[i] = s.run(r.Context(), r.RemoteAddr, op)
	}
	writeJSON(w, 200, map[string]any{"results": out})
}

func (s *Server) keys(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"provider": s.Svc.Provider.Name(),
		"current":  s.Svc.Provider.CurrentVersion(),
		"versions": s.Svc.Provider.Status(),
	})
}

func (s *Server) rotate(w http.ResponseWriter, r *http.Request) {
	v, err := s.Svc.Provider.Rotate(r.Context())
	s.Audit.Log(audit.Event{Op: "rotate", KEKVersion: v, OK: err == nil, Remote: remoteHost(r.RemoteAddr)})
	if err != nil {
		writeErr(w, 500, "internal_error")
		return
	}
	writeJSON(w, 200, map[string]any{"version": v})
}

func streamCtx(r *http.Request) envelope.Context {
	return envelope.Context{
		Tenant:     r.Header.Get("X-Cryplus-Tenant"),
		Collection: r.Header.Get("X-Cryplus-Collection"),
		Field:      r.Header.Get("X-Cryplus-Field"),
		RecordID:   r.Header.Get("X-Cryplus-Record"),
	}
}

func (s *Server) streamLog(op string, c envelope.Context, r *http.Request, err error) {
	code := ""
	if err != nil {
		code = errCode(err)
		if errors.Is(err, envelope.ErrStream) {
			code = "malformed_stream"
		}
	}
	s.Audit.Log(audit.Event{Op: op, Tenant: c.Tenant, Collection: c.Collection, Field: c.Field, OK: err == nil, Code: code, Remote: remoteHost(r.RemoteAddr)})
}

func (s *Server) streamEncrypt(w http.ResponseWriter, r *http.Request) {
	c := streamCtx(r)
	_ = http.NewResponseController(w).EnableFullDuplex()
	w.Header().Set("Content-Type", "application/octet-stream")
	ew, err := s.Svc.EncryptWriter(r.Context(), c, w)
	if err != nil {
		s.streamLog("stream_encrypt", c, r, err)
		writeErr(w, 400, errCode(err))
		return
	}
	_, err = io.Copy(ew, r.Body)
	if err == nil {
		err = ew.Close()
	}
	s.streamLog("stream_encrypt", c, r, err)
}

func (s *Server) streamDecrypt(w http.ResponseWriter, r *http.Request) {
	c := streamCtx(r)
	_ = http.NewResponseController(w).EnableFullDuplex()
	dr, err := s.Svc.DecryptReader(r.Context(), c, r.Body)
	if err != nil {
		s.streamLog("stream_decrypt", c, r, err)
		code := errCode(err)
		if errors.Is(err, envelope.ErrStream) {
			code = "malformed_stream"
		}
		writeErr(w, statusFor(code), code)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	// Plaintext is released chunk by chunk, only after each chunk authenticates.
	// If a later chunk fails, the connection is aborted so the client sees a
	// failed transfer instead of a clean-looking short body.
	_, err = io.Copy(w, dr)
	s.streamLog("stream_decrypt", c, r, err)
	if err != nil {
		panic(http.ErrAbortHandler)
	}
}

func (s *Server) streamRewrap(w http.ResponseWriter, r *http.Request) {
	c := streamCtx(r)
	_ = http.NewResponseController(w).EnableFullDuplex()
	w.Header().Set("Content-Type", "application/octet-stream")
	_, err := s.Svc.RewrapStreamHeader(r.Context(), c, r.Body, w)
	s.streamLog("stream_rewrap", c, r, err)
	if err != nil {
		panic(http.ErrAbortHandler)
	}
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, 400, "bad_request")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func remoteHost(a string) string {
	h, _, err := net.SplitHostPort(a)
	if err != nil {
		return a
	}
	return h
}
