// Package server exposes the envelope service over an HTTP API so any language
// can use it through a thin SDK. All routes except /healthz require a bearer
// token that maps to a Service with roles and a tenant allowlist. Off-host
// access requires TLS (optionally mutual TLS).
package server

import (
	"context"
	"crypto/tls"
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

type ctxKey struct{}

type Server struct {
	Svc   *envelope.Service
	Audit *audit.Logger
	Auth  *Auth
	mux   *http.ServeMux
}

// New builds a server with a single shared token (all roles, all tenants).
func New(svc *envelope.Service, a *audit.Logger, token string) (*Server, error) {
	auth, err := NewSingleTokenAuth(token)
	if err != nil {
		return nil, err
	}
	return NewWithAuth(svc, a, auth), nil
}

// NewWithAuth builds a server with per-service tokens.
func NewWithAuth(svc *envelope.Service, a *audit.Logger, auth *Auth) *Server {
	s := &Server{Svc: svc, Audit: a, Auth: auth, mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "provider": svc.Provider.Name()})
	})
	s.mux.HandleFunc("POST /v1/encrypt", s.guard(RoleCrypt, s.single("encrypt")))
	s.mux.HandleFunc("POST /v1/decrypt", s.guard(RoleCrypt, s.single("decrypt")))
	s.mux.HandleFunc("POST /v1/blind-index", s.guard(RoleCrypt, s.single("blind")))
	s.mux.HandleFunc("POST /v1/rewrap", s.guard(RoleCrypt, s.single("rewrap")))
	s.mux.HandleFunc("POST /v1/batch", s.guard(RoleCrypt, s.batch))
	s.mux.HandleFunc("GET /v1/keys", s.guard(RoleAdmin, s.keys))
	s.mux.HandleFunc("POST /v1/keys/rotate", s.guard(RoleAdmin, s.rotate))
	s.mux.HandleFunc("POST /v1/stream/encrypt", s.guard(RoleCrypt, s.streamEncrypt))
	s.mux.HandleFunc("POST /v1/stream/decrypt", s.guard(RoleCrypt, s.streamDecrypt))
	s.mux.HandleFunc("POST /v1/stream/rewrap", s.guard(RoleCrypt, s.streamRewrap))
	return s
}

func (s *Server) Handler() http.Handler { return s.mux }

// ServeOptions control how the API is exposed.
type ServeOptions struct {
	// AllowRemote permits non-loopback addresses. It additionally REQUIRES TLS.
	AllowRemote bool
	// TLS enables HTTPS (use tlsutil.ServerConfig; add a client CA for mTLS).
	TLS *tls.Config
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Serve runs the API on addr until ctx ends.
func (s *Server) Serve(ctx context.Context, addr string, o ServeOptions) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if !isLoopback(host) {
		if !o.AllowRemote {
			return errors.New("server: refusing to listen on a non-loopback address without --allow-remote")
		}
		if o.TLS == nil {
			return errors.New("server: --allow-remote requires TLS (--tls-cert/--tls-key); plain HTTP is only allowed on loopback")
		}
	}
	srv := &http.Server{
		Addr: addr, Handler: s.mux, TLSConfig: o.TLS,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	errc := make(chan error, 1)
	go func() {
		if o.TLS != nil {
			errc <- srv.ListenAndServeTLS("", "") // certificates come from TLSConfig.GetCertificate
		} else {
			errc <- srv.ListenAndServe()
		}
	}()
	select {
	case <-ctx.Done():
		sc, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(sc)
	case err := <-errc:
		return err
	}
}

// guard authenticates the caller and checks the route's role.
func (s *Server) guard(role string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		svc := s.Auth.Identify(tok)
		if svc == nil {
			s.Audit.Log(audit.Event{Op: "auth", OK: false, Code: "unauthorized", Remote: remoteHost(r.RemoteAddr)})
			writeErr(w, 401, "unauthorized")
			return
		}
		if !svc.Roles[role] {
			s.Audit.Log(audit.Event{Op: "auth", Service: svc.Name, OK: false, Code: "role_forbidden", Remote: remoteHost(r.RemoteAddr)})
			writeErr(w, 403, "role_forbidden")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, svc)))
	}
}

func serviceOf(r *http.Request) *Service {
	svc, _ := r.Context().Value(ctxKey{}).(*Service)
	return svc
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

var (
	errBadOp           = errors.New("bad_op")
	errTenantForbidden = errors.New("tenant_forbidden")
)

func (s *Server) run(ctx context.Context, svc *Service, remote string, rq opReq) opRes {
	var res opRes
	var err error
	c := rq.Context
	switch {
	case svc != nil && !svc.AllowsTenant(c.Tenant):
		err = errTenantForbidden
	case rq.Op == "encrypt":
		var pt []byte
		if pt, err = base64.StdEncoding.DecodeString(rq.Data); err == nil {
			res.Data, err = s.Svc.Encrypt(ctx, c, pt)
		}
	case rq.Op == "decrypt":
		var pt []byte
		if pt, err = s.Svc.Decrypt(ctx, c, rq.Data); err == nil {
			res.Data = base64.StdEncoding.EncodeToString(pt)
		}
	case rq.Op == "blind":
		var v []byte
		if v, err = base64.StdEncoding.DecodeString(rq.Data); err == nil {
			res.Data, err = s.Svc.BlindIndex(ctx, c, v)
		}
	case rq.Op == "rewrap":
		res.Data, res.Changed, err = s.Svc.Rewrap(ctx, c, rq.Data)
	default:
		err = errBadOp
	}
	code := ""
	if err != nil {
		code = errCode(err)
		res = opRes{Error: code}
	}
	ev := audit.Event{Op: rq.Op, Service: svcName(svc), Tenant: c.Tenant, Collection: c.Collection, Field: c.Field, OK: err == nil, Code: code, Remote: remoteHost(remote)}
	if err == nil && (rq.Op == "decrypt" || rq.Op == "rewrap") {
		if info, ierr := envelope.Inspect(rq.Data); ierr == nil {
			ev.KEKVersion = info.KEKVersion
		}
	}
	s.Audit.Log(ev)
	return res
}

func svcName(s *Service) string {
	if s == nil {
		return ""
	}
	return s.Name
}

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
	case errors.Is(err, errTenantForbidden):
		return "tenant_forbidden"
	case errors.Is(err, keyring.ErrUnknownVersion):
		return "unknown_key_version"
	case errors.Is(err, keyring.ErrReadOnly):
		return "read_only_instance"
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
		res := s.run(r.Context(), serviceOf(r), r.RemoteAddr, rq)
		if res.Error != "" {
			writeJSON(w, statusFor(res.Error), res)
			return
		}
		writeJSON(w, 200, res)
	}
}

func statusFor(code string) int {
	switch code {
	case "decryption_failed", "tenant_forbidden", "role_forbidden":
		return 403
	case "internal_error":
		return 500
	case "read_only_instance":
		return 409
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
	svc := serviceOf(r)
	out := make([]opRes, len(in.Ops))
	for i, op := range in.Ops {
		out[i] = s.run(r.Context(), svc, r.RemoteAddr, op)
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
	code := ""
	if err != nil {
		code = errCode(err)
	}
	s.Audit.Log(audit.Event{Op: "rotate", Service: svcName(serviceOf(r)), KEKVersion: v, OK: err == nil, Code: code, Remote: remoteHost(r.RemoteAddr)})
	if err != nil {
		writeErr(w, statusFor(code), code)
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
	s.Audit.Log(audit.Event{Op: op, Service: svcName(serviceOf(r)), Tenant: c.Tenant, Collection: c.Collection, Field: c.Field, OK: err == nil, Code: code, Remote: remoteHost(r.RemoteAddr)})
}

// streamAllowed enforces the tenant allowlist before any stream work starts.
func (s *Server) streamAllowed(w http.ResponseWriter, r *http.Request, op string, c envelope.Context) bool {
	if svc := serviceOf(r); svc != nil && !svc.AllowsTenant(c.Tenant) {
		s.streamLog(op, c, r, errTenantForbidden)
		writeErr(w, 403, "tenant_forbidden")
		return false
	}
	return true
}

func (s *Server) streamEncrypt(w http.ResponseWriter, r *http.Request) {
	c := streamCtx(r)
	_ = http.NewResponseController(w).EnableFullDuplex()
	if !s.streamAllowed(w, r, "stream_encrypt", c) {
		return
	}
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
	if !s.streamAllowed(w, r, "stream_decrypt", c) {
		return
	}
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
	if !s.streamAllowed(w, r, "stream_rewrap", c) {
		return
	}
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
