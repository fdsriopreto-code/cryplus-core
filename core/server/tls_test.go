package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fdsriopreto-code/cryplus-core/envelope"
	"github.com/fdsriopreto-code/cryplus-core/keyring"
	"github.com/fdsriopreto-code/cryplus-core/tlsutil"
)

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func clientTLS(t *testing.T, dir, caFile, certName string, version uint16) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pem, _ := os.ReadFile(filepath.Join(dir, caFile))
	pool.AppendCertsFromPEM(pem)
	cfg := &tls.Config{RootCAs: pool, MinVersion: version, MaxVersion: version}
	if version == 0 {
		cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS13, 0
	}
	if certName != "" {
		c, err := tls.LoadX509KeyPair(filepath.Join(dir, certName+".pem"), filepath.Join(dir, certName+"-key.pem"))
		if err != nil {
			t.Fatal(err)
		}
		cfg.Certificates = []tls.Certificate{c}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
}

func startTLS(t *testing.T, cfgFn func(dir string) *tls.Config) (addr, dir string) {
	t.Helper()
	dir = t.TempDir()
	if err := tlsutil.DevCerts(dir, nil, "operax-api", time.Hour); err != nil {
		t.Fatal(err)
	}
	p, _ := keyring.NewMemory()
	s, _ := New(envelope.New(p, 0), nil, tok)
	addr = freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.Serve(ctx, addr, ServeOptions{TLS: cfgFn(dir)})
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return addr, dir
}

func TestTLS13ServerAndRejectsOlderTLS(t *testing.T) {
	addr, dir := startTLS(t, func(d string) *tls.Config {
		cfg, err := tlsutil.ServerConfig(filepath.Join(d, "server.pem"), filepath.Join(d, "server-key.pem"), "")
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	})
	c := clientTLS(t, dir, "ca.pem", "", 0)
	res, err := c.Get("https://" + addr + "/healthz")
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("https healthz: %v", err)
	}
	if res.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("negotiated 0x%x, want TLS 1.3", res.TLS.Version)
	}
	// a TLS 1.2-only client must be refused
	old := clientTLS(t, dir, "ca.pem", "", tls.VersionTLS12)
	if _, err := old.Get("https://" + addr + "/healthz"); err == nil {
		t.Fatal("server accepted a TLS 1.2 connection")
	}
	// a client that does not trust our CA must be refused by its own verification
	rogue := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool()}}, Timeout: 3 * time.Second}
	if _, err := rogue.Get("https://" + addr + "/healthz"); err == nil {
		t.Fatal("client trusted an unknown CA")
	}
	// plain HTTP to the TLS port must not work
	if r, err := http.Get("http://" + addr + "/healthz"); err == nil && r.StatusCode == 200 {
		t.Fatal("plain HTTP served on the TLS port")
	}
}

func TestMutualTLS(t *testing.T) {
	addr, dir := startTLS(t, func(d string) *tls.Config {
		cfg, err := tlsutil.ServerConfig(filepath.Join(d, "server.pem"), filepath.Join(d, "server-key.pem"), filepath.Join(d, "ca.pem"))
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	})
	// with a valid client certificate: works (and the bearer token is still required)
	good := clientTLS(t, dir, "ca.pem", "client", 0)
	res, err := good.Get("https://" + addr + "/healthz")
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("mTLS with valid client cert failed: %v", err)
	}
	req, _ := http.NewRequest("GET", "https://"+addr+"/v1/keys", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if r, err := good.Do(req); err != nil || r.StatusCode != 200 {
		t.Fatalf("authenticated call over mTLS: %v", err)
	}
	// no client certificate: the TLS handshake itself is rejected
	if _, err := clientTLS(t, dir, "ca.pem", "", 0).Get("https://" + addr + "/healthz"); err == nil {
		t.Fatal("server accepted a client without a certificate")
	}
	// a certificate signed by a DIFFERENT CA: rejected
	other := t.TempDir()
	if err := tlsutil.DevCerts(other, nil, "attacker", time.Hour); err != nil {
		t.Fatal(err)
	}
	evil := clientTLS(t, dir, "ca.pem", "", 0)
	c, _ := tls.LoadX509KeyPair(filepath.Join(other, "client.pem"), filepath.Join(other, "client-key.pem"))
	evil.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{c}
	if _, err := evil.Get("https://" + addr + "/healthz"); err == nil {
		t.Fatal("server accepted a client certificate from an untrusted CA")
	}
}

func TestRemoteRequiresTLS(t *testing.T) {
	p, _ := keyring.NewMemory()
	s, _ := New(envelope.New(p, 0), nil, tok)
	if err := s.Serve(context.Background(), "0.0.0.0:0", ServeOptions{AllowRemote: true}); err == nil || !strings.Contains(err.Error(), "requires TLS") {
		t.Fatalf("remote without TLS must be refused, got %v", err)
	}
	if err := s.Serve(context.Background(), "0.0.0.0:0", ServeOptions{}); err == nil || !strings.Contains(err.Error(), "allow-remote") {
		t.Fatalf("remote without --allow-remote must be refused, got %v", err)
	}
}

func TestCertificateRenewalWithoutRestart(t *testing.T) {
	dir := t.TempDir()
	if err := tlsutil.DevCerts(dir, nil, "c", time.Hour); err != nil {
		t.Fatal(err)
	}
	cfg, err := tlsutil.ServerConfig(filepath.Join(dir, "server.pem"), filepath.Join(dir, "server-key.pem"), "")
	if err != nil {
		t.Fatal(err)
	}
	c1, _ := cfg.GetCertificate(nil)
	first := c1.Leaf
	_ = first
	serial1 := c1.Certificate[0]

	// "renew": write a brand new pair over the same paths
	dir2 := t.TempDir()
	tlsutil.DevCerts(dir2, nil, "c", time.Hour)
	for _, f := range []string{"server.pem", "server-key.pem"} {
		b, _ := os.ReadFile(filepath.Join(dir2, f))
		os.WriteFile(filepath.Join(dir, f), b, 0o600)
		os.Chtimes(filepath.Join(dir, f), time.Now().Add(time.Minute), time.Now().Add(time.Minute))
	}
	c2, err := cfg.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(c2.Certificate[0]) == string(serial1) {
		t.Fatal("renewed certificate was not picked up")
	}
	// a broken replacement must not take the service down: keep the last good cert
	os.WriteFile(filepath.Join(dir, "server.pem"), []byte("garbage"), 0o600)
	os.Chtimes(filepath.Join(dir, "server.pem"), time.Now().Add(2*time.Minute), time.Now().Add(2*time.Minute))
	c3, err := cfg.GetCertificate(nil)
	if err != nil || string(c3.Certificate[0]) != string(c2.Certificate[0]) {
		t.Fatalf("broken renewal must keep serving the last good certificate: %v", err)
	}
}
