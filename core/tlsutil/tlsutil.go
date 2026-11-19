// Package tlsutil builds the server TLS configuration (TLS 1.3, optional
// mutual TLS, certificates re-read when they change on disk) and generates
// throwaway development certificates.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type reloader struct {
	certFile, keyFile string
	mu                sync.Mutex
	cert              *tls.Certificate
	certMod, keyMod   time.Time
}

func (r *reloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cs, err1 := os.Stat(r.certFile)
	ks, err2 := os.Stat(r.keyFile)
	if err1 != nil || err2 != nil {
		if r.cert != nil {
			return r.cert, nil // keep serving the last good certificate
		}
		return nil, errors.Join(err1, err2)
	}
	if r.cert == nil || !cs.ModTime().Equal(r.certMod) || !ks.ModTime().Equal(r.keyMod) {
		c, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
		if err != nil {
			if r.cert != nil {
				return r.cert, nil
			}
			return nil, err
		}
		r.cert, r.certMod, r.keyMod = &c, cs.ModTime(), ks.ModTime()
	}
	return r.cert, nil
}

// ServerConfig returns a TLS 1.3 server config. With clientCAFile set, clients
// must present a certificate signed by that CA (mutual TLS). The server
// certificate is re-read when the files change, so renewal needs no restart.
func ServerConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	r := &reloader{certFile: certFile, keyFile: keyFile}
	if _, err := r.get(nil); err != nil {
		return nil, fmt.Errorf("tls: load certificate: %w", err)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: r.get}
	if clientCAFile != "" {
		pem, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("tls: read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("tls: no certificates found in client CA file")
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode)
}

func newKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	return n
}

// DevCerts writes a private CA plus a server and a client certificate into
// dir. FOR DEVELOPMENT AND TESTS: in production use your own PKI. Files:
// ca.pem, server.pem/server-key.pem, client.pem/client-key.pem. The CA private
// key is not written (nothing can mint more certificates afterwards).
func DevCerts(dir string, serverHosts []string, clientName string, valid time.Duration) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if valid <= 0 {
		valid = 90 * 24 * time.Hour
	}
	now := time.Now().Add(-time.Minute)
	caKey, err := newKey()
	if err != nil {
		return err
	}
	caTmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "cryplus dev CA"},
		NotBefore: now, NotAfter: now.Add(valid), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	if err := writePEM(filepath.Join(dir, "ca.pem"), "CERTIFICATE", caDER, 0o644); err != nil {
		return err
	}

	issue := func(name string, tmpl *x509.Certificate) error {
		k, err := newKey()
		if err != nil {
			return err
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &k.PublicKey, caKey)
		if err != nil {
			return err
		}
		kd, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return err
		}
		if err := writePEM(filepath.Join(dir, name+".pem"), "CERTIFICATE", der, 0o644); err != nil {
			return err
		}
		return writePEM(filepath.Join(dir, name+"-key.pem"), "PRIVATE KEY", kd, 0o600)
	}

	srv := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "cryplus-core"},
		NotBefore: now, NotAfter: now.Add(valid),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	for _, h := range serverHosts {
		if ip := net.ParseIP(h); ip != nil {
			srv.IPAddresses = append(srv.IPAddresses, ip)
		} else {
			srv.DNSNames = append(srv.DNSNames, h)
		}
	}
	if err := issue("server", srv); err != nil {
		return err
	}
	if clientName == "" {
		clientName = "cryplus-client"
	}
	cli := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: clientName},
		NotBefore: now, NotAfter: now.Add(valid),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	return issue("client", cli)
}
