// Command cryplus-core runs the Cryplus key-management and encryption
// sidecar. Applications talk to it through a thin SDK over local HTTP.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/fdsriopreto-code/cryplus-core/audit"
	"github.com/fdsriopreto-code/cryplus-core/envelope"
	"github.com/fdsriopreto-code/cryplus-core/keyring"
	"github.com/fdsriopreto-code/cryplus-core/server"
)

func main() {
	var (
		listen   = flag.String("listen", "127.0.0.1:7788", "address to listen on (loopback only unless --allow-remote)")
		remote   = flag.Bool("allow-remote", false, "allow listening on a non-loopback address (put TLS/mTLS in front!)")
		provider = flag.String("provider", "local", "key provider: local | vault | kms | memory")
		keyfile  = flag.String("keyfile", "", "local provider: key file path (default ./cryplus-keys.json)")
		auditf   = flag.String("audit-log", "cryplus-audit.jsonl", "audit log path ('-' for stderr, '' to disable)")
		alg      = flag.String("alg", "xchacha20", "payload cipher: xchacha20 | aes256gcm")
		dev      = flag.Bool("dev", false, "generate an ephemeral token and print it")
	)
	flag.Parse()

	token := os.Getenv("CRYPLUS_TOKEN")
	if token == "" && *dev {
		b := make([]byte, 24)
		rand.Read(b)
		token = hex.EncodeToString(b)
		fmt.Fprintf(os.Stderr, "CRYPLUS_TOKEN=%s\n", token)
	}
	if token == "" {
		log.Fatal("set CRYPLUS_TOKEN (min 16 chars) or pass --dev")
	}

	var p keyring.Provider
	var err error
	switch *provider {
	case "local":
		path := *keyfile
		if path == "" {
			path = "cryplus-keys.json"
		}
		if path, err = filepath.Abs(path); err == nil {
			if pass := os.Getenv("CRYPLUS_PASSPHRASE"); pass != "" {
				var sl keyring.Sealer
				if sl, err = keyring.NewPassphraseSealer(pass); err == nil {
					p, err = keyring.OpenSealed(context.Background(), path, sl)
				}
			} else {
				log.Println("WARNING: key file is stored unencrypted; set CRYPLUS_PASSPHRASE to seal it")
				p, err = keyring.OpenLocal(path)
			}
		}
	case "memory":
		log.Println("WARNING: memory provider — all data is unrecoverable after exit")
		p, err = keyring.NewMemory()
	case "vault":
		p, err = keyring.NewVaultFromEnv()
	case "kms":
		p, err = keyring.NewKMSFromEnv(context.Background())
	default:
		log.Fatalf("unknown provider %q", *provider)
	}
	if err != nil {
		log.Fatalf("provider: %v", err)
	}

	a := envelope.XChaCha20Poly1305
	switch *alg {
	case "xchacha20":
	case "aes256gcm":
		a = envelope.AES256GCM
	default:
		log.Fatalf("unknown --alg %q", *alg)
	}

	var aw io.Writer
	switch *auditf {
	case "":
	case "-":
		aw = os.Stderr
	default:
		f, err := os.OpenFile(*auditf, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			log.Fatalf("audit log: %v", err)
		}
		defer f.Close()
		aw = f
	}

	srv, err := server.New(envelope.New(p, a), audit.New(aw), token)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("cryplus-core listening on %s (provider=%s, kek v%d)", *listen, p.Name(), p.CurrentVersion())
	if err := srv.Serve(ctx, *listen, *remote); err != nil {
		log.Fatal(err)
	}
}
