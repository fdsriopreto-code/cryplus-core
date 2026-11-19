// Command cryplus-core runs the Cryplus key-management and encryption
// service. Applications talk to it through a thin SDK over HTTP(S).
//
//	cryplus-core [serve flags]            run the service
//	cryplus-core token new ...            create a service token
//	cryplus-core tls dev-certs ...        generate development TLS certificates
//	cryplus-core file encrypt|decrypt ... offline file encryption (backups, disaster recovery)
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
	"strings"
	"syscall"
	"time"

	"github.com/fdsriopreto-code/cryplus-core/audit"
	"github.com/fdsriopreto-code/cryplus-core/envelope"
	"github.com/fdsriopreto-code/cryplus-core/keyring"
	"github.com/fdsriopreto-code/cryplus-core/server"
	"github.com/fdsriopreto-code/cryplus-core/tlsutil"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "token":
			cmdToken(os.Args[2:])
			return
		case "tls":
			cmdTLS(os.Args[2:])
			return
		case "file":
			cmdFile(os.Args[2:])
			return
		case "help", "-h", "--help":
			usage()
			return
		}
	}
	serve()
}

func usage() {
	fmt.Fprint(os.Stderr, `cryplus-core: envelope-encryption key service

Usage:
  cryplus-core [flags]                       run the service (see flags below)
  cryplus-core token new --name N [--roles crypt,admin] [--tenants '*'] [--file tokens.json]
  cryplus-core tls dev-certs --out DIR [--host H1,H2] [--client-name NAME]
  cryplus-core file encrypt|decrypt --tenant T [--collection C] [--field F] IN OUT   ('-' = stdin/stdout)

Run "cryplus-core --help" for the service flags.
`)
}

// secretFromEnv returns $NAME, or the trimmed contents of the file named by $NAME_FILE
// (the Docker/Kubernetes secrets convention, which keeps the value out of `docker inspect`).
func secretFromEnv(name string) (string, error) {
	if v := os.Getenv(name); v != "" {
		return v, nil
	}
	if f := os.Getenv(name + "_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", fmt.Errorf("%s_FILE: %w", name, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return "", nil
}

// providerFlags are shared by the service and the offline file commands.
type providerFlags struct {
	provider, keyfile string
	follower          bool
}

func (p providerFlags) build(ctx context.Context) (keyring.Provider, error) {
	switch p.provider {
	case "local":
		path := p.keyfile
		if path == "" {
			path = "cryplus-keys.json"
		}
		path, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		var sl keyring.Sealer
		pass, perr := secretFromEnv("CRYPLUS_PASSPHRASE")
		if perr != nil {
			return nil, perr
		}
		if pass != "" {
			if sl, err = keyring.NewPassphraseSealer(pass); err != nil {
				return nil, err
			}
		} else {
			log.Println("WARNING: key file is stored unencrypted; set CRYPLUS_PASSPHRASE to seal it")
		}
		if p.follower {
			return keyring.OpenFollower(ctx, path, sl)
		}
		return keyring.OpenSealed(ctx, path, sl)
	case "memory":
		log.Println("WARNING: memory provider: all data is unrecoverable after exit")
		return keyring.NewMemory()
	case "vault":
		return keyring.NewVaultFromEnv(p.follower)
	case "kms":
		return keyring.NewKMSFromEnv(ctx, p.follower)
	}
	return nil, fmt.Errorf("unknown provider %q", p.provider)
}

func serve() {
	var (
		listen   = flag.String("listen", "127.0.0.1:7788", "address to listen on")
		remote   = flag.Bool("allow-remote", false, "allow a non-loopback address (REQUIRES --tls-cert/--tls-key)")
		provider = flag.String("provider", "local", "key provider: local | vault | kms | memory")
		keyfile  = flag.String("keyfile", "", "key file path (default ./cryplus-keys.json)")
		follower = flag.Bool("follower", false, "read-only instance: never creates or rotates keys, follows the leader's key file")
		reload   = flag.Duration("reload-interval", 5*time.Second, "how often to re-read the key file and tokens file")
		auditf   = flag.String("audit-log", "cryplus-audit.jsonl", "audit log path ('-' for stderr, '' to disable)")
		alg      = flag.String("alg", "xchacha20", "payload cipher: xchacha20 | aes256gcm")
		dev      = flag.Bool("dev", false, "generate an ephemeral token and print it")
		tokens   = flag.String("tokens-file", "", "per-service tokens file (see 'token new'); otherwise CRYPLUS_TOKEN is used")
		tlsCert  = flag.String("tls-cert", "", "TLS certificate (PEM); enables HTTPS (TLS 1.3 only)")
		tlsKey   = flag.String("tls-key", "", "TLS private key (PEM)")
		clientCA = flag.String("client-ca", "", "CA bundle (PEM): require and verify client certificates (mutual TLS)")
	)
	flag.Usage = usage
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var auth *server.Auth
	var err error
	if *tokens != "" {
		if auth, err = server.LoadAuthFile(*tokens); err != nil {
			log.Fatalf("tokens file: %v", err)
		}
		go auth.Poll(ctx, *reload,
			func(e error) { log.Printf("tokens file NOT reloaded (keeping previous set): %v", e) },
			func(n int) { log.Printf("tokens file reloaded: %d service(s)", n) })
	} else {
		token, terr := secretFromEnv("CRYPLUS_TOKEN")
		if terr != nil {
			log.Fatal(terr)
		}
		if token == "" && *dev {
			b := make([]byte, 24)
			rand.Read(b)
			token = hex.EncodeToString(b)
			fmt.Fprintf(os.Stderr, "CRYPLUS_TOKEN=%s\n", token)
		}
		if token == "" {
			log.Fatal("set CRYPLUS_TOKEN or CRYPLUS_TOKEN_FILE (min 16 chars), use --tokens-file, or pass --dev")
		}
		if auth, err = server.NewSingleTokenAuth(token); err != nil {
			log.Fatal(err)
		}
	}

	p, err := providerFlags{*provider, *keyfile, *follower}.build(ctx)
	if err != nil {
		log.Fatalf("provider: %v", err)
	}
	if l, ok := p.(*keyring.Local); ok {
		go l.PollReload(ctx, *reload, func(changed bool, err error) {
			if err != nil {
				log.Printf("key file NOT reloaded (keeping the keys already trusted): %v", err)
			} else if changed {
				log.Printf("key file reloaded: current KEK v%d", l.CurrentVersion())
			}
		})
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

	var opts server.ServeOptions
	opts.AllowRemote = *remote
	if *tlsCert != "" || *tlsKey != "" {
		if opts.TLS, err = tlsutil.ServerConfig(*tlsCert, *tlsKey, *clientCA); err != nil {
			log.Fatal(err)
		}
	} else if *clientCA != "" {
		log.Fatal("--client-ca needs --tls-cert and --tls-key")
	}

	srv := server.NewWithAuth(envelope.New(p, a), audit.New(aw), auth)
	mode := "http"
	if opts.TLS != nil {
		mode = "https/TLS1.3"
		if *clientCA != "" {
			mode += "+mTLS"
		}
	}
	role := "leader"
	if *follower {
		role = "follower"
	}
	log.Printf("cryplus-core listening on %s (%s, provider=%s, %s, kek v%d)", *listen, mode, p.Name(), role, p.CurrentVersion())
	if err := srv.Serve(ctx, *listen, opts); err != nil {
		log.Fatal(err)
	}
}
