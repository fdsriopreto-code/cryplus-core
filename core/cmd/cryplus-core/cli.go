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
	"strings"
	"time"

	"github.com/fdsriopreto-code/cryplus-core/envelope"
	"github.com/fdsriopreto-code/cryplus-core/server"
	"github.com/fdsriopreto-code/cryplus-core/tlsutil"
)

// parseInterspersed parses flags that may appear before, between or after positional
// arguments (Go's flag package stops at the first positional), and returns the positionals.
func parseInterspersed(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			os.Exit(2)
		}
		if fs.NArg() == 0 {
			return pos
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// cryplus-core token new --name operax-api --roles crypt --tenants '*' --file tokens.json
func cmdToken(args []string) {
	if len(args) == 0 || args[0] != "new" {
		log.Fatal("usage: cryplus-core token new --name N [--roles crypt,admin] [--tenants '*'] [--file tokens.json]")
	}
	fs := flag.NewFlagSet("token new", flag.ExitOnError)
	name := fs.String("name", "", "service name (shows up in the audit log)")
	roles := fs.String("roles", "crypt", "comma-separated: crypt, admin")
	tenants := fs.String("tenants", "", "comma-separated tenant allowlist: '*', exact ids, or 'prefix*' (required)")
	file := fs.String("file", "", "tokens file to append to (created if missing)")
	fs.Parse(args[1:])
	if *name == "" || *tenants == "" {
		log.Fatal("--name and --tenants are required (use --tenants '*' for every tenant)")
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatal(err)
	}
	token := hex.EncodeToString(b)
	r, t := splitList(*roles), splitList(*tenants)
	if *file != "" {
		if err := server.AppendService(*file, *name, token, r, t); err != nil {
			log.Fatal(err)
		}
		fmt.Fprintf(os.Stderr, "added %q to %s (only the SHA-256 is stored there)\n", *name, *file)
	} else {
		fmt.Fprintf(os.Stderr, "add this to your tokens file:\n{\"name\":%q,\"token_sha256\":%q,\"roles\":%q,\"tenants\":%q}\n", *name, server.HashToken(token), r, t)
	}
	fmt.Fprintln(os.Stderr, "\nThe token below is shown ONCE. Store it in the service's secret manager:")
	fmt.Println(token)
}

// cryplus-core tls dev-certs --out ./certs --host cryplus.internal
func cmdTLS(args []string) {
	if len(args) == 0 || args[0] != "dev-certs" {
		log.Fatal("usage: cryplus-core tls dev-certs --out DIR [--host H1,H2] [--client-name NAME] [--days N]")
	}
	fs := flag.NewFlagSet("tls dev-certs", flag.ExitOnError)
	out := fs.String("out", "certs", "output directory")
	hosts := fs.String("host", "", "extra server DNS names / IPs (localhost and 127.0.0.1 are always included)")
	cn := fs.String("client-name", "cryplus-client", "client certificate common name")
	days := fs.Int("days", 90, "validity in days")
	fs.Parse(args[1:])
	if err := tlsutil.DevCerts(*out, splitList(*hosts), *cn, time.Duration(*days)*24*time.Hour); err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s/{ca.pem,server.pem,server-key.pem,client.pem,client-key.pem}\nFor development only: use your own PKI in production.\n", *out)
}

// cryplus-core file encrypt|decrypt --tenant T --collection C --field F IN OUT
func cmdFile(args []string) {
	if len(args) == 0 || (args[0] != "encrypt" && args[0] != "decrypt") {
		log.Fatal("usage: cryplus-core file encrypt|decrypt --tenant T [--collection C] [--field F] IN OUT")
	}
	op := args[0]
	fs := flag.NewFlagSet("file "+op, flag.ExitOnError)
	tenant := fs.String("tenant", "", "tenant the data belongs to (required)")
	coll := fs.String("collection", "", "collection / bucket (part of the encryption context)")
	field := fs.String("field", "", "field / object key (part of the encryption context)")
	provider := fs.String("provider", "local", "key provider: local | vault | kms")
	keyfile := fs.String("keyfile", "", "key file path")
	alg := fs.String("alg", "xchacha20", "cipher for encrypt: xchacha20 | aes256gcm")
	pos := parseInterspersed(fs, args[1:])
	if *tenant == "" || len(pos) != 2 {
		log.Fatal("need --tenant and two arguments: IN OUT ('-' for stdin/stdout)")
	}

	// Offline use never creates keys and never rotates: it opens the existing key file as a follower.
	p, err := providerFlags{*provider, *keyfile, true}.build(context.Background())
	if err != nil {
		log.Fatalf("provider: %v", err)
	}
	a := envelope.XChaCha20Poly1305
	if *alg == "aes256gcm" {
		a = envelope.AES256GCM
	}
	svc := envelope.New(p, a)
	c := envelope.Context{Tenant: *tenant, Collection: *coll, Field: *field}

	in := io.Reader(os.Stdin)
	if pos[0] != "-" {
		f, err := os.Open(pos[0])
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		in = f
	}
	var w io.Writer = os.Stdout
	var outFile *os.File
	finalPath := pos[1]
	if finalPath != "-" {
		// write to a temp file and rename, so a failed decrypt never leaves a plausible-looking partial file
		outFile, err = os.OpenFile(finalPath+".partial", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			log.Fatal(err)
		}
		w = outFile
	}
	fail := func(err error) {
		if outFile != nil {
			outFile.Close()
			os.Remove(finalPath + ".partial")
		}
		log.Fatal(err)
	}

	ctx := context.Background()
	switch op {
	case "encrypt":
		ew, err := svc.EncryptWriter(ctx, c, w)
		if err != nil {
			fail(err)
		}
		if _, err := io.Copy(ew, in); err != nil {
			fail(err)
		}
		if err := ew.Close(); err != nil {
			fail(err)
		}
	case "decrypt":
		dr, err := svc.DecryptReader(ctx, c, in)
		if err != nil {
			fail(err)
		}
		if _, err := io.Copy(w, dr); err != nil {
			fail(fmt.Errorf("decrypt failed (data corrupt, truncated, wrong tenant/context, or wrong key): %w", err))
		}
	}
	if outFile != nil {
		if err := outFile.Close(); err != nil {
			fail(err)
		}
		if err := os.Rename(finalPath+".partial", finalPath); err != nil {
			log.Fatal(err)
		}
	}
}
