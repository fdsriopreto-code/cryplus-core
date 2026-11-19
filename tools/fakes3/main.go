// fakes3 is a local S3-compatible server (in-memory) for tests. It is NOT AWS.
package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:9333", "listen address")
	flag.Parse()
	backend := s3mem.New()
	faker := gofakes3.New(backend)
	log.Printf("fakes3 listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, faker.Server()))
}
