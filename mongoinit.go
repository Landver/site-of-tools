//go:build ignore

// Command mongo-init provisions the application database on the shared MongoDB
// server. MongoDB creates databases lazily, so an untouched "site-of-tools" never
// appears in `show dbs`; this connects with MONGODB_URI (from the environment or
// .env), creates the database explicitly via platform.Mongo.EnsureDatabase, then
// prints the server's database + collection listing to confirm.
//
// It is NOT part of the app build — the //go:build ignore tag excludes it from
// `go build ./...`, `go vet ./...`, and the test gate. Run it once from a host
// that can reach the server (optional now that the app writes on first request):
//
//	make mongo-init          # loads .env, then runs: go run mongoinit.go
//	# or directly:
//	MONGODB_URI='mongodb://user:pass@host/admin' go run mongoinit.go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Landver/site-of-tools/platform"
)

func main() {
	cfg := platform.Load() // loads .env, reads MONGODB_URI + MONGODB_DATABASE
	if cfg.MongoURI == "" {
		log.Fatal("MONGODB_URI is not set (add it to .env or pass it in the environment)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	m, err := platform.OpenMongo(ctx, cfg.MongoURI, cfg.MongoDatabase)
	if err != nil {
		log.Fatalf("open mongo: %v", err)
	}
	defer m.Close(ctx)

	if err := m.EnsureDatabase(ctx); err != nil {
		log.Fatalf("ensure database: %v", err)
	}
	fmt.Printf("ensured database %q\n", cfg.MongoDatabase)

	// Confirm by listing what the server now reports. An empty filter (bson doc)
	// matches everything.
	empty := map[string]any{}
	dbs, err := m.Client.ListDatabaseNames(ctx, empty)
	if err != nil {
		log.Fatalf("list databases: %v", err)
	}
	fmt.Printf("databases on server: %v\n", dbs)

	colls, err := m.DB().ListCollectionNames(ctx, empty)
	if err != nil {
		log.Fatalf("list collections: %v", err)
	}
	fmt.Printf("collections in %q: %v\n", cfg.MongoDatabase, colls)
}
