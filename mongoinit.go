//go:build ignore

// Command mongo-init provisions app DB on shared MongoDB server. Mongo
// creates DBs lazily → untouched "site-of-tools" never shows in `show dbs`;
// connects w/ MONGODB_URI (env or .env), creates DB explicitly via
// platform.Mongo.EnsureDatabase, then prints server's DB + collection
// listing to confirm.
//
// NOT part of app build — //go:build ignore tag excludes it from
// `go build ./...`, `go vet ./...`, test gate. Run once from host that can
// reach server (optional now, app writes on first request):
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

	// Confirm by listing what server now reports. Empty filter (bson doc)
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
