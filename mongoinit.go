//go:build ignore

// Command mongo-init creates the app database up front, since Mongo creates one lazily (make mongo-init).
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Landver/site-of-tools/platform"
)

func main() {
	cfg := platform.Load()
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

	// An empty filter matches everything.
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
