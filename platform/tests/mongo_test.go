package tests

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/platform"
)

// TestOpenMongoDisabled: an empty URI returns ErrMongoUnavailable and no client, so the server still boots.
func TestOpenMongoDisabled(t *testing.T) {
	m, err := platform.OpenMongo(context.Background(), "", "")
	if !errors.Is(err, platform.ErrMongoUnavailable) {
		t.Fatalf("OpenMongo(\"\") error = %v, want ErrMongoUnavailable", err)
	}
	if m != nil {
		t.Fatalf("OpenMongo(\"\") = %v, want nil *Mongo", m)
	}
}

// TestNilMongoIsSafe: callers may `defer m.Close(ctx)` and call m.DB() without a nil check.
func TestNilMongoIsSafe(t *testing.T) {
	var m *platform.Mongo
	ctx := context.Background()

	if got := m.DB(); got != nil {
		t.Errorf("nil Mongo DB() = %v, want nil", got)
	}
	if err := m.Close(ctx); err != nil {
		t.Errorf("nil Mongo Close() = %v, want nil", err)
	}
	if err := m.Ping(ctx); !errors.Is(err, platform.ErrMongoUnavailable) {
		t.Errorf("nil Mongo Ping() = %v, want ErrMongoUnavailable", err)
	}
	if err := m.EnsureDatabase(ctx); !errors.Is(err, platform.ErrMongoUnavailable) {
		t.Errorf("nil Mongo EnsureDatabase() = %v, want ErrMongoUnavailable", err)
	}
}

// TestOpenMongoLive reads MONGODB_TEST_URI, not MONGODB_URI, which `make test` exports from .env every run.
func TestOpenMongoLive(t *testing.T) {
	uri := os.Getenv("MONGODB_TEST_URI")
	if uri == "" {
		t.Skip("MONGODB_TEST_URI not set; skipping live MongoDB integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	m, err := platform.OpenMongo(ctx, uri, os.Getenv("MONGODB_DATABASE"))
	if err != nil {
		t.Fatalf("OpenMongo(live) error = %v", err)
	}
	defer m.Close(ctx)

	if m.DB() == nil {
		t.Fatal("live Mongo DB() = nil, want a database handle")
	}
	if err := m.Ping(ctx); err != nil {
		t.Fatalf("live Mongo Ping() = %v, want nil", err)
	}
	if err := m.EnsureDatabase(ctx); err != nil {
		t.Fatalf("live Mongo EnsureDatabase() = %v, want nil", err)
	}
}
