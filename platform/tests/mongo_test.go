package tests

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/platform"
)

// TestOpenMongoDisabled: empty URI = Mongo off → OpenMongo returns
// ErrMongoUnavailable, no client → server boots w/o database. Same non-fatal
// contract as iptools.OpenService w/ absent BINs.
func TestOpenMongoDisabled(t *testing.T) {
	m, err := platform.OpenMongo(context.Background(), "", "")
	if !errors.Is(err, platform.ErrMongoUnavailable) {
		t.Fatalf("OpenMongo(\"\") error = %v, want ErrMongoUnavailable", err)
	}
	if m != nil {
		t.Fatalf("OpenMongo(\"\") = %v, want nil *Mongo", m)
	}
}

// TestNilMongoIsSafe: nil *Mongo = valid "disabled" value. Every method must be
// nil-safe → callers can `defer m.Close(ctx)` + probe m.DB() w/o nil check, same
// as nil *iptools.Service.
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

// TestOpenMongoLive: integration test. Runs only when MONGODB_TEST_URI set (+
// server reachable), skips otherwise → CI, fresh clones, plain `make test` stay
// green. Mirrors BIN-dependent tests skipping w/ absent databases (ARCHITECTURE
// §9).
//
// Reads MONGODB_TEST_URI not app's MONGODB_URI on purpose: `make test` includes+
// exports .env → keying off MONGODB_URI fires live network call every run.
// Dedicated var keeps suite hermetic, makes hitting real server explicit opt-in
// (`MONGODB_TEST_URI=… go test ./platform/...`).
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
