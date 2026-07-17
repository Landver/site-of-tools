package platform

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

// DefaultMongoDatabase is the application database on the shared MongoDB server
// (mongodb.corpberry.com). Config.MongoDatabase defaults to this; override with
// MONGODB_DATABASE. Note this is *not* the database in the connection string's
// path (that segment names the auth database — "/admin" — which is separate from
// the application database selected here).
const DefaultMongoDatabase = "site-of-tools"

// mongoServerSelectionTimeout bounds how long OpenMongo waits to find a reachable
// server, so a down/unreachable host fails fast at startup instead of blocking on
// the driver's 30s default. It does not cap ordinary query latency (which stays
// governed by the caller's context).
const mongoServerSelectionTimeout = 10 * time.Second

// ErrMongoUnavailable is returned when Mongo is not configured (empty MONGODB_URI).
// It mirrors iptools.ErrUnavailable: callers treat it as "this feature is off",
// not as a fatal error, so the server still boots without a database.
var ErrMongoUnavailable = errors.New("mongodb is not configured (MONGODB_URI is empty)")

// Mongo is the shared MongoDB client. It is opened once at startup and shared
// across request goroutines — the driver's *mongo.Client is safe for concurrent
// use and pools connections internally, so (like the iptools BIN handles) it is
// never reopened per request. A nil *Mongo is a valid "disabled" value: every
// method below is nil-safe, exactly like a nil *iptools.Service.
//
// This type deliberately owns only the connection, no business logic. Per
// CLAUDE.md rule #5, a feature's persistence (repositories, queries, indexes)
// lives *below* its domain service, taking the *mongo.Database from DB(). No
// feature uses Mongo yet; this is the plumbing that lets one land later without
// reshaping the app.
type Mongo struct {
	Client *mongo.Client // the raw driver client (transactions, admin commands, …)
	db     *mongo.Database
}

// OpenMongo dials the server, verifies the connection with a ping, and selects
// the application database. An empty uri returns (nil, ErrMongoUnavailable) so a
// caller can start without Mongo — the same "missing data is non-fatal" contract
// iptools.OpenService uses for absent BINs. An empty dbName falls back to
// DefaultMongoDatabase. The caller owns the returned client and must Close it.
func OpenMongo(ctx context.Context, uri, dbName string) (*Mongo, error) {
	if uri == "" {
		return nil, ErrMongoUnavailable
	}
	if dbName == "" {
		dbName = DefaultMongoDatabase
	}

	opts := options.Client().
		ApplyURI(uri).
		SetServerSelectionTimeout(mongoServerSelectionTimeout)
	client, err := mongo.Connect(opts)
	if err != nil {
		return nil, fmt.Errorf("connect mongo: %w", err)
	}

	// Connect is lazy, so ping to fail fast if the server is unreachable or the
	// credentials are wrong; disconnect the half-open client so it never leaks on
	// the error path.
	pingCtx, cancel := context.WithTimeout(ctx, mongoServerSelectionTimeout)
	defer cancel()
	if err := client.Ping(pingCtx, readpref.Primary()); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("ping mongo: %w", err)
	}

	return &Mongo{Client: client, db: client.Database(dbName)}, nil
}

// DB returns the application *mongo.Database, or nil on a nil receiver. Feature
// repositories build their collections from this handle.
func (m *Mongo) DB() *mongo.Database {
	if m == nil {
		return nil
	}
	return m.db
}

// Ping verifies the connection is still usable. A nil receiver reports
// ErrMongoUnavailable rather than panicking.
func (m *Mongo) Ping(ctx context.Context) error {
	if m == nil {
		return ErrMongoUnavailable
	}
	return m.Client.Ping(ctx, readpref.Primary())
}

// Close disconnects the client and drains its connection pool. A nil receiver is
// a no-op, so `defer m.Close(ctx)` is safe even when Mongo is disabled.
func (m *Mongo) Close(ctx context.Context) error {
	if m == nil {
		return nil
	}
	return m.Client.Disconnect(ctx)
}

// EnsureDatabase makes the application database exist explicitly by creating a
// small sentinel collection. MongoDB creates a database lazily on its first
// write, so an untouched database never appears in `listDatabases`; calling this
// once (e.g. via `make mongo-init`) provisions "site-of-tools" up front. It is
// idempotent — an already-present collection (NamespaceExists) counts as success.
func (m *Mongo) EnsureDatabase(ctx context.Context) error {
	if m == nil {
		return ErrMongoUnavailable
	}
	const sentinel = "_meta" // an empty collection whose only job is to keep the db present
	if err := m.db.CreateCollection(ctx, sentinel); err != nil {
		var cmdErr mongo.CommandError
		if !errors.As(err, &cmdErr) || cmdErr.Code != 48 { // 48 = NamespaceExists
			return fmt.Errorf("create sentinel collection %q: %w", sentinel, err)
		}
	}
	return nil
}
