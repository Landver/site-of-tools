package platform

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

// DefaultMongoDatabase: app db on shared MongoDB server (localhost).
// Config.MongoDatabase defaults to this; override w/ MONGODB_DATABASE. Not the
// db in connection string's path (that segment names auth db — "/admin" —
// separate from app db selected here).
const DefaultMongoDatabase = "site-of-tools"

// mongoServerSelectionTimeout bounds how long OpenMongo waits for a reachable
// server → down/unreachable host fails fast at startup instead of blocking on
// driver's 30s default. Doesn't cap ordinary query latency (still governed by
// caller's context).
const mongoServerSelectionTimeout = 10 * time.Second

// ErrMongoUnavailable: returned when Mongo not configured (empty MONGODB_URI).
// Mirrors iptools.ErrUnavailable: callers treat it as "feature's off", not
// fatal → server still boots w/o a database.
var ErrMongoUnavailable = errors.New("mongodb is not configured (MONGODB_URI is empty)")

// Mongo: shared MongoDB client. Opened once at startup, shared across request
// goroutines — driver's *mongo.Client safe for concurrent use, pools
// connections internally → (like iptools BIN handles) never reopened per
// request. nil *Mongo = valid "disabled" value: every method below nil-safe,
// same as nil *iptools.Service.
//
// Owns only the connection, no business logic. Per CLAUDE.md rule #5, a
// feature's persistence (repositories, queries, indexes) lives *below* its
// domain service, taking *mongo.Database from DB() — see iptools.History
// (lookup history) and RequestLog (request corpus), first two consumers.
type Mongo struct {
	Client *mongo.Client // raw driver client (transactions, admin commands, …)
	db     *mongo.Database
}

// OpenMongo dials server, verifies connection w/ ping, selects app db. Empty
// uri returns (nil, ErrMongoUnavailable) → caller can start w/o Mongo — same
// "missing data is non-fatal" contract iptools.OpenService uses for absent
// BINs. Empty dbName falls back to DefaultMongoDatabase. Caller owns returned
// client, must Close it.
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

	// Connect is lazy → ping to fail fast if server unreachable or creds wrong;
	// disconnect half-open client so it never leaks on error path.
	pingCtx, cancel := context.WithTimeout(ctx, mongoServerSelectionTimeout)
	defer cancel()
	if err := client.Ping(pingCtx, readpref.Primary()); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("ping mongo: %w", err)
	}

	return &Mongo{Client: client, db: client.Database(dbName)}, nil
}

// DB returns the app *mongo.Database, or nil on a nil receiver. Feature
// repositories build their collections from this handle.
func (m *Mongo) DB() *mongo.Database {
	if m == nil {
		return nil
	}
	return m.db
}

// Ping verifies the connection is still usable. nil receiver reports
// ErrMongoUnavailable rather than panicking.
func (m *Mongo) Ping(ctx context.Context) error {
	if m == nil {
		return ErrMongoUnavailable
	}
	return m.Client.Ping(ctx, readpref.Primary())
}

// Close disconnects the client and drains its connection pool. nil receiver =
// no-op, so `defer m.Close(ctx)` is safe even when Mongo is disabled.
func (m *Mongo) Close(ctx context.Context) error {
	if m == nil {
		return nil
	}
	return m.Client.Disconnect(ctx)
}

// EnsureDatabase makes the app database exist explicitly by creating a small
// sentinel collection. MongoDB creates a database lazily on its first write →
// an untouched database never appears in `listDatabases`; calling this once
// (e.g. via `make mongo-init`) provisions "site-of-tools" up front. Idempotent
// — an already-present collection (NamespaceExists) counts as success.
func (m *Mongo) EnsureDatabase(ctx context.Context) error {
	if m == nil {
		return ErrMongoUnavailable
	}
	const sentinel = "_meta" // empty collection, only job: keep the db present
	if err := m.db.CreateCollection(ctx, sentinel); err != nil {
		var cmdErr mongo.CommandError
		if !errors.As(err, &cmdErr) || cmdErr.Code != 48 { // 48 = NamespaceExists
			return fmt.Errorf("create sentinel collection %q: %w", sentinel, err)
		}
	}
	return nil
}

// EnsureTTLIndex idempotently creates an ascending index on field that also
// expires each document ttl after its field value. One bit of setup every
// time-ordered collection here needs — a rolling corpus that self-prunes — so
// features (request log, iptools history) share this helper instead of
// repeating the options dance. The same ascending index also serves a
// *descending* sort on field (Mongo scans it in reverse) → a "most recent N"
// query needs no second index. Re-creating an identical index is a no-op, so
// callers can run this on every startup.
func EnsureTTLIndex(ctx context.Context, coll *mongo.Collection, field string, ttl time.Duration) error {
	_, err := coll.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: field, Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(int32(ttl.Seconds())),
	})
	return err
}
