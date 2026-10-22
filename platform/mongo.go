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

// DefaultMongoDatabase is the app DB; the URI's path names the auth DB ("/admin"), not this one.
const DefaultMongoDatabase = "site-of-tools"

// mongoServerSelectionTimeout fails startup fast on an unreachable server instead of the driver's 30s.
const mongoServerSelectionTimeout = 10 * time.Second

// ErrMongoUnavailable means MONGODB_URI is empty: callers treat it as "feature off", not fatal.
var ErrMongoUnavailable = errors.New("mongodb is not configured (MONGODB_URI is empty)")

// Mongo is the one shared client; a nil *Mongo is the valid "disabled" value and every method is nil-safe.
type Mongo struct {
	Client *mongo.Client // raw driver client (transactions, admin commands, …)
	db     *mongo.Database
}

// OpenMongo connects and pings; an empty uri returns ErrMongoUnavailable. The caller must Close it.
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

	// Connect is lazy, so ping to fail fast; disconnect so the half-open client doesn't leak.
	pingCtx, cancel := context.WithTimeout(ctx, mongoServerSelectionTimeout)
	defer cancel()
	if err := client.Ping(pingCtx, readpref.Primary()); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("ping mongo: %w", err)
	}

	return &Mongo{Client: client, db: client.Database(dbName)}, nil
}

// DB returns the app database, or nil on a nil receiver.
func (m *Mongo) DB() *mongo.Database {
	if m == nil {
		return nil
	}
	return m.db
}

// Ping reports ErrMongoUnavailable on a nil receiver.
func (m *Mongo) Ping(ctx context.Context) error {
	if m == nil {
		return ErrMongoUnavailable
	}
	return m.Client.Ping(ctx, readpref.Primary())
}

// Close is a no-op on a nil receiver, so `defer m.Close(ctx)` is safe when Mongo is disabled.
func (m *Mongo) Close(ctx context.Context) error {
	if m == nil {
		return nil
	}
	return m.Client.Disconnect(ctx)
}

// EnsureDatabase creates a sentinel collection, since Mongo lists a database only after its first write.
func (m *Mongo) EnsureDatabase(ctx context.Context) error {
	if m == nil {
		return ErrMongoUnavailable
	}
	const sentinel = "_meta"
	if err := m.db.CreateCollection(ctx, sentinel); err != nil {
		var cmdErr mongo.CommandError
		if !errors.As(err, &cmdErr) || cmdErr.Code != 48 { // 48 = NamespaceExists
			return fmt.Errorf("create sentinel collection %q: %w", sentinel, err)
		}
	}
	return nil
}

// EnsureTTLIndex creates an ascending index that expires documents ttl after field; it also serves a
// descending "most recent N" sort, and re-creating it is a no-op, so call it on every startup.
func EnsureTTLIndex(ctx context.Context, coll *mongo.Collection, field string, ttl time.Duration) error {
	_, err := coll.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: field, Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(int32(ttl.Seconds())),
	})
	return err
}
