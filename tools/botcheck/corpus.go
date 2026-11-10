package botcheck

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/Landver/site-of-tools/platform"
)

// 30 days: long enough to catch a farm rotating proxies, short enough to never become a visitor registry.
const corpusTTL = 30 * 24 * time.Hour

const corpusCollection = "botcheck_fingerprints"

// Only a one-way hash of the stable fields is stored, never the raw fingerprint.
type corpusEntry struct {
	Hash string    `bson:"hash"`
	IP   string    `bson:"ip"`
	TS   time.Time `bson:"ts"`
}

// Corpus stores fingerprint sightings; a nil *Corpus (Mongo off) is a valid store that no-ops.
type Corpus struct {
	coll *mongo.Collection
}

// NewCorpus returns nil when db is nil (Mongo disabled).
func NewCorpus(db *mongo.Database) *Corpus {
	if db == nil {
		return nil
	}
	return &Corpus{coll: db.Collection(corpusCollection)}
}

// EnsureIndexes creates the TTL index; a failure only loses auto-expiry, so callers treat it as non-fatal.
func (c *Corpus) EnsureIndexes(ctx context.Context) error {
	if c == nil {
		return nil
	}
	return platform.EnsureTTLIndex(ctx, c.coll, "ts", corpusTTL)
}

// Record is synchronous: the handler counts right after, and the count must include this sighting.
func (c *Corpus) Record(ctx context.Context, hash, ip string) error {
	if c == nil || hash == "" || ip == "" {
		return nil
	}
	_, err := c.coll.InsertOne(ctx, corpusEntry{Hash: hash, IP: ip, TS: time.Now()})
	return err
}

func (c *Corpus) distinctCount(ctx context.Context, field string, filter any) (int, error) {
	if c == nil {
		return 0, nil
	}
	var out []string
	if err := c.coll.Distinct(ctx, field, filter).Decode(&out); err != nil {
		return 0, err
	}
	return len(out), nil
}

// DistinctIPs feeds fingerprint_reuse; a disabled store returns 0, which the rule treats as no data.
func (c *Corpus) DistinctIPs(ctx context.Context, hash string) (int, error) {
	return c.distinctCount(ctx, "ip", bson.D{{Key: "hash", Value: hash}})
}

// DistinctHashesByIP feeds ip_fingerprint_churn (many fingerprints from one IP); the caller owns window.
func (c *Corpus) DistinctHashesByIP(ctx context.Context, ip string, window time.Duration) (int, error) {
	if ip == "" {
		return 0, nil
	}
	filter := bson.D{
		{Key: "ip", Value: ip},
		{Key: "ts", Value: bson.D{{Key: "$gte", Value: time.Now().Add(-window)}}},
	}
	return c.distinctCount(ctx, "hash", filter)
}
