package botcheck

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/Landver/site-of-tools/platform"
)

// corpusTTL bounds how long a fingerprint sighting is kept: long enough to
// catch a scraping farm rotating proxies within a month, short enough that the
// tool never becomes a permanent registry of who visited. Self-prunes via a
// TTL index.
const corpusTTL = 30 * 24 * time.Hour

// corpusCollection is the collection in the site-of-tools database.
const corpusCollection = "botcheck_fingerprints"

// corpusEntry is one recorded sighting: this exact fingerprint hash was
// presented from this IP at this time. Deliberately minimal — the hash is
// one-way (sha256 over stable client fields; the raw fingerprint is never
// stored), the IP feeds the distinct count, and ts drives the TTL.
type corpusEntry struct {
	Hash string    `bson:"hash"`
	IP   string    `bson:"ip"`
	TS   time.Time `bson:"ts"`
}

// Corpus is the persistence layer for the fingerprint-reuse signal (G41/G42) —
// a repository below the domain, per CLAUDE.md rule #5, mirroring
// tools/iptools/history.go. A nil *Corpus is a valid "disabled" value (Mongo
// off): Record no-ops and DistinctIPs returns zero, so the handler needs no
// guards, exactly like a nil *iptools.History.
type Corpus struct {
	coll *mongo.Collection
}

// NewCorpus builds the repository from the application database handle. A nil
// db (Mongo disabled) returns nil — the nil-safe disabled store.
func NewCorpus(db *mongo.Database) *Corpus {
	if db == nil {
		return nil
	}
	return &Corpus{coll: db.Collection(corpusCollection)}
}

// EnsureIndexes creates the TTL index that prunes the corpus. Best-effort and
// idempotent (safe to run on every startup); a failure only forfeits
// auto-expiry, so callers treat it as non-fatal. Nil-safe.
func (c *Corpus) EnsureIndexes(ctx context.Context) error {
	if c == nil {
		return nil
	}
	return platform.EnsureTTLIndex(ctx, c.coll, "ts", corpusTTL)
}

// Record persists one fingerprint sighting. Nil-safe; an empty hash or IP is
// "not supplied" and records nothing. It runs on the request path (synchronous)
// because the handler counts right after recording — the pair must stay ordered
// or the current request could miss its own sighting. Volume is low (one POST
// per page view), so a single insert is fine; the error is for tests and
// callers that care, the handler treats a lost record as acceptable.
func (c *Corpus) Record(ctx context.Context, hash, ip string) error {
	if c == nil || hash == "" || ip == "" {
		return nil
	}
	_, err := c.coll.InsertOne(ctx, corpusEntry{Hash: hash, IP: ip, TS: time.Now()})
	return err
}

// DistinctIPs counts how many different IPs presented this exact fingerprint
// within the retention window — the fingerprint_reuse rule's input. Nil-safe: a
// disabled store returns (0, nil), which the rule treats as "no corpus data",
// never as evidence.
func (c *Corpus) DistinctIPs(ctx context.Context, hash string) (int, error) {
	if c == nil {
		return 0, nil
	}
	var ips []string
	if err := c.coll.Distinct(ctx, "ip", bson.D{{Key: "hash", Value: hash}}).Decode(&ips); err != nil {
		return 0, err
	}
	return len(ips), nil
}

// DistinctHashesByIP counts how many DIFFERENT fingerprint hashes this IP
// presented within the given rolling window — the ip_fingerprint_churn rule's
// input, and the temporal inverse of DistinctIPs (reuse is one fingerprint from
// many IPs; churn is many fingerprints from one IP). A normal address shows one
// or a few (a household's devices); a single address cycling many distinct
// fingerprints in minutes is a randomising automation client or a busy shared
// egress. Nil-safe and empty-ip-safe: both return (0, nil), which the rule
// treats as "no corpus data", never as evidence. The window is passed in (not a
// package constant) so the domain layer owns the churn semantics and this stays
// a plain query.
func (c *Corpus) DistinctHashesByIP(ctx context.Context, ip string, window time.Duration) (int, error) {
	if c == nil || ip == "" {
		return 0, nil
	}
	filter := bson.D{
		{Key: "ip", Value: ip},
		{Key: "ts", Value: bson.D{{Key: "$gte", Value: time.Now().Add(-window)}}},
	}
	var hashes []string
	if err := c.coll.Distinct(ctx, "hash", filter).Decode(&hashes); err != nil {
		return 0, err
	}
	return len(hashes), nil
}
