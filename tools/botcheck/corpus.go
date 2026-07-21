package botcheck

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/Landver/site-of-tools/platform"
)

// corpusTTL bounds how long a fingerprint sighting stays: long enough →
// catch scraping farm rotating proxies within a month, short enough → tool
// never becomes permanent registry of who visited. Self-prunes via TTL index.
const corpusTTL = 30 * 24 * time.Hour

// corpusCollection: collection in site-of-tools database.
const corpusCollection = "botcheck_fingerprints"

// corpusEntry: one recorded sighting — this exact fingerprint hash presented
// from this IP at this time. Deliberately minimal: hash one-way (sha256 over
// stable client fields; raw fingerprint never stored), IP feeds distinct
// count, ts drives TTL.
type corpusEntry struct {
	Hash string    `bson:"hash"`
	IP   string    `bson:"ip"`
	TS   time.Time `bson:"ts"`
}

// Corpus: persistence layer for fingerprint-reuse signal (G41/G42) —
// repository below domain, per CLAUDE.md rule #5, mirrors
// tools/iptools/history.go. Nil *Corpus = valid "disabled" value (Mongo off):
// Record no-ops, DistinctIPs returns zero → handler needs no guards, same as
// nil *iptools.History.
type Corpus struct {
	coll *mongo.Collection
}

// NewCorpus builds repository from app database handle. Nil db (Mongo
// disabled) → returns nil, the nil-safe disabled store.
func NewCorpus(db *mongo.Database) *Corpus {
	if db == nil {
		return nil
	}
	return &Corpus{coll: db.Collection(corpusCollection)}
}

// EnsureIndexes creates TTL index that prunes corpus. Best-effort + idempotent
// (safe every startup); failure only forfeits auto-expiry → callers treat as
// non-fatal. Nil-safe.
func (c *Corpus) EnsureIndexes(ctx context.Context) error {
	if c == nil {
		return nil
	}
	return platform.EnsureTTLIndex(ctx, c.coll, "ts", corpusTTL)
}

// Record persists one fingerprint sighting. Nil-safe; empty hash or IP =
// "not supplied" → records nothing. Runs on request path (synchronous):
// handler counts right after recording — pair must stay ordered or current
// request could miss its own sighting. Volume low (one POST per page view)
// → single insert fine; error is for tests + callers who care, handler
// treats a lost record as acceptable.
func (c *Corpus) Record(ctx context.Context, hash, ip string) error {
	if c == nil || hash == "" || ip == "" {
		return nil
	}
	_, err := c.coll.InsertOne(ctx, corpusEntry{Hash: hash, IP: ip, TS: time.Now()})
	return err
}

// DistinctIPs counts how many different IPs presented this exact fingerprint
// within retention window — fingerprint_reuse rule's input. Nil-safe:
// disabled store returns (0, nil), rule treats as "no corpus data", never
// evidence.
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
// presented within given rolling window — ip_fingerprint_churn rule's input,
// temporal inverse of DistinctIPs (reuse = one fingerprint from many IPs;
// churn = many fingerprints from one IP). Normal address shows one or few
// (household's devices); single address cycling many distinct fingerprints in
// minutes = randomising automation client or busy shared egress. Nil-safe +
// empty-ip-safe: both return (0, nil), rule treats as "no corpus data", never
// evidence. Window passed in (not package constant) → domain layer owns churn
// semantics, this stays plain query.
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
