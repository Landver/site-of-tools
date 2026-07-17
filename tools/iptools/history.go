package iptools

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/Landver/site-of-tools/platform"
)

// historyTTL bounds how long a recorded lookup is kept: long enough to be a
// useful "recent lookups" list, short enough that the tool never becomes a
// permanent registry of who-looked-up-what. Self-prunes via a TTL index.
const historyTTL = 90 * 24 * time.Hour

// historyCollection is the collection in the site-of-tools database.
const historyCollection = "ip_lookups"

// HistoryEntry is one recorded lookup — the queried IP, the salient facts, and
// when it happened. Deliberately a projection of Result, not the whole struct:
// enough to show and to replay (click the IP to re-run), no more.
type HistoryEntry struct {
	IP          string    `bson:"ip" json:"ip"`
	CountryCode string    `bson:"country_code,omitempty" json:"country_code,omitempty"`
	Country     string    `bson:"country,omitempty" json:"country,omitempty"`
	City        string    `bson:"city,omitempty" json:"city,omitempty"`
	ASN         string    `bson:"asn,omitempty" json:"asn,omitempty"`
	ASName      string    `bson:"as_name,omitempty" json:"as_name,omitempty"`
	CreatedAt   time.Time `bson:"created_at" json:"created_at"`
}

// History is the persistence layer for IP-lookup history — a repository below the
// domain, per CLAUDE.md rule #5. A nil *History is a valid "disabled" value (Mongo
// off): Record no-ops and Recent returns nothing, so the handler needs no guards,
// exactly like a nil *Service or a nil *platform.RequestLog.
type History struct {
	coll *mongo.Collection
}

// NewHistory builds the repository from the application database handle. A nil db
// (Mongo disabled) returns nil — the nil-safe disabled store. The TTL index is
// best-effort; a failure only forfeits auto-expiry, so it is non-fatal.
func NewHistory(ctx context.Context, db *mongo.Database) *History {
	if db == nil {
		return nil
	}
	coll := db.Collection(historyCollection)
	_ = platform.EnsureTTLIndex(ctx, coll, "created_at", historyTTL)
	return &History{coll: coll}
}

// Record persists one successful lookup. Nil-safe. It writes off the request path
// (a background goroutine with its own bounded context) so recording never adds
// latency to — or fails — the lookup the visitor is waiting on: a lost record is
// acceptable, a slowed lookup is not. Volume is low (user-initiated lookups
// only), so a plain goroutine is enough; the higher-volume request log uses a
// bounded queue instead.
func (h *History) Record(res *Result) {
	if h == nil || res == nil {
		return
	}
	e := HistoryEntry{
		IP: res.IP, CountryCode: res.CountryCode, Country: res.Country,
		City: res.City, ASN: res.ASN, ASName: res.ASName, CreatedAt: time.Now(),
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = h.coll.InsertOne(ctx, e)
	}()
}

// Recent returns the most recent n lookups, newest first. Nil-safe: a disabled
// store returns an empty result and no error, so the handler renders an empty
// history without special-casing Mongo being off. The created_at TTL index also
// serves this descending sort (Mongo scans it in reverse), so no second index.
func (h *History) Recent(ctx context.Context, n int64) ([]HistoryEntry, error) {
	if h == nil {
		return nil, nil
	}
	cur, err := h.coll.Find(ctx, bson.D{}, options.Find().
		SetSort(bson.D{{Key: "created_at", Value: -1}}).
		SetLimit(n))
	if err != nil {
		return nil, err
	}
	var out []HistoryEntry
	if err := cur.All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}
