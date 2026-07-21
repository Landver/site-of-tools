package iptools

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/Landver/site-of-tools/platform"
)

// historyTTL: how long a recorded lookup stays. Long enough for useful
// "recent lookups" list, short enough tool never becomes permanent
// who-looked-up-what registry. Self-prunes via TTL index.
const historyTTL = 90 * 24 * time.Hour

// historyCollection: collection name in site-of-tools database.
const historyCollection = "ip_lookups"

// HistoryEntry is one recorded lookup: queried IP, salient facts, when it
// happened. Deliberately a projection of Result, not whole struct → enough
// to show + replay (click IP to re-run), no more.
type HistoryEntry struct {
	IP          string    `bson:"ip" json:"ip"`
	CountryCode string    `bson:"country_code,omitempty" json:"country_code,omitempty"`
	Country     string    `bson:"country,omitempty" json:"country,omitempty"`
	City        string    `bson:"city,omitempty" json:"city,omitempty"`
	ASN         string    `bson:"asn,omitempty" json:"asn,omitempty"`
	ASName      string    `bson:"as_name,omitempty" json:"as_name,omitempty"`
	CreatedAt   time.Time `bson:"created_at" json:"created_at"`
}

// History is the persistence layer for IP-lookup history: a repository below
// domain, per CLAUDE.md rule #5. Nil *History = valid "disabled" value (Mongo
// off) → Record no-ops, Recent returns nothing → handler needs no guards,
// same as nil *Service or nil *platform.RequestLog.
type History struct {
	coll *mongo.Collection
}

// NewHistory builds repository from application database handle. Nil db
// (Mongo disabled) → returns nil, the nil-safe disabled store. TTL index is
// best-effort: failure only forfeits auto-expiry → non-fatal.
func NewHistory(ctx context.Context, db *mongo.Database) *History {
	if db == nil {
		return nil
	}
	coll := db.Collection(historyCollection)
	_ = platform.EnsureTTLIndex(ctx, coll, "created_at", historyTTL)
	return &History{coll: coll}
}

// Record persists one successful lookup. Nil-safe. Writes off request path
// (background goroutine, own bounded context) → recording never adds
// latency to, or fails, the lookup visitor's waiting on: lost record OK,
// slowed lookup not. Volume low (user-initiated lookups only) → plain
// goroutine enough; higher-volume request log uses bounded queue instead.
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

// Recent returns most recent n lookups, newest first. Nil-safe: disabled
// store returns empty result + no error → handler renders empty history, no
// special-casing Mongo off. created_at TTL index also serves this
// descending sort (Mongo scans it in reverse) → no second index.
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
