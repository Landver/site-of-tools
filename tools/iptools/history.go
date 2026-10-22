package iptools

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/Landver/site-of-tools/platform"
)

// Long enough for a useful recent list, short enough never to become a who-looked-up-what registry.
const historyTTL = 90 * 24 * time.Hour

const historyCollection = "ip_lookups"

// HistoryEntry is a projection of Result: enough to show and replay a lookup, no more.
type HistoryEntry struct {
	IP          string    `bson:"ip" json:"ip"`
	CountryCode string    `bson:"country_code,omitempty" json:"country_code,omitempty"`
	Country     string    `bson:"country,omitempty" json:"country,omitempty"`
	City        string    `bson:"city,omitempty" json:"city,omitempty"`
	ASN         string    `bson:"asn,omitempty" json:"asn,omitempty"`
	ASName      string    `bson:"as_name,omitempty" json:"as_name,omitempty"`
	CreatedAt   time.Time `bson:"created_at" json:"created_at"`
}

// History is nil-safe: a nil *History (Mongo off) no-ops, so the handler needs no guards.
type History struct {
	coll *mongo.Collection
}

// NewHistory returns nil when db is nil; a failed TTL index only forfeits auto-expiry.
func NewHistory(ctx context.Context, db *mongo.Database) *History {
	if db == nil {
		return nil
	}
	coll := db.Collection(historyCollection)
	_ = platform.EnsureTTLIndex(ctx, coll, "created_at", historyTTL)
	return &History{coll: coll}
}

// Record writes off the request path: a lost record is fine, a slowed lookup is not.
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

// Recent: the created_at TTL index also serves this descending sort, so no second index.
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
