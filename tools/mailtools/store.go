package mailtools

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/Landver/site-of-tools/platform"
)

const (
	dnsblCacheColl = "email_dnsbl_cache"
	// Short enough to see a delisting soon, long enough to keep repeat checks off the lists' query limits.
	dnsblTTL = 20 * time.Minute
)

// Store caches DNSBL reports in MongoDB.
type Store struct {
	dnsbl *mongo.Collection
}

// NewStore returns nil for a nil db, which the Service reads as no cache.
func NewStore(ctx context.Context, db *mongo.Database) *Store {
	if db == nil {
		return nil
	}
	coll := db.Collection(dnsblCacheColl)
	_ = platform.EnsureTTLIndex(ctx, coll, "created_at", dnsblTTL)
	return &Store{dnsbl: coll}
}

type dnsblEntry struct {
	Target    string       `bson:"_id"`
	Report    *DNSBLReport `bson:"report"`
	CreatedAt time.Time    `bson:"created_at"`
}

// cachedDNSBL returns target's cached report, or runs query and caches what it returns.
func (st *Store) cachedDNSBL(ctx context.Context, target string, query func() *DNSBLReport) *DNSBLReport {
	if st == nil {
		return query()
	}
	var hit dnsblEntry
	if st.dnsbl.FindOne(ctx, bson.M{"_id": target}).Decode(&hit) == nil {
		return hit.Report
	}
	rep := query()
	entry := dnsblEntry{Target: target, Report: rep, CreatedAt: time.Now().UTC()}
	_, _ = st.dnsbl.ReplaceOne(ctx, bson.M{"_id": target}, entry, options.Replace().SetUpsert(true))
	return rep
}
