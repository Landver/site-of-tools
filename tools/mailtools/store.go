package mailtools

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/Landver/site-of-tools/platform"
)

const (
	dnsblCacheColl = "email_dnsbl_cache"
	domainMetaColl = "email_domain_meta"
	// DNSBL reputation is cached for 20 minutes to prevent hitting query limits.
	dnsblTTL = 20 * time.Minute
)

// DNSBLCacheEntry stores the aggregated blacklist audit for an IP or hostname.
type DNSBLCacheEntry struct {
	Target       string        `bson:"target" json:"target"`
	Results      []DNSBLResult `bson:"results" json:"results"`
	ListedCount  int           `bson:"listed_count" json:"listed_count"`
	WarningCount int           `bson:"warning_count" json:"warning_count"`
	TotalChecked int           `bson:"total_checked" json:"total_checked"`
	CreatedAt    time.Time     `bson:"created_at" json:"created_at"`
}

// SyncMeta tracks upstream dataset versions and synchronization timestamps.
type SyncMeta struct {
	Key       string    `bson:"key" json:"key"`
	Hash      string    `bson:"hash" json:"hash"`
	Count     int       `bson:"count" json:"count"`
	UpdatedAt time.Time `bson:"updated_at" json:"updated_at"`
}

// Store handles MongoDB persistence for mailtools (DNSBL cache and sync metadata).
type Store struct {
	dnsblColl *mongo.Collection
	metaColl  *mongo.Collection
}

// NewStore initializes collections and ensures TTL indexes on MongoDB.
func NewStore(ctx context.Context, db *mongo.Database) *Store {
	if db == nil {
		return nil
	}
	dnsbl := db.Collection(dnsblCacheColl)
	_ = platform.EnsureTTLIndex(ctx, dnsbl, "created_at", dnsblTTL)
	_, _ = dnsbl.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.M{"target": 1}})
	meta := db.Collection(domainMetaColl)
	return &Store{
		dnsblColl: dnsbl,
		metaColl:  meta,
	}
}

// GetDNSBLCache retrieves cached DNSBL results for a target, if present and fresh.
func (s *Store) GetDNSBLCache(ctx context.Context, target string) (*DNSBLCacheEntry, error) {
	if s == nil || s.dnsblColl == nil {
		return nil, nil
	}
	var entry DNSBLCacheEntry
	err := s.dnsblColl.FindOne(ctx, bson.M{"target": target}).Decode(&entry)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		return nil, err
	}
	return &entry, nil
}

// SaveDNSBLCache stores DNSBL query results in MongoDB with auto-expiring TTL.
func (s *Store) SaveDNSBLCache(ctx context.Context, target string, results []DNSBLResult, listed, warnings, total int) {
	if s == nil || s.dnsblColl == nil {
		return
	}
	filter := bson.M{"target": target}
	update := bson.M{"$set": bson.M{
		"target":        target,
		"results":       results,
		"listed_count":  listed,
		"warning_count": warnings,
		"total_checked": total,
		"created_at":    time.Now().UTC(),
	}}
	opts := options.UpdateOne().SetUpsert(true)
	_, _ = s.dnsblColl.UpdateOne(ctx, filter, update, opts)
}

// GetSyncMeta retrieves metadata for an upstream dataset key (e.g. "disposable", "freemail").
func (s *Store) GetSyncMeta(ctx context.Context, key string) (*SyncMeta, error) {
	if s == nil || s.metaColl == nil {
		return nil, nil
	}
	var meta SyncMeta
	err := s.metaColl.FindOne(ctx, bson.M{"key": key}).Decode(&meta)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		return nil, err
	}
	return &meta, nil
}

// SetSyncMeta updates or creates sync metadata for an upstream dataset.
func (s *Store) SetSyncMeta(ctx context.Context, meta SyncMeta) error {
	if s == nil || s.metaColl == nil {
		return nil
	}
	update := bson.M{"$set": bson.M{
		"hash":       meta.Hash,
		"count":      meta.Count,
		"updated_at": meta.UpdatedAt,
	}}
	opts := options.UpdateOne().SetUpsert(true)
	_, err := s.metaColl.UpdateOne(ctx, bson.M{"key": meta.Key}, update, opts)
	return err
}
