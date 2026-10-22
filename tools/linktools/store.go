package linktools

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/Landver/site-of-tools/platform"
)

const linksCollection = "links"

// hitWriteTimeout can be generous: the write is off the request path.
const hitWriteTimeout = 5 * time.Second

var (
	// ErrLinkNotFound answers never-existed, expired and revoked alike: telling them apart is an oracle.
	ErrLinkNotFound = errors.New("no such link")

	// ErrCodeTaken lets the domain tell a collision from a storage failure without the Mongo driver.
	ErrCodeTaken = errors.New("that code is already in use")
)

// Link is one alias. json:"-" means nothing to a template, so the console must omit CreatedIP itself.
type Link struct {
	Code      string     `bson:"code"        json:"code"`
	Target    string     `bson:"target"      json:"target"`
	Original  string     `bson:"original,omitempty" json:"original,omitempty"` // pre-clean
	Note      string     `bson:"note,omitempty"     json:"note,omitempty"`     // capped at 256 B
	CreatedAt time.Time  `bson:"created_at"  json:"created_at"`
	CreatedIP string     `bson:"created_ip,omitempty" json:"-"` // forensics only
	ExpiresAt *time.Time `bson:"expires_at,omitempty" json:"expires_at,omitempty"`
	RevokedAt *time.Time `bson:"revoked_at,omitempty" json:"revoked_at,omitempty"`
	// Cleaned is per-request only: Original already records what the URL was.
	Cleaned   []string   `bson:"-"           json:"cleaned,omitempty"`
	Hits      int64      `bson:"hits"        json:"hits"`
	LastHitAt *time.Time `bson:"last_hit_at,omitempty" json:"last_hit_at,omitempty"`
}

// linkRetention is long on purpose: while an expired row exists, its code can't be re-registered.
const linkRetention = 10 * 365 * 24 * time.Hour

// LinkStore is nil-safe: a nil one (Mongo off) reports ErrDisabled or nothing.
type LinkStore struct {
	coll *mongo.Collection
	// indexErr: why the unique index on {code:1} is missing, if it is.
	indexErr error
	// cache and hits bound the one unauthenticated, unlimited route in the suite.
	cache *resolveCache
	hits  *hitBatcher
}

// NewLinkStore returns nil for a nil db. A failed unique index on code is not swallowed: Insert
// fails closed while reads keep resolving, and IndexError reports it at startup.
func NewLinkStore(ctx context.Context, db *mongo.Database) *LinkStore {
	if db == nil {
		return nil
	}
	coll := db.Collection(linksCollection)
	s := &LinkStore{coll: coll}
	if _, err := coll.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "code", Value: 1}},
		Options: options.Index().SetUnique(true),
	}); err != nil {
		s.indexErr = err
	}
	// GC only (Resolve enforces expiry), and never expire-at-date: deleting soon after expiry frees the
	// code, and a re-registered slug would take over every copy of the old link.
	_ = platform.EnsureTTLIndex(ctx, coll, "expires_at", linkRetention)
	s.cache = newResolveCache()
	s.hits = newHitBatcher(coll)
	return s
}

// IndexError lets wiring log a unique-index failure at startup, not on the first create. Nil-safe.
func (s *LinkStore) IndexError() error {
	if s == nil {
		return nil
	}
	return s.indexErr
}

// Insert refuses without the unique index: an unarbitrated collision would cross two people's links.
func (s *LinkStore) Insert(ctx context.Context, l *Link) error {
	if s == nil {
		return ErrDisabled
	}
	if l == nil || l.Code == "" {
		return errors.New("link has no code")
	}
	if s.indexErr != nil {
		return fmt.Errorf("unique index on %s.code is missing: %w", linksCollection, s.indexErr)
	}
	if _, err := s.coll.InsertOne(ctx, l); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("%w: %s", ErrCodeTaken, l.Code)
		}
		return err
	}
	// A probe may have cached a negative moments ago; without this a new alias 404s for a minute.
	s.cache.invalidate(l.Code)
	return nil
}

// ByCode is case-sensitive: base58 codes differ by case, so folding would merge two namespaces.
func (s *LinkStore) ByCode(ctx context.Context, code string) (*Link, error) {
	if s == nil {
		return nil, ErrDisabled
	}
	// Negatives too, or hammering a missing code costs a FindOne per request.
	if l, ok := s.cache.get(code); ok {
		if l == nil {
			return nil, ErrLinkNotFound
		}
		copied := *l
		return &copied, nil
	}
	// Taken before the query: a create or revoke landing mid-flight makes the answer stale.
	gen := s.cache.generation()

	var l Link
	err := s.coll.FindOne(ctx, bson.D{{Key: "code", Value: code}}).Decode(&l)
	if errors.Is(err, mongo.ErrNoDocuments) {
		s.cache.putIfFresh(code, nil, gen)
		return nil, ErrLinkNotFound
	}
	if err != nil {
		// A transport failure is not evidence of absence, so it is never cached.
		return nil, err
	}
	s.cache.putIfFresh(code, &l, gen)
	copied := l
	return &copied, nil
}

// Recent sorts without an index: the corpus is small and key-gated, so a scan beats a second index.
func (s *LinkStore) Recent(ctx context.Context, n int64) ([]Link, error) {
	if s == nil {
		return nil, nil
	}
	cur, err := s.coll.Find(ctx, bson.D{}, options.Find().
		SetSort(bson.D{{Key: "created_at", Value: -1}}).
		SetLimit(n))
	if err != nil {
		return nil, err
	}
	var out []Link
	if err := cur.All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Revoke soft-deletes: a freed slug re-registered elsewhere would hijack every copy of the old link.
func (s *LinkStore) Revoke(ctx context.Context, code string, at time.Time) error {
	if s == nil {
		return ErrDisabled
	}
	res, err := s.coll.UpdateOne(ctx,
		bson.D{{Key: "code", Value: code}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "revoked_at", Value: at}}}})
	if err != nil {
		return err
	}
	if res.MatchedCount == 0 {
		return ErrLinkNotFound
	}
	// Revocation must never wait out a cache TTL.
	s.cache.invalidate(code)
	return nil
}

// RecordHit counts off the request path: a lost hit count is acceptable, a slowed redirect is not.
func (s *LinkStore) RecordHit(code string) {
	if s == nil || code == "" {
		return
	}
	// Queued, never a goroutine per hit, which would make a burst a pool-exhaustion primitive.
	s.hits.record(code)
}

// Close drains the pending hit counts on shutdown.
func (s *LinkStore) Close() {
	if s == nil {
		return
	}
	s.hits.Close()
}
