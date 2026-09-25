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

// linksCollection: collection name in the site-of-tools database.
const linksCollection = "links"

// hitWriteTimeout bounds the fire-and-forget $inc. Generous, because the write
// is already off the request path and a slow one costs the visitor nothing.
const hitWriteTimeout = 5 * time.Second

var (
	// ErrLinkNotFound: no usable link under that code. Deliberately the single
	// answer for "never existed", "expired" and "revoked" alike — distinguishing
	// them is an existence oracle over the guessable custom-slug namespace
	// (docs/04-short-links.md §7).
	ErrLinkNotFound = errors.New("no such link")

	// ErrCodeTaken: the unique index refused the insert. Translated here so the
	// domain layer above never has to import the Mongo driver to tell a
	// collision from a real storage failure — CLAUDE.md rule #5 cuts both ways.
	ErrCodeTaken = errors.New("that code is already in use")
)

// Link is one alias. Shape fixed by docs/04-short-links.md §4.
//
// Original holds the pre-clean URL when clean ran and changed something, so a
// rule bug stays recoverable and auditable. CreatedIP is forensics only and is
// `json:"-"` so it cannot leak through the API — note that a struct tag means
// nothing to a template, so the console's view model must omit it explicitly
// (§8).
type Link struct {
	Code      string     `bson:"code"        json:"code"`
	Target    string     `bson:"target"      json:"target"`
	Original  string     `bson:"original,omitempty" json:"original,omitempty"` // pre-clean
	Note      string     `bson:"note,omitempty"     json:"note,omitempty"`     // capped at 256 B
	CreatedAt time.Time  `bson:"created_at"  json:"created_at"`
	CreatedIP string     `bson:"created_ip,omitempty" json:"-"` // forensics only
	ExpiresAt *time.Time `bson:"expires_at,omitempty" json:"expires_at,omitempty"`
	RevokedAt *time.Time `bson:"revoked_at,omitempty" json:"revoked_at,omitempty"`
	// Cleaned names the parameters stripped at create time. Not persisted —
	// Original already records what the URL was, and this is the per-request
	// explanation the API contract (§9) promises alongside it.
	Cleaned   []string   `bson:"-"           json:"cleaned,omitempty"`
	Hits      int64      `bson:"hits"        json:"hits"`
	LastHitAt *time.Time `bson:"last_hit_at,omitempty" json:"last_hit_at,omitempty"`
}

// linkRetention is how long an EXPIRED link's document is kept before Mongo
// sweeps it. Long, on purpose: while the row exists the unique index still
// blocks re-registration of its code, so the slug cannot be silently reused.
const linkRetention = 10 * 365 * 24 * time.Hour

// LinkStore is the persistence layer for short links: repository below the
// domain, per CLAUDE.md rule #5. Nil *LinkStore is a valid "disabled" value
// (Mongo off) → every method is nil-safe and reports ErrDisabled or nothing,
// same contract as iptools.History and platform.RequestLog.
type LinkStore struct {
	coll *mongo.Collection
	// indexErr: why the unique index on {code:1} is not in place, if it isn't.
	// See NewLinkStore.
	indexErr error
	// cache + hits bound the one unauthenticated, unlimited route in the suite.
	// See resolvecache.go for why both are necessary.
	cache *resolveCache
	hits  *hitBatcher
}

// NewLinkStore builds the repository from the app database handle. Nil db
// (Mongo disabled) → nil store, which NewShortener turns into "creation off".
//
// Two indexes, treated very differently on purpose (docs/04-short-links.md §4):
//
//   - {code: 1} unique is load-bearing. It is what makes §3's insert-and-retry
//     collision strategy correct, and without it two callers can be handed the
//     same code. Its failure is NOT swallowed the way iptools/history.go:51
//     swallows its TTL failure: it is recorded and returned from Insert, so the
//     feature fails closed on writes rather than silently losing the guarantee.
//     Reads keep working, so existing links still resolve. (The constructor
//     returns one value because the wiring in main.go treats an absent store as
//     "feature off"; the error surfaces at the method that actually depends on
//     it, and IndexError reports it for startup logging.)
//   - expires_at is garbage collection only, so it stays best-effort. ttl=0
//     yields expireAfterSeconds: 0 — the expire-at-a-date idiom, under which a
//     document whose field is absent or not a BSON date never expires.
//     Enforcement lives in Shortener.Resolve, never here: Mongo's TTL monitor
//     sweeps roughly every 60s and lags under load.
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
	// expires_at is GARBAGE COLLECTION, not enforcement. Shortener.Resolve
	// compares ExpiresAt against time.Now() itself, so expiry is already exact;
	// this index only sweeps up long-dead rows.
	//
	// Deliberately NOT expireAfterSeconds:0 (expire-at-the-stored-date). That
	// would delete the document ~60s after expiry, which frees the unique code
	// and lets a later create re-register the same custom slug pointing somewhere
	// else — alias takeover, and every copy of the old link in someone's notes
	// silently changes destination. Reclaiming a slug is an explicit operator
	// action, never a background thread (docs/04-short-links.md §4).
	_ = platform.EnsureTTLIndex(ctx, coll, "expires_at", linkRetention)
	s.cache = newResolveCache()
	s.hits = newHitBatcher(coll)
	return s
}

// IndexError reports the unique-index failure, if any, so wiring code can log
// it once at startup instead of discovering it on the first create. Nil-safe.
func (s *LinkStore) IndexError() error {
	if s == nil {
		return nil
	}
	return s.indexErr
}

// Insert writes one new link. A duplicate code comes back as ErrCodeTaken so
// the caller can retry (generated code) or report 409 (custom slug); never
// check-then-insert, which is a race (docs/04-short-links.md §3).
//
// Refuses outright when the unique index is missing: an insert that cannot be
// arbitrated is worse than no insert, because the collision would surface later
// as one person's alias resolving to another person's target.
// Insert writes one new link, invalidating any cached negative for its code so
// a freshly created alias resolves at once rather than after the negative TTL.
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
	// A probe for this code may have cached a negative moments ago. Drop it, or
	// a brand-new alias 404s for up to a minute.
	s.cache.invalidate(l.Code)
	return nil
}

// ByCode fetches one link by its exact code. Case-sensitive: base58 codes
// differ by case, and slugs are lowercase-only by validation, so folding here
// would merge two distinct namespaces. Missing document → ErrLinkNotFound.
//
// The filter value is a plain string parameter, never a decoded map, so an
// operator document can never reach it — the guard §3 asks for is upstream in
// validateCode, this is the second half of it.
func (s *LinkStore) ByCode(ctx context.Context, code string) (*Link, error) {
	if s == nil {
		return nil, ErrDisabled
	}
	// Cache first, negatives included. Without the negative half, hammering a
	// code that does not exist still costs a FindOne per request against the
	// shared database (docs/04-short-links.md §7).
	if l, ok := s.cache.get(code); ok {
		if l == nil {
			return nil, ErrLinkNotFound
		}
		copied := *l
		return &copied, nil
	}
	// Captured BEFORE the round trip: if a create or revoke lands while this
	// query is in flight, the answer below is already stale and must not be
	// cached over it.
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

// Recent returns the n newest links, newest first, for the key-gated console
// (docs/04-short-links.md §8). Nil-safe: a disabled store lists nothing and
// reports no error.
//
// No index backs this sort. The corpus is operator-created and small by
// construction (the write path is key-gated), so a collection scan on an
// admin-only page is the cheaper trade than a second index on every insert.
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

// Revoke soft-deletes a link: the document stays, RevokedAt is set, Resolve
// filters on it. Never a hard delete, because deleting frees the slug and a
// freed slug re-registered to a new target is alias takeover — every copy of
// the old link in somebody's notes silently changes destination
// (docs/04-short-links.md §4). Reclaiming a code is an explicit operator
// action, never a background thread.
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
	// Revocation must never wait on a cache: a revoked link that keeps
	// redirecting for another minute is the whole reason revocation exists.
	s.cache.invalidate(code)
	return nil
}

// RecordHit increments the counter for one code, off the request path.
//
// context.Background() with its own timeout, never the request context: that
// one is cancelled the instant the redirect response completes, so the write
// would be aborted rather than merely slow (docs/04-short-links.md §4). The
// redirect issues before this write is acknowledged, by design — a lost hit
// count is acceptable, a slowed redirect is not. Same shape as
// iptools.History.Record.
func (s *LinkStore) RecordHit(code string) {
	if s == nil || code == "" {
		return
	}
	// Queued, not a goroutine per hit. The old shape held a 5s context and a
	// pooled connection per request, so a burst on a valid code was a goroutine
	// and connection-pool exhaustion primitive (docs/04-short-links.md §7).
	s.hits.record(code)
}

// Close drains the pending hit counts. Paired with main.go's shutdown, in the
// same shape as platform.RequestLog.Close.
func (s *LinkStore) Close() {
	if s == nil {
		return
	}
	s.hits.Close()
}
