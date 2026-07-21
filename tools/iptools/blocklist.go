package iptools

import (
	"context"
	"errors"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/Landver/site-of-tools/platform"
)

// blocklistCollection: shared IP blocklist in site-of-tools db. Name NOT
// tool-scoped on purpose — common corpus any service/script/workflow (n8n,
// rate limiter, manual ban list, ipsum sync below) writes flagged IPs into,
// any consumer reads. botcheck (ip_blocklisted rule) + the IP tool
// (proxy/blocklist/network card) read it, G37; neither owns it.
const blocklistCollection = "ip_blocklist"

// blocklistTTL: entry not refreshed within window self-prunes (TTL index on
// updated_at). Two months per owner spec — long enough a still-listed IP the
// daily ipsum sync keeps touching never expires, short enough reputation
// decays once IP falls off every feed / a one-off ban goes stale. Not a
// permanent record.
const blocklistTTL = 60 * 24 * time.Hour

// BlocklistSourceIPsum: `source` value the ipsum sync (ipsum.go) stamps.
// Exported — part of the corpus contract: a reader (botcheck) tells the
// automatic aggregate feed apart from a deliberate ban another service wrote.
const BlocklistSourceIPsum = "ipsum"

// BlockEntry: one row — an IP flagged by some source for some reason, immutable
// created_at + rolling updated_at. Field names = corpus public schema:
// external writers match them (snake_case bson) + use $setOnInsert for
// created_at so it stays set-once, like Upsert below.
type BlockEntry struct {
	IP     string `bson:"ip" json:"ip"`
	Source string `bson:"source" json:"source"` // what flagged it: "ipsum", "rate-limiter", "manual", …
	Reason string `bson:"reason,omitempty" json:"reason,omitempty"`
	// Count: optional confidence/occurrence count (ipsum: how many of its 30+
	// lists flag this IP). 0 = source carries no numeric strength.
	Count int `bson:"count,omitempty" json:"count,omitempty"`
	// Meta: source-specific extras, so no data lost when a richer feed is
	// ingested (ipsum stashes its feed timestamp + URL here).
	Meta      map[string]any `bson:"meta,omitempty" json:"meta,omitempty"`
	CreatedAt time.Time      `bson:"created_at" json:"created_at"` // set once, first insert
	UpdatedAt time.Time      `bson:"updated_at" json:"updated_at"` // refreshed every touch; drives TTL
}

// BlockLookup: reader's view of all records for one IP, folded to the two facts
// a consumer scores on — which sources flagged it, highest count any carried.
type BlockLookup struct {
	Sources  []string `json:"sources,omitempty"`   // distinct sources with this IP listed
	MaxCount int      `json:"max_count,omitempty"` // highest Count across those records (0 if none carry one)
}

// Listed: IP in the corpus at all?
func (l BlockLookup) Listed() bool { return len(l.Sources) > 0 }

// SourcesLabel joins the sources for display ("ipsum, rate-limiter").
func (l BlockLookup) SourcesLabel() string { return strings.Join(l.Sources, ", ") }

// BlockList: repository for the shared IP blocklist corpus — persistence below
// domain (CLAUDE.md rule #5), same nil-safe shape as iptools.History /
// botcheck.Corpus / platform.RequestLog. Nil *BlockList = disabled store
// (Mongo off): every method no-ops / returns zero → callers need no guards.
type BlockList struct {
	coll *mongo.Collection
}

// NewBlockList builds the repo from the app db handle. Nil db (Mongo off) →
// nil, the nil-safe disabled store.
func NewBlockList(db *mongo.Database) *BlockList {
	if db == nil {
		return nil
	}
	return &BlockList{coll: db.Collection(blocklistCollection)}
}

// EnsureIndexes creates the two indexes, best-effort + idempotent (safe every
// startup). Nil-safe.
//
//   - TTL on updated_at: the self-prune owner asked for (entries older than
//     blocklistTTL dropped). First — the load-bearing one.
//   - unique (ip, source): each source keeps its OWN record per IP → the daily
//     ipsum refresh never clobbers a manual/other-service ban + vice versa
//     (the "don't lose data" guarantee). Its ip-prefix also serves Check's
//     by-IP query → no separate ip index.
func (b *BlockList) EnsureIndexes(ctx context.Context) error {
	if b == nil {
		return nil
	}
	if err := platform.EnsureTTLIndex(ctx, b.coll, "updated_at", blocklistTTL); err != nil {
		return err
	}
	_, err := b.coll.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "ip", Value: 1}, {Key: "source", Value: 1}},
		Options: options.Index().SetUnique(true).SetName("ip_source_unique"),
	})
	return err
}

// Upsert records (or refreshes) one flagged IP. Nil-safe; empty ip/source =
// "not supplied" → records nothing. created_at written only on first insert
// ($setOnInsert) → immutable across refreshes; updated_at + mutable fields
// (reason/count/meta) rewritten every call, which also keeps the entry alive
// vs the TTL. Entry point other Go services call to flag an IP.
func (b *BlockList) Upsert(ctx context.Context, e BlockEntry) error {
	if b == nil || e.IP == "" || e.Source == "" {
		return nil
	}
	_, err := b.coll.UpdateOne(ctx,
		bson.D{{Key: "ip", Value: e.IP}, {Key: "source", Value: e.Source}},
		blocklistUpdate(e, time.Now()),
		options.UpdateOne().SetUpsert(true),
	)
	return err
}

// UpsertMany applies Upsert semantics to a batch in one unordered BulkWrite —
// the ipsum sync's bulk path. Nil-safe; empty ip/source entries skipped.
// Returns docs inserted or modified. Driver splits an oversized batch itself,
// but callers still chunk (see SyncIPsum) to bound memory + keep one slow write
// from stalling all.
func (b *BlockList) UpsertMany(ctx context.Context, entries []BlockEntry) (int, error) {
	if b == nil || len(entries) == 0 {
		return 0, nil
	}
	now := time.Now()
	models := make([]mongo.WriteModel, 0, len(entries))
	for _, e := range entries {
		if e.IP == "" || e.Source == "" {
			continue
		}
		models = append(models, mongo.NewUpdateOneModel().
			SetFilter(bson.D{{Key: "ip", Value: e.IP}, {Key: "source", Value: e.Source}}).
			SetUpdate(blocklistUpdate(e, now)).
			SetUpsert(true))
	}
	if len(models) == 0 {
		return 0, nil
	}
	res, err := b.coll.BulkWrite(ctx, models, options.BulkWrite().SetOrdered(false))
	if res == nil {
		return 0, err
	}
	return int(res.UpsertedCount + res.ModifiedCount), err
}

// Check returns every source with this IP listed + the highest count among
// them. Nil-safe + empty-ip-safe: both return a zero BlockLookup + nil err →
// a reader treats "corpus off" + "IP not listed" identically, never evidence.
func (b *BlockList) Check(ctx context.Context, ip string) (BlockLookup, error) {
	if b == nil || ip == "" {
		return BlockLookup{}, nil
	}
	// Sort by source so BlockLookup.Sources (and the detail string built from
	// it) is deterministic across requests, not MongoDB natural order.
	cur, err := b.coll.Find(ctx, bson.D{{Key: "ip", Value: ip}},
		options.Find().SetSort(bson.D{{Key: "source", Value: 1}}))
	if err != nil {
		return BlockLookup{}, err
	}
	var entries []BlockEntry
	if err := cur.All(ctx, &entries); err != nil {
		return BlockLookup{}, err
	}
	var lk BlockLookup
	for _, e := range entries {
		lk.Sources = append(lk.Sources, e.Source)
		lk.MaxCount = max(lk.MaxCount, e.Count)
	}
	return lk, nil
}

// LastSync returns the newest updated_at among records from source, or zero
// time if none. The ipsum sync uses it to skip a re-download when the corpus
// was refreshed within the last day → frequent restarts don't re-fetch.
// Nil-safe.
func (b *BlockList) LastSync(ctx context.Context, source string) (time.Time, error) {
	if b == nil {
		return time.Time{}, nil
	}
	var e BlockEntry
	err := b.coll.FindOne(ctx,
		bson.D{{Key: "source", Value: source}},
		options.FindOne().SetSort(bson.D{{Key: "updated_at", Value: -1}}),
	).Decode(&e)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return e.UpdatedAt, nil
}

// blocklistUpdate builds the upsert doc shared by Upsert + UpsertMany:
// created_at only on insert (immutable), everything mutable set every time
// (refreshes the TTL clock). count/meta omitted from $set when empty → a
// source carrying neither stamps no nulls.
func blocklistUpdate(e BlockEntry, now time.Time) bson.D {
	set := bson.D{
		{Key: "reason", Value: e.Reason},
		{Key: "updated_at", Value: now},
	}
	if e.Count > 0 {
		set = append(set, bson.E{Key: "count", Value: e.Count})
	}
	if len(e.Meta) > 0 {
		set = append(set, bson.E{Key: "meta", Value: e.Meta})
	}
	return bson.D{
		{Key: "$setOnInsert", Value: bson.D{
			{Key: "ip", Value: e.IP},
			{Key: "source", Value: e.Source},
			{Key: "created_at", Value: now},
		}},
		{Key: "$set", Value: set},
	}
}
