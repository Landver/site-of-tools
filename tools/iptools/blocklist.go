package iptools

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/Landver/site-of-tools/platform"
)

// Deliberately not tool-scoped: a shared corpus any service writes flagged IPs into and any consumer reads.
const blocklistCollection = "ip_blocklist"

// Still-listed IPs are re-touched daily and never expire; ones every feed dropped decay after two months.
const blocklistTTL = 60 * 24 * time.Hour

// The slack matters: a sync's write lands just after its tick, so guarding on the bare interval
// would skip every other tick (a 48h cadence).
const (
	blocklistSyncInterval = 24 * time.Hour
	blocklistSyncSlack    = 1 * time.Hour
)

// Exported so botcheck can tell automatic feeds apart from a deliberate ban another service wrote.
const (
	BlocklistSourceIPsum        = "ipsum"
	BlocklistSourceSpamhausDROP = "spamhaus-drop"
)

// BlockEntry's bson names are a public schema for external writers; they set created_at via $setOnInsert.
type BlockEntry struct {
	// A netblock entry stores its CIDR here; Check matches netblocks by RangeStart/RangeEnd instead.
	IP     string `bson:"ip" json:"ip"`
	Source string `bson:"source" json:"source"` // "ipsum", "spamhaus-drop", "rate-limiter", "manual", …
	Reason string `bson:"reason,omitempty" json:"reason,omitempty"`
	// 0 when the source has no numeric strength (Spamhaus DROP is presence-only).
	Count int `bson:"count,omitempty" json:"count,omitempty"`
	// Inclusive IPv4 bounds, one doc per CIDR instead of one per address; IPv6 netblocks are unsupported.
	RangeStart uint32 `bson:"range_start,omitempty" json:"range_start,omitempty"`
	RangeEnd   uint32 `bson:"range_end,omitempty" json:"range_end,omitempty"`
	// Spamhaus's licence requires its date and copyright text to stay with the data; they live here.
	Meta      map[string]any `bson:"meta,omitempty" json:"meta,omitempty"`
	CreatedAt time.Time      `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time      `bson:"updated_at" json:"updated_at"` // refreshed every touch; drives TTL
}

// BlockLookup folds every record for one IP into the facts a consumer scores on.
type BlockLookup struct {
	Sources  []string `json:"sources,omitempty"`
	MaxCount int      `json:"max_count,omitempty"`
}

func (l BlockLookup) Listed() bool { return len(l.Sources) > 0 }

func (l BlockLookup) SourcesLabel() string { return strings.Join(l.Sources, ", ") }

// BlockList is nil-safe: a nil *BlockList (Mongo off) no-ops, so callers need no guards.
type BlockList struct {
	coll *mongo.Collection
}

// NewBlockList returns nil, the disabled store, when db is nil.
func NewBlockList(db *mongo.Database) *BlockList {
	if db == nil {
		return nil
	}
	return &BlockList{coll: db.Collection(blocklistCollection)}
}

type Checker interface {
	Check(ctx context.Context, ip string) (BlockLookup, error)
}

// CheckerFrom returns nil for nil b: a nil *BlockList answers "not listed", read as checked-clean.
func CheckerFrom(b *BlockList) Checker {
	if b == nil {
		return nil
	}
	return b
}

// EnsureIndexes: unique (ip, source) keeps each source's own record, so a feed sync never clobbers a
// manual ban; the range index is sparse because only netblock entries carry ranges.
func (b *BlockList) EnsureIndexes(ctx context.Context) error {
	if b == nil {
		return nil
	}
	if err := platform.EnsureTTLIndex(ctx, b.coll, "updated_at", blocklistTTL); err != nil {
		return err
	}
	if _, err := b.coll.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "ip", Value: 1}, {Key: "source", Value: 1}},
		Options: options.Index().SetUnique(true).SetName("ip_source_unique"),
	}); err != nil {
		return err
	}
	_, err := b.coll.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "range_start", Value: 1}, {Key: "range_end", Value: 1}},
		Options: options.Index().SetSparse(true).SetName("range_sparse"),
	})
	return err
}

// Upsert is how other Go services flag an IP; an empty ip or source records nothing.
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

// UpsertMany returns docs inserted or modified; callers still chunk to bound memory per write.
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

// Check also matches IPv4 netblocks containing ip; corpus off and not listed both return a zero lookup.
func (b *BlockList) Check(ctx context.Context, ip string) (BlockLookup, error) {
	if b == nil || ip == "" {
		return BlockLookup{}, nil
	}
	filter := bson.D{{Key: "ip", Value: ip}}
	if addr, err := netip.ParseAddr(ip); err == nil && addr.Is4() {
		n := ipv4Uint32(addr)
		filter = bson.D{{Key: "$or", Value: bson.A{
			bson.D{{Key: "ip", Value: ip}},
			bson.D{
				{Key: "range_start", Value: bson.D{{Key: "$lte", Value: n}}},
				{Key: "range_end", Value: bson.D{{Key: "$gte", Value: n}}},
			},
		}}}
	}
	// Sorted so Sources is deterministic, not Mongo natural order.
	cur, err := b.coll.Find(ctx, filter, options.Find().SetSort(bson.D{{Key: "source", Value: 1}}))
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

// LastSync returns the newest updated_at from source, or zero time if none.
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

// ShouldSync never skips on a read error, so a transient failure can't stall syncing.
func (b *BlockList) ShouldSync(ctx context.Context, source string) (skip bool, last time.Time, err error) {
	if b == nil {
		return false, time.Time{}, nil
	}
	last, err = b.LastSync(ctx, source)
	if err != nil || last.IsZero() {
		return false, last, err
	}
	return time.Since(last) < blocklistSyncInterval-blocklistSyncSlack, last, nil
}

type BlockSyncResult struct {
	Parsed   int
	Written  int       // docs inserted or modified
	Skipped  bool      // corpus fresh, no download
	LastSync time.Time // set when Skipped
}

// A partial write reads as fresh to ShouldSync, so a restart skips until the next tick; accepted,
// since the 60-day TTL means nothing expires meanwhile.
func (b *BlockList) syncFeed(
	ctx context.Context, source string, chunkSize int,
	fetch func(context.Context) (io.ReadCloser, error),
	parse func(io.Reader) ([]BlockEntry, error),
) (BlockSyncResult, error) {
	if b == nil {
		return BlockSyncResult{}, nil
	}
	if skip, last, err := b.ShouldSync(ctx, source); err == nil && skip {
		return BlockSyncResult{Skipped: true, LastSync: last}, nil
	}

	body, err := fetch(ctx)
	if err != nil {
		return BlockSyncResult{}, err
	}
	defer body.Close()

	entries, err := parse(body)
	if err != nil {
		return BlockSyncResult{}, err
	}

	res := BlockSyncResult{Parsed: len(entries)}
	for start := 0; start < len(entries); start += chunkSize {
		end := min(start+chunkSize, len(entries))
		n, err := b.UpsertMany(ctx, entries[start:end])
		res.Written += n
		if err != nil {
			return res, err
		}
	}
	return res, nil
}

// fetchFeed fails on non-200 so an outage never parses as an empty feed.
func fetchFeed(ctx context.Context, client *http.Client, url, what string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return nil, fmt.Errorf("fetch %s: unexpected status %s", what, resp.Status)
	}
	return resp.Body, nil
}

// runDailySync syncs now, then daily until ctx ends; failures log and retry on the next tick.
func runDailySync(ctx context.Context, bl *BlockList, label, unit string, sync func(context.Context, *BlockList) (BlockSyncResult, error)) {
	if bl == nil {
		log.Printf("%s blocklist: disabled (no Mongo); skipping periodic sync", label)
		return
	}

	syncOnce := func() {
		c, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		switch res, err := sync(c, bl); {
		case err != nil:
			log.Printf("%s blocklist: sync failed: %v", label, err)
		case res.Skipped:
			log.Printf("%s blocklist: corpus fresh (last synced %s), skipped download", label, res.LastSync.Format(time.RFC3339))
		default:
			log.Printf("%s blocklist: synced %d %s (%d written)", label, res.Parsed, unit, res.Written)
		}
	}

	syncOnce()
	ticker := time.NewTicker(blocklistSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			syncOnce()
		}
	}
}

// Empty count/range/meta stay out of $set so a source lacking them stamps no nulls.
func blocklistUpdate(e BlockEntry, now time.Time) bson.D {
	set := bson.D{
		{Key: "reason", Value: e.Reason},
		{Key: "updated_at", Value: now},
	}
	if e.Count > 0 {
		set = append(set, bson.E{Key: "count", Value: e.Count})
	}
	if e.RangeStart != 0 || e.RangeEnd != 0 {
		set = append(set, bson.E{Key: "range_start", Value: e.RangeStart}, bson.E{Key: "range_end", Value: e.RangeEnd})
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
