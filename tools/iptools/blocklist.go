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

// blocklistCollection: shared IP blocklist in site-of-tools db. Name NOT
// tool-scoped on purpose — common corpus any service/script/workflow (n8n,
// rate limiter, manual ban list, the ipsum + Spamhaus DROP syncs below) writes
// flagged IPs/netblocks into, any consumer reads. botcheck (ip_blocklisted
// rule) + the IP tool (proxy/blocklist/network card) read it, G37; neither
// owns it.
const blocklistCollection = "ip_blocklist"

// blocklistTTL: entry not refreshed within window self-prunes (TTL index on
// updated_at). Two months per owner spec — long enough a still-listed IP the
// daily feed syncs keep touching never expires, short enough reputation
// decays once IP falls off every feed / a one-off ban goes stale. Not a
// permanent record.
const blocklistTTL = 60 * 24 * time.Hour

// blocklistSyncInterval / blocklistSyncSlack: the shared daily-feed cadence
// every corpus-feeding sync (ipsum.go, spamhaus.go) uses via ShouldSync below.
// Slack exists because a sync's completion write always lands slightly AFTER
// the tick that triggered it — guarding on the bare interval skips every
// other scheduled tick (real cadence ~48h, not 24h). One shared pair, not
// duplicated per feed, since both feeds want the identical daily cadence.
const (
	blocklistSyncInterval = 24 * time.Hour
	blocklistSyncSlack    = 1 * time.Hour
)

// BlocklistSourceIPsum: `source` value the ipsum sync (ipsum.go) stamps.
// BlocklistSourceSpamhausDROP: `source` value the Spamhaus DROP sync
// (spamhaus.go) stamps. Both exported — part of the corpus contract: a
// reader (botcheck) tells the automatic feeds apart from a deliberate ban
// another service wrote (see botcheck's IPBlocklistDeliberate).
const (
	BlocklistSourceIPsum        = "ipsum"
	BlocklistSourceSpamhausDROP = "spamhaus-drop"
)

// BlockEntry: one row — an IP (or IPv4 netblock) flagged by some source for
// some reason, immutable created_at + rolling updated_at. Field names = corpus
// public schema: external writers match them (snake_case bson) + use
// $setOnInsert for created_at so it stays set-once, like Upsert below.
type BlockEntry struct {
	// IP: the flagged address for a single-IP entry (ipsum, manual bans, …),
	// or the CIDR string itself for a netblock entry (Spamhaus DROP) — the
	// CIDR IS that record's identity, keeping the (ip, source) unique index
	// meaningful either way. Range-type entries also set RangeStart/RangeEnd;
	// Check matches them by containment, not by this string.
	IP     string `bson:"ip" json:"ip"`
	Source string `bson:"source" json:"source"` // what flagged it: "ipsum", "spamhaus-drop", "rate-limiter", "manual", …
	Reason string `bson:"reason,omitempty" json:"reason,omitempty"`
	// Count: optional confidence/occurrence count (ipsum: how many of its 30+
	// lists flag this IP). 0 = source carries no numeric strength — true for
	// Spamhaus DROP, which is binary presence on a high-confidence curated
	// list, not a count.
	Count int `bson:"count,omitempty" json:"count,omitempty"`
	// RangeStart/RangeEnd: inclusive IPv4 bounds (see IPv4RangeBounds) for a
	// netblock entry — one document covers a whole CIDR instead of one row per
	// address (Spamhaus DROP's ~1,669 blocks cover ~15M individual addresses;
	// expanding to per-IP rows isn't an option). Zero/omitted for a plain
	// single-IP entry. IPv6 netblocks unsupported — Check's range branch is
	// IPv4-only.
	RangeStart uint32 `bson:"range_start,omitempty" json:"range_start,omitempty"`
	RangeEnd   uint32 `bson:"range_end,omitempty" json:"range_end,omitempty"`
	// Meta: source-specific extras, so no data lost when a richer feed is
	// ingested (ipsum stashes its feed timestamp + URL; Spamhaus DROP stashes
	// its copyright notice + timestamp + terms URL + per-record sblid/rir —
	// their license requires "the date and copy text remain with the file and
	// data", which this satisfies literally).
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

// EnsureIndexes creates the three indexes, best-effort + idempotent (safe every
// startup). Nil-safe.
//
//   - TTL on updated_at: the self-prune owner asked for (entries older than
//     blocklistTTL dropped). First — the load-bearing one.
//   - unique (ip, source): each source keeps its OWN record per IP/CIDR → the
//     daily feed syncs never clobber a manual/other-service ban + vice versa
//     (the "don't lose data" guarantee). Its ip-prefix also serves Check's
//     exact-match branch → no separate ip index.
//   - sparse (range_start, range_end): serves Check's containment branch.
//     Sparse because only netblock entries (Spamhaus DROP) carry these fields
//     — the vast majority (ipsum's ~100k single-IP rows) would otherwise
//     bloat a non-sparse index for nothing.
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

// Upsert records (or refreshes) one flagged IP/netblock. Nil-safe; empty
// ip/source = "not supplied" → records nothing. created_at written only on
// first insert ($setOnInsert) → immutable across refreshes; updated_at +
// mutable fields (reason/count/range/meta) rewritten every call, which also
// keeps the entry alive vs the TTL. Entry point other Go services call to
// flag an IP.
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
// the feed syncs' bulk path. Nil-safe; empty ip/source entries skipped.
// Returns docs inserted or modified. Driver splits an oversized batch itself,
// but callers still chunk (see ipsum.go/spamhaus.go) to bound memory + keep
// one slow write from stalling all.
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
// them — matching either an exact single-IP entry, or (for a parseable IPv4
// address) a netblock entry whose [RangeStart, RangeEnd] contains it, so a
// Spamhaus-DROP-style whole-netblock ban catches every address inside it
// without one document per address. Nil-safe + empty-ip-safe: both return a
// zero BlockLookup + nil err → a reader treats "corpus off" + "IP not listed"
// identically, never evidence.
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
	// Sort by source so BlockLookup.Sources (and the detail string built from
	// it) is deterministic across requests, not MongoDB natural order.
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

// LastSync returns the newest updated_at among records from source, or zero
// time if none. ShouldSync builds on this; call it directly only for a raw
// read. Nil-safe.
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

// ShouldSync is the shared staleness guard every daily feed sync (ipsum,
// Spamhaus DROP, …) calls before downloading: skip only if the last record
// from source was touched within (blocklistSyncInterval - blocklistSyncSlack)
// — see that constant's doc for why the slack, not the bare interval, is the
// threshold. err != nil ⇒ skip=false (caller falls through and tries the
// download rather than getting stuck never syncing on a transient read
// error). Nil-safe: never skips on a nil repo (moot in practice — callers
// return before reaching here on a nil *BlockList — but keeps the method
// itself safe to call directly).
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

// BlockSyncResult reports one feed sync's outcome (ipsum, Spamhaus DROP, …),
// for logging/tests. Shared by every feed via syncFeed below — the two feeds
// this corpus has today, ipsum and Spamhaus DROP, need identical fields, so
// one type rather than a same-shape type per feed.
type BlockSyncResult struct {
	Parsed   int       // valid records parsed from the feed
	Written  int       // docs inserted or modified
	Skipped  bool      // corpus fresh (see ShouldSync) → no download
	LastSync time.Time // when the corpus was last refreshed (set when Skipped)
}

// syncFeed is the shared body every daily feed sync runs: skip per ShouldSync
// if the corpus is fresh, else fetch, parse, and upsert in chunks of
// chunkSize. fetch and parse are the only feed-specific parts (SyncIPsum/
// SyncSpamhausDROP are thin wrappers supplying their own). Nil-safe (nil b →
// zero result, no download — callers never need their own nil check).
//
// A PARTIAL prior write (some chunks succeeded, then an error) can read as
// complete by ShouldSync, so a restart inside the window then skips, leaving
// un-written entries absent till the next proceeding tick. Accepted: needs a
// rare mid-batch Mongo failure AND an in-window restart, self-heals next
// tick, and the 60-day TTL means nothing expires meanwhile — not worth a
// persisted completion marker.
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

// fetchFeed GETs url's body via client. Caller closes it. Non-200 = error
// (body drained + closed) → an outage never parses as an empty feed + wipes
// nothing; the caller's next scheduled tick retries. what names the feed in
// the wrapped error message.
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

// runDailySync runs sync once now (self-skips via ShouldSync if fresh), then
// on a daily ticker until ctx is cancelled — the shared body every daily feed
// sync (RunIPsumSync, RunSpamhausDROPSync) uses. Launch as a background
// goroutine from main. Nil bl (Mongo off) → returns at once, nothing spins.
// label names the feed in log lines; unit names what Written counts ("IPs",
// "netblocks"). Best-effort: a failed fetch/write logs + retries next tick.
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

// blocklistUpdate builds the upsert doc shared by Upsert + UpsertMany:
// created_at only on insert (immutable), everything mutable set every time
// (refreshes the TTL clock). count/range/meta omitted from $set when empty →
// a source carrying none of them stamps no nulls.
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
