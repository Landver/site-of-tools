package tests

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/iptools"
)

const blocklistColl = "ip_blocklist" // matches the unexported name in blocklist.go

// TestNewBlockListDisabled: nil db (Mongo off) → nil repo, the nil-safe
// disabled store.
func TestNewBlockListDisabled(t *testing.T) {
	if b := iptools.NewBlockList(nil); b != nil {
		t.Fatalf("NewBlockList(nil db) = %v, want nil (disabled)", b)
	}
}

// TestNilBlockListIsSafe: every method no-ops / returns zero on a nil repo, so
// a Mongo-less boot needs no guards in callers.
func TestNilBlockListIsSafe(t *testing.T) {
	var b *iptools.BlockList
	ctx := context.Background()
	if err := b.EnsureIndexes(ctx); err != nil {
		t.Errorf("nil EnsureIndexes err = %v, want nil", err)
	}
	if err := b.Upsert(ctx, iptools.BlockEntry{IP: "1.2.3.4", Source: "manual"}); err != nil {
		t.Errorf("nil Upsert err = %v, want nil", err)
	}
	if n, err := b.UpsertMany(ctx, []iptools.BlockEntry{{IP: "1.2.3.4", Source: "manual"}}); err != nil || n != 0 {
		t.Errorf("nil UpsertMany = (%d, %v), want (0, nil)", n, err)
	}
	lk, err := b.Check(ctx, "1.2.3.4")
	if err != nil || lk.Listed() {
		t.Errorf("nil Check = (%+v, %v), want (empty, nil)", lk, err)
	}
	if ts, err := b.LastSync(ctx, "ipsum"); err != nil || !ts.IsZero() {
		t.Errorf("nil LastSync = (%v, %v), want (zero, nil)", ts, err)
	}
}

// liveBlockListDB opens the dedicated test DB, drops the collection, returns a
// fresh repo. Skips unless MONGODB_TEST_URI is set (keeps `make test`/CI
// hermetic), mirroring liveHistoryDB.
func liveBlockListDB(t *testing.T, ctx context.Context) (*iptools.BlockList, *platform.Mongo) {
	t.Helper()
	uri := os.Getenv("MONGODB_TEST_URI")
	if uri == "" {
		t.Skip("MONGODB_TEST_URI not set; skipping live blocklist integration test")
	}
	m, err := platform.OpenMongo(ctx, uri, "site-of-tools-test")
	if err != nil {
		t.Fatalf("open mongo: %v", err)
	}
	db := m.DB()
	if err := db.Collection(blocklistColl).Drop(ctx); err != nil {
		t.Fatalf("pre-clean: %v", err)
	}
	t.Cleanup(func() { _ = db.Collection(blocklistColl).Drop(ctx); _ = m.Close(ctx) })
	bl := iptools.NewBlockList(db)
	if err := bl.EnsureIndexes(ctx); err != nil {
		t.Fatalf("EnsureIndexes: %v", err)
	}
	return bl, m
}

// TestBlockListLiveRoundTrip: exercises the corpus against real Mongo — the
// upsert/created-at-immutability contract, multi-source independence, and
// LastSync — the behaviour the offline nil-safe tests can't reach.
func TestBlockListLiveRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	bl, m := liveBlockListDB(t, ctx)
	const ip = "203.0.113.9"

	// First insert from the ipsum feed.
	if err := bl.Upsert(ctx, iptools.BlockEntry{IP: ip, Source: iptools.BlocklistSourceIPsum, Count: 3, Reason: "seed"}); err != nil {
		t.Fatalf("Upsert #1: %v", err)
	}
	created, updated1 := readTimes(t, ctx, m, ip, iptools.BlocklistSourceIPsum)
	if created.IsZero() || updated1.IsZero() {
		t.Fatalf("timestamps not set on insert: created=%v updated=%v", created, updated1)
	}

	// Re-upsert the same (ip, source) with a higher count: created_at must stay
	// put, updated_at must advance, count must update.
	time.Sleep(5 * time.Millisecond) // clear a Mongo millisecond so updated_at strictly advances
	if err := bl.Upsert(ctx, iptools.BlockEntry{IP: ip, Source: iptools.BlocklistSourceIPsum, Count: 7, Reason: "refresh"}); err != nil {
		t.Fatalf("Upsert #2: %v", err)
	}
	created2, updated2 := readTimes(t, ctx, m, ip, iptools.BlocklistSourceIPsum)
	if !created2.Equal(created) {
		t.Errorf("created_at changed on refresh: %v → %v (must be immutable)", created, created2)
	}
	if !updated2.After(updated1) {
		t.Errorf("updated_at did not advance on refresh: %v → %v", updated1, updated2)
	}

	// A second, deliberate source for the same IP is an independent record —
	// the ipsum refresh above never clobbered it, and it never clobbers ipsum.
	if err := bl.Upsert(ctx, iptools.BlockEntry{IP: ip, Source: "rate-limiter", Reason: "too many requests"}); err != nil {
		t.Fatalf("Upsert manual: %v", err)
	}
	lk, err := bl.Check(ctx, ip)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(lk.Sources) != 2 {
		t.Errorf("Check sources = %v, want two independent records (ipsum + rate-limiter)", lk.Sources)
	}
	if lk.MaxCount != 7 {
		t.Errorf("Check MaxCount = %d, want 7 (highest across records)", lk.MaxCount)
	}

	// Sort is by source NAME, not insertion order: add a third source that
	// sorts before the earlier two, then assert the exact ordered slice — this
	// guards the deterministic sort in Check (would pass on insertion order alone
	// otherwise, since ipsum<rate-limiter already).
	if err := bl.Upsert(ctx, iptools.BlockEntry{IP: ip, Source: "aaa-scanner"}); err != nil {
		t.Fatalf("Upsert third source: %v", err)
	}
	lk, err = bl.Check(ctx, ip)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if diff := cmp.Diff([]string{"aaa-scanner", "ipsum", "rate-limiter"}, lk.Sources); diff != "" {
		t.Errorf("Sources not sorted by source name (-want +got):\n%s", diff)
	}

	// LastSync sees the ipsum refresh we just made.
	last, err := bl.LastSync(ctx, iptools.BlocklistSourceIPsum)
	if err != nil {
		t.Fatalf("LastSync: %v", err)
	}
	if !last.Equal(updated2) {
		t.Errorf("LastSync = %v, want the latest ipsum updated_at %v", last, updated2)
	}

	// UpsertMany writes a batch; Check finds a batch member.
	n, err := bl.UpsertMany(ctx, []iptools.BlockEntry{
		{IP: "198.51.100.7", Source: iptools.BlocklistSourceIPsum, Count: 4},
		{IP: "198.51.100.8", Source: iptools.BlocklistSourceIPsum, Count: 2},
		{IP: "", Source: iptools.BlocklistSourceIPsum}, // skipped (no IP)
		{IP: "198.51.100.9", Source: ""},               // skipped (no source)
	})
	if err != nil {
		t.Fatalf("UpsertMany: %v", err)
	}
	if n != 2 {
		t.Errorf("UpsertMany wrote %d, want 2 (two valid rows, two skipped)", n)
	}
	if lk, _ := bl.Check(ctx, "198.51.100.7"); !lk.Listed() || lk.MaxCount != 4 {
		t.Errorf("batch member 198.51.100.7 = %+v, want listed with count 4", lk)
	}

	// Nil and all-skipped batches return (0, nil) without a write.
	for _, empty := range [][]iptools.BlockEntry{
		nil,
		{{IP: "", Source: "ipsum"}, {IP: "9.9.9.9", Source: ""}},
	} {
		if got, err := bl.UpsertMany(ctx, empty); err != nil || got != 0 {
			t.Errorf("UpsertMany(%v) = (%d, %v), want (0, nil)", empty, got, err)
		}
	}
}

// readTimes fetches created_at / updated_at for one (ip, source) record
// straight from the collection — the repo's Check intentionally doesn't expose
// timestamps, so the immutability assertions read the raw doc.
func readTimes(t *testing.T, ctx context.Context, m *platform.Mongo, ip, source string) (created, updated time.Time) {
	t.Helper()
	var e iptools.BlockEntry
	err := m.DB().Collection(blocklistColl).
		FindOne(ctx, bson.D{{Key: "ip", Value: ip}, {Key: "source", Value: source}}).
		Decode(&e)
	if err != nil {
		t.Fatalf("read raw doc for %s/%s: %v", ip, source, err)
	}
	return e.CreatedAt, e.UpdatedAt
}

// TestSyncIPsumNilRepo: nil repo (Mongo off) → zero result, no error, no
// download attempted. Offline, needs no DB.
func TestSyncIPsumNilRepo(t *testing.T) {
	res, err := iptools.SyncIPsum(context.Background(), nil)
	if err != nil {
		t.Errorf("SyncIPsum(nil) err = %v, want nil", err)
	}
	if res.Parsed != 0 || res.Written != 0 || res.Skipped || !res.LastSync.IsZero() {
		t.Errorf("SyncIPsum(nil) = %+v, want zero result", res)
	}
}

// TestSyncIPsumSkipsWhenFresh: a fresh ipsum record makes the staleness guard
// return BEFORE any network fetch — exercises the interval-slack guard (the
// prior-pass cadence fix) without hitting GitHub. Gated on MONGODB_TEST_URI.
func TestSyncIPsumSkipsWhenFresh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	bl, _ := liveBlockListDB(t, ctx)
	if err := bl.Upsert(ctx, iptools.BlockEntry{IP: "203.0.113.60", Source: iptools.BlocklistSourceIPsum, Count: 3}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	res, err := iptools.SyncIPsum(ctx, bl)
	if err != nil {
		t.Fatalf("SyncIPsum: %v", err)
	}
	if !res.Skipped || res.Written != 0 || res.Parsed != 0 {
		t.Errorf("SyncIPsum on a fresh corpus = %+v, want Skipped with no download", res)
	}
}
