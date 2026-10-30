package tests

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/iptools"
)

const blocklistColl = "ip_blocklist" // matches unexported name in blocklist.go

func TestNewBlockListDisabled(t *testing.T) {
	if b := iptools.NewBlockList(nil); b != nil {
		t.Fatalf("NewBlockList(nil db) = %v, want nil (disabled)", b)
	}
}

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
	if err := b.FlagProbe(ctx, "8.8.8.8", "/.env"); err != nil {
		t.Errorf("nil FlagProbe err = %v, want nil", err)
	}
	if _, err := b.ProbeIPs(ctx); !errors.Is(err, platform.ErrMongoUnavailable) {
		t.Errorf("nil ProbeIPs err = %v, want ErrMongoUnavailable", err)
	}
}

// liveBlockListDB skips unless MONGODB_TEST_URI is set, keeping `make test` and CI hermetic.
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

func TestBlockListLiveRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	bl, m := liveBlockListDB(t, ctx)
	const ip = "203.0.113.9"

	if err := bl.Upsert(ctx, iptools.BlockEntry{IP: ip, Source: iptools.BlocklistSourceIPsum, Count: 3, Reason: "seed"}); err != nil {
		t.Fatalf("Upsert #1: %v", err)
	}
	created, updated1 := readTimes(t, ctx, m, ip, iptools.BlocklistSourceIPsum)
	if created.IsZero() || updated1.IsZero() {
		t.Fatalf("timestamps not set on insert: created=%v updated=%v", created, updated1)
	}

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

	// A second source is an independent record: neither clobbers the other.
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

	// "aaa-scanner" sorts first, so this fails if Check returns insertion order instead of sorting.
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

	last, err := bl.LastSync(ctx, iptools.BlocklistSourceIPsum)
	if err != nil {
		t.Fatalf("LastSync: %v", err)
	}
	if !last.Equal(updated2) {
		t.Errorf("LastSync = %v, want the latest ipsum updated_at %v", last, updated2)
	}

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

	for _, empty := range [][]iptools.BlockEntry{
		nil,
		{{IP: "", Source: "ipsum"}, {IP: "9.9.9.9", Source: ""}},
	} {
		if got, err := bl.UpsertMany(ctx, empty); err != nil || got != 0 {
			t.Errorf("UpsertMany(%v) = (%d, %v), want (0, nil)", empty, got, err)
		}
	}
}

// readTimes reads the raw doc: Check deliberately doesn't expose timestamps.
func readTimes(t *testing.T, ctx context.Context, m *platform.Mongo, ip, source string) (created, updated time.Time) {
	t.Helper()
	e := readEntry(t, ctx, m, ip, source)
	return e.CreatedAt, e.UpdatedAt
}

func TestSyncIPsumNilRepo(t *testing.T) {
	res, err := iptools.SyncIPsum(context.Background(), nil)
	if err != nil {
		t.Errorf("SyncIPsum(nil) err = %v, want nil", err)
	}
	if res.Parsed != 0 || res.Written != 0 || res.Skipped || !res.LastSync.IsZero() {
		t.Errorf("SyncIPsum(nil) = %+v, want zero result", res)
	}
}

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

func TestBlockListLiveRangeContainment(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	bl, _ := liveBlockListDB(t, ctx)

	// Literal bounds keep the fixture independent of production CIDR math.
	const (
		cidr                        = "203.0.113.0/24" // 203.0.113.0 .. 203.0.113.255
		rangeStart, rangeEnd uint32 = 0xCB007100, 0xCB0071FF
	)
	entry := iptools.BlockEntry{
		IP: cidr, Source: iptools.BlocklistSourceSpamhausDROP,
		RangeStart: rangeStart, RangeEnd: rangeEnd, Reason: "test netblock",
	}
	if err := bl.Upsert(ctx, entry); err != nil {
		t.Fatalf("seed range entry: %v", err)
	}

	for _, ip := range []string{"203.0.113.1", "203.0.113.0", "203.0.113.255", "203.0.113.200"} {
		if lk, err := bl.Check(ctx, ip); err != nil || !lk.Listed() || lk.Sources[0] != iptools.BlocklistSourceSpamhausDROP {
			t.Errorf("Check(%s) = %+v, err=%v — want listed by spamhaus-drop", ip, lk, err)
		}
	}
	for _, ip := range []string{"203.0.112.255", "203.0.114.0"} {
		if lk, err := bl.Check(ctx, ip); err != nil || lk.Listed() {
			t.Errorf("Check(%s) = %+v, err=%v — want NOT listed (outside the range)", ip, lk, err)
		}
	}

	if err := bl.Upsert(ctx, iptools.BlockEntry{IP: "203.0.113.50", Source: iptools.BlocklistSourceIPsum, Count: 5}); err != nil {
		t.Fatalf("seed single-ip entry: %v", err)
	}
	lk, err := bl.Check(ctx, "203.0.113.50")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if diff := cmp.Diff([]string{iptools.BlocklistSourceIPsum, iptools.BlocklistSourceSpamhausDROP}, lk.Sources); diff != "" {
		t.Errorf("Sources for an IP matched by both a single-IP entry and a containing range (-want +got):\n%s", diff)
	}
}

func TestSyncSpamhausDROPNilRepo(t *testing.T) {
	res, err := iptools.SyncSpamhausDROP(context.Background(), nil)
	if err != nil {
		t.Errorf("SyncSpamhausDROP(nil) err = %v, want nil", err)
	}
	if res.Parsed != 0 || res.Written != 0 || res.Skipped || !res.LastSync.IsZero() {
		t.Errorf("SyncSpamhausDROP(nil) = %+v, want zero result", res)
	}
}

func TestSyncSpamhausDROPSkipsWhenFresh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	bl, _ := liveBlockListDB(t, ctx)
	if err := bl.Upsert(ctx, iptools.BlockEntry{
		IP: "198.51.100.0/24", Source: iptools.BlocklistSourceSpamhausDROP, RangeStart: 1, RangeEnd: 2,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	res, err := iptools.SyncSpamhausDROP(ctx, bl)
	if err != nil {
		t.Fatalf("SyncSpamhausDROP: %v", err)
	}
	if !res.Skipped || res.Written != 0 || res.Parsed != 0 {
		t.Errorf("SyncSpamhausDROP on a fresh corpus = %+v, want Skipped with no download", res)
	}
}

// TestFlagProbeLive: a probe lists the IP until 30 days after its latest hit, beside its feed record.
func TestFlagProbeLive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	bl, m := liveBlockListDB(t, ctx)
	const ip = "8.8.4.4" // FlagProbe skips unroutable addresses, documentation ranges included

	if err := bl.Upsert(ctx, iptools.BlockEntry{IP: ip, Source: iptools.BlocklistSourceIPsum, Count: 2}); err != nil {
		t.Fatalf("seed ipsum: %v", err)
	}
	if err := bl.FlagProbe(ctx, ip, "/.env?x=1"); err != nil {
		t.Fatalf("FlagProbe #1: %v", err)
	}
	first := readEntry(t, ctx, m, ip, iptools.BlocklistSourceProbe)
	if left := time.Until(first.ExpiresAt); left < 29*24*time.Hour || left > 30*24*time.Hour {
		t.Errorf("expires_at in %v, want ~30 days", left)
	}
	if first.Reason != "probed /.env" {
		t.Errorf("reason = %q, want the path without its query", first.Reason)
	}

	time.Sleep(5 * time.Millisecond)
	if err := bl.FlagProbe(ctx, ip, "/.git/config"); err != nil {
		t.Fatalf("FlagProbe #2: %v", err)
	}
	second := readEntry(t, ctx, m, ip, iptools.BlocklistSourceProbe)
	if !second.ExpiresAt.After(first.ExpiresAt) || !second.CreatedAt.Equal(first.CreatedAt) {
		t.Errorf("second probe: expires %v → %v, created %v → %v; want a later expiry, same created_at",
			first.ExpiresAt, second.ExpiresAt, first.CreatedAt, second.CreatedAt)
	}
	if feed := readEntry(t, ctx, m, ip, iptools.BlocklistSourceIPsum); !feed.ExpiresAt.IsZero() {
		t.Errorf("ipsum doc got expires_at %v; feeds must keep their updated_at TTL", feed.ExpiresAt)
	}

	for _, form := range []string{ip, "::ffff:" + ip} { // any spelling of the address finds the listing
		if lk, err := bl.Check(ctx, form); err != nil || !lk.Probed() || len(lk.Sources) != 2 {
			t.Errorf("Check(%s) = (%+v, %v), want both sources and Probed", form, lk, err)
		}
	}
	for _, skip := range []string{"10.0.0.1", "203.0.113.9", "not-an-ip"} {
		if err := bl.FlagProbe(ctx, skip, "/.env"); err != nil {
			t.Errorf("FlagProbe(%s) err = %v, want a silent skip", skip, err)
		}
	}
	if err := bl.FlagProbe(ctx, "::ffff:1.1.1.1", "/.env"); err != nil {
		t.Fatalf("FlagProbe mapped: %v", err)
	}
	ips, err := bl.ProbeIPs(ctx)
	if err != nil {
		t.Fatalf("ProbeIPs: %v", err)
	}
	if diff := cmp.Diff([]string{"1.1.1.1", ip}, ips, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
		t.Errorf("ProbeIPs (-want +got):\n%s", diff)
	}

	// Mongo, not the code, enforces the 30 days: the doc's own date via an expireAfterSeconds 0 index.
	specs, err := m.DB().Collection(blocklistColl).Indexes().ListSpecifications(ctx)
	if err != nil {
		t.Fatalf("list indexes: %v", err)
	}
	if !slices.ContainsFunc(specs, func(s mongo.IndexSpecification) bool {
		return s.Name == "expires_at_1" && s.ExpireAfterSeconds != nil && *s.ExpireAfterSeconds == 0
	}) {
		t.Errorf("no expires_at TTL index with expireAfterSeconds 0 among %d indexes", len(specs))
	}
}

func readEntry(t *testing.T, ctx context.Context, m *platform.Mongo, ip, source string) iptools.BlockEntry {
	t.Helper()
	var e iptools.BlockEntry
	if err := m.DB().Collection(blocklistColl).FindOne(ctx, bson.D{{Key: "ip", Value: ip}, {Key: "source", Value: source}}).Decode(&e); err != nil {
		t.Fatalf("read %s/%s: %v", ip, source, err)
	}
	return e
}
