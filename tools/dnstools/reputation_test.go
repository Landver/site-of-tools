package dnstools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Landver/site-of-tools/tools/iptools"
)

// repFakeCorpus stands in for the blocklist store and counts reads, so the caps can be asserted.
type repFakeCorpus struct {
	listed map[string]iptools.BlockLookup
	err    error

	// Zero freshness fields mean every feed synced just now.
	neverSynced bool                 // no feed has ever written: an empty corpus
	syncedAt    map[string]time.Time // per feed, for the partly-stale case
	syncErr     error                // the freshness read itself fails

	mu    sync.Mutex
	calls int
}

func (f *repFakeCorpus) Check(_ context.Context, ip string) (iptools.BlockLookup, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.err != nil {
		return iptools.BlockLookup{}, f.err
	}
	return f.listed[ip], nil
}

func (f *repFakeCorpus) LastSync(_ context.Context, source string) (time.Time, error) {
	switch {
	case f.syncErr != nil:
		return time.Time{}, f.syncErr
	case f.neverSynced:
		return time.Time{}, nil
	}
	if t, ok := f.syncedAt[source]; ok {
		return t, nil
	}
	return time.Now(), nil
}

func (f *repFakeCorpus) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestMXReputationNamesAListedMailServer(t *testing.T) {
	t.Parallel()

	_, addr := serveZone(t, testZone{
		zoneKey("listed.test", "MX"):    {"listed.test. 300 IN MX 10 mx1.listed.test."},
		zoneKey("mx1.listed.test", "A"): {"mx1.listed.test. 300 IN A 192.0.2.10"},
	})
	corpus := &repFakeCorpus{listed: map[string]iptools.BlockLookup{
		"192.0.2.10": {Sources: []string{"ipsum", "spamhaus-drop"}, MaxCount: 7},
	}}

	m := newTestService().repRun(context.Background(), "listed.test", addr, corpus)

	if m.Listed != 1 || m.Checked != 1 {
		t.Fatalf("listed=%d checked=%d, want 1 and 1 (rows: %+v)", m.Listed, m.Checked, m.Hosts)
	}
	if got := m.Hosts[0].Addrs[0].Sources; got != "ipsum, spamhaus-drop" {
		t.Errorf("sources = %q, want both feeds joined for display", got)
	}
	if got := m.Hosts[0].Addrs[0].Count; got != 7 {
		t.Errorf("confidence count = %d, want the corpus value 7", got)
	}
	for _, want := range []string{"mx1.listed.test", "192.0.2.10", "ipsum"} {
		if !hasNote(m.Notes, "fail", want) {
			t.Errorf("no failing note mentions %q; notes: %+v", want, m.Notes)
		}
	}
	if hasNote(m.Notes, "ok", "") {
		t.Errorf("a listed server produced an ok note too: %+v", m.Notes)
	}
}

// An empty card cannot tell "nothing found" from "nothing looked", so clean is said out loud.
func TestMXReputationCleanIsStatedNotImplied(t *testing.T) {
	t.Parallel()

	_, addr := serveZone(t, testZone{
		zoneKey("clean.test", "MX"): {
			"clean.test. 300 IN MX 10 mx1.clean.test.",
			"clean.test. 300 IN MX 20 mx2.clean.test.",
		},
		zoneKey("mx1.clean.test", "A"): {"mx1.clean.test. 300 IN A 192.0.2.20"},
		zoneKey("mx2.clean.test", "A"): {"mx2.clean.test. 300 IN A 192.0.2.21"},
	})
	corpus := &repFakeCorpus{}

	m := newTestService().repRun(context.Background(), "clean.test", addr, corpus)

	if m.Listed != 0 || m.Checked != 2 {
		t.Fatalf("listed=%d checked=%d, want 0 and 2", m.Listed, m.Checked)
	}
	if !hasNote(m.Notes, "ok", "Clean") {
		t.Errorf("a clean domain produced no positive finding; notes: %+v", m.Notes)
	}
	// Bounded by the corpus read, named as a reader knows the feeds rather than by our slugs.
	if !hasNote(m.Notes, "ok", "IPsum") ||
		!hasNote(m.Notes, "ok", "Spamhaus DROP") {
		t.Errorf("the clean note doesn't name the corpus it read: %+v", m.Notes)
	}
	if !strings.Contains(m.Corpus, "not a live query") {
		t.Errorf("Corpus caveat = %q, want it to disclaim live DNSBL queries", m.Corpus)
	}
}

// An empty corpus (first boot, or feeds dead past the TTL) says "not listed" with no error.
func TestMXReputationAnEmptyCorpusIsNotClean(t *testing.T) {
	t.Parallel()

	_, addr := serveZone(t, testZone{
		zoneKey("empty.test", "MX"):    {"empty.test. 300 IN MX 10 mx1.empty.test."},
		zoneKey("mx1.empty.test", "A"): {"mx1.empty.test. 300 IN A 192.0.2.90"},
	})
	corpus := &repFakeCorpus{neverSynced: true}

	m := newTestService().repRun(context.Background(), "empty.test", addr, corpus)

	if m.Checked != 1 {
		t.Fatalf("checked = %d, want the address still read (rows: %+v)", m.Checked, m.Hosts)
	}
	if hasNote(m.Notes, "ok", "Clean") {
		t.Fatalf("an empty corpus produced a clean verdict: %+v", m.Notes)
	}
	if m.CorpusUsable() {
		t.Error("CorpusUsable() = true for a corpus no feed has ever written to")
	}
	if len(m.StaleFeeds) != len(m.Feeds) {
		t.Errorf("StaleFeeds = %v, want every feed (%v)", m.StaleFeeds, m.Feeds)
	}
	if !m.CorpusSynced.IsZero() {
		t.Errorf("CorpusSynced = %v, want the zero time for a corpus never written to", m.CorpusSynced)
	}
	if !hasNote(m.Notes, "warn", "not checked") {
		t.Errorf("the reader is not told to read this as 'not checked': %+v", m.Notes)
	}
}

// The clean result still stands on the current feed, and the card names the stale one.
func TestMXReputationAStaleFeedQualifiesTheCleanResult(t *testing.T) {
	t.Parallel()

	_, addr := serveZone(t, testZone{
		zoneKey("half.test", "MX"):    {"half.test. 300 IN MX 10 mx1.half.test."},
		zoneKey("mx1.half.test", "A"): {"mx1.half.test. 300 IN A 192.0.2.91"},
	})
	corpus := &repFakeCorpus{syncedAt: map[string]time.Time{
		iptools.BlocklistSourceSpamhausDROP: time.Now().Add(-20 * 24 * time.Hour),
	}}

	m := newTestService().repRun(context.Background(), "half.test", addr, corpus)

	if !m.CorpusUsable() {
		t.Fatal("CorpusUsable() = false while one feed is still current")
	}
	if !hasNote(m.Notes, "ok", "Clean") {
		t.Errorf("a current feed still backs a clean result; notes: %+v", m.Notes)
	}
	if !hasNote(m.Notes, "warn", iptools.BlocklistSourceSpamhausDROP) {
		t.Errorf("the stale feed is not named: %+v", m.Notes)
	}
	if hasNote(m.Notes, "warn", iptools.BlocklistSourceIPsum) {
		t.Errorf("the current feed was reported as stale: %+v", m.Notes)
	}
}

func TestMXReputationUnreadableFreshnessIsNotClean(t *testing.T) {
	t.Parallel()

	_, addr := serveZone(t, testZone{
		zoneKey("age.test", "MX"):    {"age.test. 300 IN MX 10 mx1.age.test."},
		zoneKey("mx1.age.test", "A"): {"mx1.age.test. 300 IN A 192.0.2.92"},
	})
	corpus := &repFakeCorpus{syncErr: errors.New("mongo is down")}

	m := newTestService().repRun(context.Background(), "age.test", addr, corpus)

	if hasNote(m.Notes, "ok", "Clean") {
		t.Errorf("an unreadable corpus age produced a clean verdict: %+v", m.Notes)
	}
	if !hasNote(m.Notes, "warn", "freshness could not be read") {
		t.Errorf("no note says why the corpus cannot back the result: %+v", m.Notes)
	}
}

// Preference order, so the cap keeps the hosts a sender tries first, not RRset rotation's pick.
func TestMXReputationTakesHostsInPreferenceOrder(t *testing.T) {
	t.Parallel()

	z := testZone{zoneKey("order.test", "MX"): {
		"order.test. 300 IN MX 30 third.order.test.",
		"order.test. 300 IN MX 10 first.order.test.",
		"order.test. 300 IN MX 20 second.order.test.",
	}}
	for i, h := range []string{"first", "second", "third"} {
		z[zoneKey(h+".order.test", "A")] = []string{fmt.Sprintf("%s.order.test. 300 IN A 192.0.2.%d", h, 30+i)}
	}
	_, addr := serveZone(t, z)
	m := newTestService().repRun(context.Background(), "order.test", addr, &repFakeCorpus{})

	var got []string
	for _, h := range m.Hosts {
		got = append(got, h.Host)
	}
	want := []string{"first.order.test", "second.order.test", "third.order.test"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("host order = %v, want %v", got, want)
	}
	if m.Hosts[0].Preference != 10 {
		t.Errorf("first host preference = %d, want 10", m.Hosts[0].Preference)
	}
}

func TestMXReputationBoundsItsFanOut(t *testing.T) {
	t.Parallel()

	z := testZone{}
	var mx []string
	for i := 0; i < 9; i++ {
		host := fmt.Sprintf("mx%d.big.test", i)
		mx = append(mx, fmt.Sprintf("big.test. 300 IN MX %d %s.", 10+i, host))
		// Three addresses each, past repMaxAddrsPerHost, so the per-host cap bites too.
		z[zoneKey(host, "A")] = []string{
			fmt.Sprintf("%s. 300 IN A 198.51.100.%d", host, 10+i),
			fmt.Sprintf("%s. 300 IN A 198.51.100.%d", host, 100+i),
			fmt.Sprintf("%s. 300 IN A 198.51.100.%d", host, 200+i),
		}
	}
	z[zoneKey("big.test", "MX")] = mx

	_, addr := serveZone(t, z)
	corpus := &repFakeCorpus{}
	m := newTestService().repRun(context.Background(), "big.test", addr, corpus)

	if m.MXCount != 9 {
		t.Fatalf("MXCount = %d, want all 9 published records counted", m.MXCount)
	}
	if len(m.Hosts) > maxMailHosts {
		t.Errorf("checked %d hosts, cap is %d", len(m.Hosts), maxMailHosts)
	}
	for _, h := range m.Hosts {
		if len(h.Addrs) > repMaxAddrsPerHost {
			t.Errorf("%s: %d addresses checked, cap is %d", h.Host, len(h.Addrs), repMaxAddrsPerHost)
		}
	}
	if m.Checked > repMaxChecks || corpus.count() > repMaxChecks {
		t.Errorf("checked=%d corpus reads=%d, cap is %d", m.Checked, corpus.count(), repMaxChecks)
	}
	if !m.HostsTruncated {
		t.Error("a capped run must admit it was capped")
	}
	if !hasNote(m.Notes, "info", "9 MX records") {
		t.Errorf("no note states how much of the delegation was skipped: %+v", m.Notes)
	}
}

// The outer loop misses a budget spent inside the last host, so that drop would be silent.
func TestMXReputationSaysWhenTheBudgetRanOutInsideAHost(t *testing.T) {
	t.Parallel()

	// 1+2+2+2+2 = 9 addresses, one past repMaxChecks: the ninth drops inside the last host.
	z := testZone{}
	var mx []string
	counts := []int{1, 2, 2, 2, 2}
	for i, n := range counts {
		host := fmt.Sprintf("m%d.bud.test", i)
		mx = append(mx, fmt.Sprintf("bud.test. 300 IN MX %d %s.", 10+i, host))
		var recs []string
		for j := 0; j < n; j++ {
			recs = append(recs, fmt.Sprintf("%s. 300 IN A 203.0.113.%d", host, 10*i+j+1))
		}
		z[zoneKey(host, "A")] = recs
	}
	z[zoneKey("bud.test", "MX")] = mx

	_, addr := serveZone(t, z)
	corpus := &repFakeCorpus{}
	m := newTestService().repRun(context.Background(), "bud.test", addr, corpus)

	if corpus.count() != repMaxChecks {
		t.Fatalf("corpus reads = %d, want the budget %d to be spent exactly", corpus.count(), repMaxChecks)
	}
	if len(m.Hosts) != len(counts) {
		t.Fatalf("host rows = %d, want all %d: no host was skipped whole", len(m.Hosts), len(counts))
	}
	if !m.AddrsTruncated {
		t.Error("an address dropped for want of budget left no trace on the struct")
	}
	if !hasNote(m.Notes, "info", "ran out") {
		t.Errorf("no note tells the reader some addresses were never read: %+v", m.Notes)
	}
	if !hasNote(m.Notes, "ok", fmt.Sprintf("all %d mail-server addresses", repMaxChecks)) {
		t.Errorf("the clean note's denominator is not what was read: %+v", m.Notes)
	}
}

// BlockList.Check answers "not listed" when disabled, so an error must never count as clean.
func TestMXReputationCorpusFailureIsNotClean(t *testing.T) {
	t.Parallel()

	_, a := serveZone(t, testZone{
		zoneKey("broken.test", "MX"):    {"broken.test. 300 IN MX 10 mx1.broken.test."},
		zoneKey("mx1.broken.test", "A"): {"mx1.broken.test. 300 IN A 192.0.2.40"},
	})
	corpus := &repFakeCorpus{err: errors.New("mongo is down")}

	m := newTestService().repRun(context.Background(), "broken.test", a, corpus)

	if m.Listed != 0 {
		t.Errorf("listed = %d, want 0: a failed read is not a listing either", m.Listed)
	}
	if got := m.Hosts[0].Addrs[0]; got.Error == "" || got.Listed {
		t.Errorf("address row = %+v, want an error and no verdict", got)
	}
	if hasNote(m.Notes, "ok", "Clean") {
		t.Errorf("an unreadable corpus produced a clean verdict: %+v", m.Notes)
	}
	if !hasNote(m.Notes, "warn", "not a clean result") {
		t.Errorf("no note separates 'could not read' from 'not listed': %+v", m.Notes)
	}
}

// RFC 7505: the zone receives no mail, so neither "nothing checked" nor "clean" is the answer.
func TestMXReputationNullMX(t *testing.T) {
	t.Parallel()

	_, a := serveZone(t, testZone{zoneKey("nomail.test", "MX"): {"nomail.test. 300 IN MX 0 ."}})
	corpus := &repFakeCorpus{}

	m := newTestService().repRun(context.Background(), "nomail.test", a, corpus)

	if !m.NullMX {
		t.Errorf("NullMX = false for a zone whose only MX is \"0 .\"")
	}
	if corpus.count() != 0 {
		t.Errorf("%d corpus reads for a domain that receives no mail", corpus.count())
	}
	if !hasNote(m.Notes, "info", "null MX") {
		t.Errorf("no note explains the null MX: %+v", m.Notes)
	}
}

// A null MX is every record targeting ".", not exactly one record.
func TestMXReputationNullMXDoesNotHaveToStandAlone(t *testing.T) {
	t.Parallel()

	_, a := serveZone(t, testZone{zoneKey("twonull.test", "MX"): {
		"twonull.test. 300 IN MX 0 .",
		"twonull.test. 300 IN MX 10 .",
	}})
	corpus := &repFakeCorpus{}

	m := newTestService().repRun(context.Background(), "twonull.test", a, corpus)

	if !m.NullMX {
		t.Errorf("NullMX = false for a zone whose every MX target is \".\" (MXCount=%d)", m.MXCount)
	}
	if corpus.count() != 0 {
		t.Errorf("%d corpus reads for a domain that receives no mail", corpus.count())
	}
	if !hasNote(m.Notes, "info", "null MX") {
		t.Errorf("no note explains the null MX: %+v", m.Notes)
	}
	if hasNote(m.Notes, "warn", "No mail-server address could be checked") {
		t.Errorf("a zone that refuses mail was reported as one we failed to check: %+v", m.Notes)
	}
}

// A null MX beside a real host breaks RFC 7505 §3; the real host is still checked.
func TestMXReputationNullMXAlongsideARealHost(t *testing.T) {
	t.Parallel()

	_, a := serveZone(t, testZone{
		zoneKey("mixed.test", "MX"): {
			"mixed.test. 300 IN MX 0 .",
			"mixed.test. 300 IN MX 10 mx1.mixed.test.",
		},
		zoneKey("mx1.mixed.test", "A"): {"mx1.mixed.test. 300 IN A 192.0.2.95"},
	})
	corpus := &repFakeCorpus{}

	m := newTestService().repRun(context.Background(), "mixed.test", a, corpus)

	if m.NullMX {
		t.Error("NullMX = true although the zone also publishes a real mail server")
	}
	if !m.NullMXConflict {
		t.Error("a null MX alongside a real host was not reported as the RFC 7505 violation it is")
	}
	if !hasNote(m.Notes, "warn", "RFC 7505") {
		t.Errorf("no note explains the contradiction: %+v", m.Notes)
	}
	if m.Checked != 1 {
		t.Errorf("checked = %d, want the real host still read (rows: %+v)", m.Checked, m.Hosts)
	}
}

func TestMXReputationNoMXRecords(t *testing.T) {
	t.Parallel()

	_, a := serveZone(t, testZone{zoneKey("nomx.test", "A"): {"nomx.test. 300 IN A 192.0.2.50"}})
	corpus := &repFakeCorpus{}

	m := newTestService().repRun(context.Background(), "nomx.test", a, corpus)

	if m.MXCount != 0 || corpus.count() != 0 {
		t.Errorf("MXCount=%d corpus reads=%d, want 0 and 0", m.MXCount, corpus.count())
	}
	if !hasNote(m.Notes, "info", "no MX records") {
		t.Errorf("notes = %+v, want one info note saying there is no mail server", m.Notes)
	}
}

// "Publishes no MX" would assert that a nonexistent name exists.
func TestMXReputationNXDomainIsNotTheSameAsNoMX(t *testing.T) {
	t.Parallel()

	_, a := serveZone(t, testZone{zoneKey("real.test", "A"): {"real.test. 300 IN A 192.0.2.80"}})
	corpus := &repFakeCorpus{}

	m := newTestService().repRun(context.Background(), "gone.example.test", a, corpus)

	if corpus.count() != 0 {
		t.Errorf("%d corpus reads for a name that does not exist", corpus.count())
	}
	if !hasNote(m.Notes, "info", "does not exist") {
		t.Errorf("notes = %+v, want one saying the name does not exist", m.Notes)
	}
	if hasNote(m.Notes, "info", "publishes no MX") {
		t.Errorf("an NXDOMAIN was reported as a domain that publishes no MX: %+v", m.Notes)
	}
}

// No public corpus lists an unroutable address, so checking one could only yield a false "clean".
func TestMXReputationSkipsUnroutableAddresses(t *testing.T) {
	t.Parallel()

	_, a := serveZone(t, testZone{
		zoneKey("private.test", "MX"):    {"private.test. 300 IN MX 10 mx1.private.test."},
		zoneKey("mx1.private.test", "A"): {"mx1.private.test. 300 IN A 10.0.0.5"},
	})
	corpus := &repFakeCorpus{}

	m := newTestService().repRun(context.Background(), "private.test", a, corpus)

	if corpus.count() != 0 {
		t.Errorf("%d corpus reads for a private address", corpus.count())
	}
	if got := m.Hosts[0].Error; !strings.Contains(got, "routable") {
		t.Errorf("host error = %q, want it to say the address is not routable", got)
	}
	if hasNote(m.Notes, "ok", "Clean") {
		t.Errorf("an unprobed host produced a clean verdict: %+v", m.Notes)
	}
}

// Only NODATA says the zone publishes no address; a SERVFAIL'd record may well exist.
func TestMXReputationSeparatesAFailedLookupFromAMissingRecord(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		domain   string
		zone     testZone
		servfail []string
		want     string
		notWant  string
	}{
		{
			name:   "servfail",
			domain: "fail.test",
			zone: testZone{
				zoneKey("fail.test", "MX"):    {"fail.test. 300 IN MX 10 mx1.fail.test."},
				zoneKey("mx1.fail.test", "A"): {"mx1.fail.test. 300 IN A 198.51.100.7"},
			},
			servfail: []string{zoneKey("mx1.fail.test", "A"), zoneKey("mx1.fail.test", "AAAA")},
			want:     "could not be resolved",
			notWant:  "publishes no A or AAAA record",
		},
		{
			name:   "nxdomain",
			domain: "ghost.test",
			zone: testZone{
				zoneKey("ghost.test", "MX"): {"ghost.test. 300 IN MX 10 mx1.ghost.test."},
			},
			want:    "does not exist",
			notWant: "publishes no A or AAAA record",
		},
		{
			name:   "nodata",
			domain: "bare.test",
			zone: testZone{
				zoneKey("bare.test", "MX"):      {"bare.test. 300 IN MX 10 mx1.bare.test."},
				zoneKey("mx1.bare.test", "TXT"): {`mx1.bare.test. 300 IN TXT "here but addressless"`},
			},
			want:    "publishes no A or AAAA record",
			notWant: "could not be resolved",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			addr := serveFailingZone(t, c.zone, c.servfail)
			m := newTestService().repRun(context.Background(), c.domain, addr, &repFakeCorpus{})

			if len(m.Hosts) != 1 {
				t.Fatalf("host rows = %d, want 1 (%+v)", len(m.Hosts), m.Hosts)
			}
			if got := m.Hosts[0].Error; !strings.Contains(got, c.want) {
				t.Errorf("host error = %q, want it to contain %q", got, c.want)
			}
			if got := m.Hosts[0].Error; strings.Contains(got, c.notWant) {
				t.Errorf("host error = %q, which asserts %q the answer does not support", got, c.notWant)
			}
			if !hasNote(m.Notes, "warn", c.want) {
				t.Errorf("the note repeats a reason the answer does not support: %+v", m.Notes)
			}
		})
	}
}

// One address under two hosts is one machine: read once, counted once in the clean denominator.
func TestMXReputationReadsASharedAddressOnce(t *testing.T) {
	t.Parallel()

	_, addr := serveZone(t, testZone{
		zoneKey("dup.test", "MX"): {
			"dup.test. 300 IN MX 10 a.dup.test.",
			"dup.test. 300 IN MX 20 b.dup.test.",
		},
		zoneKey("a.dup.test", "A"): {"a.dup.test. 300 IN A 198.51.100.9"},
		zoneKey("b.dup.test", "A"): {"b.dup.test. 300 IN A 198.51.100.9"},
	})
	corpus := &repFakeCorpus{listed: map[string]iptools.BlockLookup{
		"198.51.100.9": {Sources: []string{"ipsum"}, MaxCount: 4},
	}}

	m := newTestService().repRun(context.Background(), "dup.test", addr, corpus)

	if got := corpus.count(); got != 1 {
		t.Errorf("corpus reads = %d, want the shared address read once", got)
	}
	if m.Checked != 1 || m.Listed != 1 {
		t.Errorf("checked=%d listed=%d, want 1 and 1: one address, counted once", m.Checked, m.Listed)
	}
	// Shown on both rows, the second marked as the duplicate.
	if len(m.Hosts) != 2 || len(m.Hosts[1].Addrs) != 1 {
		t.Fatalf("rows = %+v, want the address on both hosts", m.Hosts)
	}
	if m.Hosts[0].Addrs[0].Duplicate {
		t.Error("the first occurrence was marked as a duplicate")
	}
	if !m.Hosts[1].Addrs[0].Duplicate {
		t.Error("the repeated address is not marked, so the row count and the checked count look inconsistent")
	}
	fails := slices.DeleteFunc(slices.Clone(m.Notes), func(n Note) bool { return n.Level != "fail" })
	if len(fails) != 1 {
		t.Fatalf("%d failing notes for one listed address: %+v", len(fails), fails)
	}
	for _, want := range []string{"a.dup.test", "b.dup.test", "are listed"} {
		if !strings.Contains(fails[0].Text, want) {
			t.Errorf("the finding does not mention %q: %s", want, fails[0].Text)
		}
	}
}

// Rows whose host never resolved were never read, so the note must not call them checked.
func TestMXReputationTruncationNoteCountsWhatItLookedAt(t *testing.T) {
	t.Parallel()

	z := testZone{}
	var mx []string
	for i := 0; i < 9; i++ {
		host := fmt.Sprintf("mx%d.part.test", i)
		mx = append(mx, fmt.Sprintf("part.test. 300 IN MX %d %s.", 10+i, host))
		// The 2nd and 3rd most-preferred publish no address at all.
		if i == 1 || i == 2 {
			z[zoneKey(host, "TXT")] = []string{fmt.Sprintf(`%s. 300 IN TXT "no address here"`, host)}
			continue
		}
		z[zoneKey(host, "A")] = []string{fmt.Sprintf("%s. 300 IN A 203.0.113.%d", host, 100+i)}
	}
	z[zoneKey("part.test", "MX")] = mx

	_, addr := serveZone(t, z)
	corpus := &repFakeCorpus{}
	m := newTestService().repRun(context.Background(), "part.test", addr, corpus)

	if !m.HostsTruncated || len(m.Hosts) != maxMailHosts {
		t.Fatalf("hosts=%d truncated=%v, want the %d-host cap to bite", len(m.Hosts), m.HostsTruncated, maxMailHosts)
	}
	if m.Checked != 3 || corpus.count() != 3 {
		t.Fatalf("checked=%d reads=%d, want 3: two of the five rows resolve to nothing", m.Checked, corpus.count())
	}
	if !hasNote(m.Notes, "info", "looked at") {
		t.Errorf("the truncation note counts rows as checked when two were never read: %+v", m.Notes)
	}
	if hasNote(m.Notes, "info", "most-preferred were checked") {
		t.Errorf("the note still says five were checked when three were: %+v", m.Notes)
	}
}

func TestMXReputationStopsWhenTheCallerGoesAway(t *testing.T) {
	t.Parallel()

	_, a := serveZone(t, testZone{
		zoneKey("gone.test", "MX"):    {"gone.test. 300 IN MX 10 mx1.gone.test."},
		zoneKey("mx1.gone.test", "A"): {"mx1.gone.test. 300 IN A 192.0.2.60"},
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	corpus := &repFakeCorpus{}

	m := newTestService().repRun(ctx, "gone.test", a, corpus)

	if corpus.count() != 0 {
		t.Errorf("%d corpus reads after the caller went away", corpus.count())
	}
	if hasNote(m.Notes, "ok", "Clean") {
		t.Errorf("an abandoned request produced a clean verdict: %+v", m.Notes)
	}
}

// cancelOnCheck ends the request during the first corpus read, as a deadline would mid-check.
type cancelOnCheck struct {
	*repFakeCorpus
	cancel context.CancelFunc
}

func (c cancelOnCheck) Check(ctx context.Context, ip string) (iptools.BlockLookup, error) {
	c.cancel()
	return c.repFakeCorpus.Check(ctx, ip)
}

func TestMXReputationCutShortSaysSoOnce(t *testing.T) {
	t.Parallel()

	_, a := serveZone(t, testZone{
		zoneKey("late.test", "MX"): {
			"late.test. 300 IN MX 10 mx1.late.test.",
			"late.test. 300 IN MX 20 mx2.late.test.",
			"late.test. 300 IN MX 30 mx3.late.test.",
		},
		zoneKey("mx1.late.test", "A"): {"mx1.late.test. 300 IN A 192.0.2.61"},
		zoneKey("mx2.late.test", "A"): {"mx2.late.test. 300 IN A 192.0.2.62"},
		zoneKey("mx3.late.test", "A"): {"mx3.late.test. 300 IN A 192.0.2.63"},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := newTestService().repRun(ctx, "late.test", a, cancelOnCheck{&repFakeCorpus{}, cancel})

	if !hasNote(m.Notes, "warn", "cut short before every mail server was read") {
		t.Errorf("no note says the check was cut short: %+v", m.Notes)
	}
	if hasNote(m.Notes, "warn", "could not be resolved") {
		t.Errorf("hosts never reached are reported as unresolvable: %+v", m.Notes)
	}
}

// Slices marshal as [], and the caveat travels in the payload, not only in the template.
func TestMXReputationJSONShape(t *testing.T) {
	t.Parallel()

	_, a := serveZone(t, testZone{
		zoneKey("json.test", "MX"):    {"json.test. 300 IN MX 10 mx1.json.test."},
		zoneKey("mx1.json.test", "A"): {"mx1.json.test. 300 IN A 192.0.2.70"},
	})
	m := newTestService().repRun(context.Background(), "json.test", a, &repFakeCorpus{})

	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(b)
	for _, want := range []string{`"hosts":[`, `"addresses":[`, `"notes":[`, `"feeds":[`, `"corpus":"`, `"checked":1`, `"corpus_synced":"`} {
		if !strings.Contains(body, want) {
			t.Errorf("JSON is missing %s\ngot: %s", want, body)
		}
	}
	if strings.Contains(body, ":null") {
		t.Errorf("a slice marshalled as null, which a JSON caller has to special-case:\n%s", body)
	}

	// Freshness fields are absent when there is nothing to say, present when there is.
	stale := newTestService().repRun(context.Background(), "json.test", a, &repFakeCorpus{neverSynced: true})
	sb, err := json.Marshal(stale)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(sb), `"stale_feeds":[`) {
		t.Errorf("an unusable corpus is invisible to a JSON caller:\n%s", sb)
	}
	if strings.Contains(string(sb), `"corpus_synced"`) {
		t.Errorf("a corpus never synced still reported a sync time:\n%s", sb)
	}
}

// serveFailingZone is serveZone where the keys in servfail answer SERVFAIL.
func serveFailingZone(t *testing.T, z testZone, servfail []string) string {
	t.Helper()
	_, addr := serveZoneWith(t, z, func(m *dns.Msg, q dns.Question) {
		if slices.Contains(servfail, zoneKey(q.Name, dns.TypeToString[q.Qtype])) {
			m.Answer, m.Rcode = nil, dns.RcodeServerFailure
		}
	})
	return addr
}
