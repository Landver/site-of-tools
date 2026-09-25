package dnstools

// White-box tests for the mail-server reputation card, the rule #6 exception:
// the subject is repRun, which takes the resolver address directly, and that
// is the only seam that lets the whole feature run over the loopback zone in
// testserver_test.go instead of the internet. Everything reachable through the
// exported API is tested black-box in tests/reputation_test.go.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Landver/site-of-tools/tools/iptools"
)

// repFakeCorpus stands in for the shared blocklist repository. Counting calls
// is half the point: the caps in reputation.go are only real if something
// asserts how many reads one request can make.
type repFakeCorpus struct {
	listed map[string]iptools.BlockLookup
	err    error

	// Freshness. The zero value means "every feed wrote to the corpus just
	// now", so the cases that are not about staleness read exactly as they
	// did before freshness existed; the cases that ARE about it set one of
	// these three explicitly.
	neverSynced bool                 // no feed has ever written: an empty corpus
	syncedAt    map[string]time.Time // per feed, for the partly-stale case
	syncErr     error                // the freshness read itself fails

	mu    sync.Mutex
	calls int
	seen  []string
}

func (f *repFakeCorpus) Check(_ context.Context, ip string) (iptools.BlockLookup, error) {
	f.mu.Lock()
	f.calls++
	f.seen = append(f.seen, ip)
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

func (f *repFakeCorpus) read() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.seen...)
}

// repNoteAt returns the texts of every note at one severity.
func repNoteAt(m *MXReputation, level string) []string {
	var out []string
	for _, n := range m.Notes {
		if n.Level == level {
			out = append(out, n.Text)
		}
	}
	return out
}

// repHasNote reports whether any note at level contains substr.
func repHasNote(m *MXReputation, level, substr string) bool {
	for _, t := range repNoteAt(m, level) {
		if strings.Contains(t, substr) {
			return true
		}
	}
	return false
}

// A listed mail server must be named, with its address and the feed that
// lists it. This is the whole feature: everything else is qualification.
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
		if !repHasNote(m, "fail", want) {
			t.Errorf("no failing note mentions %q; notes: %+v", want, m.Notes)
		}
	}
	// A listing is not a clean result, and must not also produce one.
	if ok := repNoteAt(m, "ok"); len(ok) > 0 {
		t.Errorf("a listed server produced an ok note too: %v", ok)
	}
}

// A clean result has to READ as clean. An empty card is the failure mode the
// docs call out: the reader cannot tell "nothing found" from "nothing looked".
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
	if !repHasNote(m, "ok", "Clean") {
		t.Errorf("a clean domain produced no positive finding; notes: %+v", m.Notes)
	}
	// The claim must be bounded by the corpus it was read from, not phrased as
	// "not blocklisted".
	if !repHasNote(m, "ok", iptools.BlocklistSourceIPsum) ||
		!repHasNote(m, "ok", iptools.BlocklistSourceSpamhausDROP) {
		t.Errorf("the clean note doesn't name the corpus it read: %+v", repNoteAt(m, "ok"))
	}
	if !strings.Contains(m.Corpus, "not a live query") {
		t.Errorf("Corpus caveat = %q, want it to disclaim live DNSBL queries", m.Corpus)
	}
}

// The named worst failure mode: a corpus that is switched on but EMPTY answers
// "not listed" to every address with a nil error, which is indistinguishable
// from a real miss at the call site. A first boot before the first sync, or a
// feed that has been failing long enough for the 60-day TTL to prune the
// collection, both land here — and neither is evidence that anything is clean.
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
	if repHasNote(m, "ok", "Clean") {
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
	if !repHasNote(m, "warn", "not checked") {
		t.Errorf("the reader is not told to read this as 'not checked': %+v", m.Notes)
	}
}

// One feed behind and one current is not the same as a dead corpus: the clean
// result still stands on the feed that is current, and the card says which
// half of the claim is missing rather than dropping the verdict entirely.
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
	if !repHasNote(m, "ok", "Clean") {
		t.Errorf("a current feed still backs a clean result; notes: %+v", m.Notes)
	}
	if !repHasNote(m, "warn", iptools.BlocklistSourceSpamhausDROP) {
		t.Errorf("the stale feed is not named: %+v", m.Notes)
	}
	if repHasNote(m, "warn", iptools.BlocklistSourceIPsum) {
		t.Errorf("the current feed was reported as stale: %+v", m.Notes)
	}
}

// A freshness read that fails is not a fresh corpus. Same rule as a failed
// Check: not knowing is never the good answer.
func TestMXReputationUnreadableFreshnessIsNotClean(t *testing.T) {
	t.Parallel()

	_, addr := serveZone(t, testZone{
		zoneKey("age.test", "MX"):    {"age.test. 300 IN MX 10 mx1.age.test."},
		zoneKey("mx1.age.test", "A"): {"mx1.age.test. 300 IN A 192.0.2.92"},
	})
	corpus := &repFakeCorpus{syncErr: errors.New("mongo is down")}

	m := newTestService().repRun(context.Background(), "age.test", addr, corpus)

	if repHasNote(m, "ok", "Clean") {
		t.Errorf("an unreadable corpus age produced a clean verdict: %+v", m.Notes)
	}
	if !repHasNote(m, "warn", "freshness could not be read") {
		t.Errorf("no note says why the corpus cannot back the result: %+v", m.Notes)
	}
}

// Hosts are taken in MX-preference order, so the hosts that fit inside the cap
// are the ones a sender really tries first rather than whichever the RRset
// rotation happened to put at the front.
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
	m := newTestService().repRun(context.Background(), "order.test", repAddrOf(t, z), &repFakeCorpus{})

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

// The budget is a hard ceiling, not a suggestion: this is a public endpoint
// and one click must not turn into an unbounded number of corpus reads.
func TestMXReputationBoundsItsFanOut(t *testing.T) {
	t.Parallel()

	z := testZone{}
	var mx []string
	for i := 0; i < 9; i++ {
		host := fmt.Sprintf("mx%d.big.test", i)
		mx = append(mx, fmt.Sprintf("big.test. 300 IN MX %d %s.", 10+i, host))
		// Three addresses each: more than repMaxAddrsPerHost, so the per-host
		// cap is exercised as well as the global one.
		z[zoneKey(host, "A")] = []string{
			fmt.Sprintf("%s. 300 IN A 198.51.100.%d", host, 10+i),
			fmt.Sprintf("%s. 300 IN A 198.51.100.%d", host, 100+i),
			fmt.Sprintf("%s. 300 IN A 198.51.100.%d", host, 200+i),
		}
	}
	z[zoneKey("big.test", "MX")] = mx

	corpus := &repFakeCorpus{}
	m := newTestService().repRun(context.Background(), "big.test", repAddrOf(t, z), corpus)

	if m.MXCount != 9 {
		t.Fatalf("MXCount = %d, want all 9 published records counted", m.MXCount)
	}
	if len(m.Hosts) > repMaxHosts {
		t.Errorf("checked %d hosts, cap is %d", len(m.Hosts), repMaxHosts)
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
	// And the admission has to reach the reader, with both numbers.
	if !repHasNote(m, "info", "9 MX records") {
		t.Errorf("no note states how much of the delegation was skipped: %+v", m.Notes)
	}
}

// The budget running out INSIDE a host is the silent case: the outer loop can
// only notice when another host remains, so on the last host the skipped
// addresses would disappear with no flag and no note.
func TestMXReputationSaysWhenTheBudgetRanOutInsideAHost(t *testing.T) {
	t.Parallel()

	// 1 + 2 + 2 + 2 + 2 = 9 addresses across five hosts, one more than
	// repMaxChecks, so the ninth is dropped inside the last host and no host
	// is skipped whole.
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

	corpus := &repFakeCorpus{}
	m := newTestService().repRun(context.Background(), "bud.test", repAddrOf(t, z), corpus)

	if corpus.count() != repMaxChecks {
		t.Fatalf("corpus reads = %d, want the budget %d to be spent exactly", corpus.count(), repMaxChecks)
	}
	if len(m.Hosts) != len(counts) {
		t.Fatalf("host rows = %d, want all %d: no host was skipped whole", len(m.Hosts), len(counts))
	}
	if !m.AddrsTruncated {
		t.Error("an address dropped for want of budget left no trace on the struct")
	}
	if !repHasNote(m, "info", "ran out") {
		t.Errorf("no note tells the reader some addresses were never read: %+v", m.Notes)
	}
	// And the clean sentence must not quietly claim the dropped one.
	if !repHasNote(m, "ok", fmt.Sprintf("all %d mail-server addresses", repMaxChecks)) {
		t.Errorf("the clean note's denominator is not what was read: %+v", repNoteAt(m, "ok"))
	}
}

// A corpus read that fails is not a clean address. BlockList.Check is nil-safe
// and answers "not listed" for a disabled store, so folding an error into the
// clean count is exactly how this card would start lying.
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
	if repHasNote(m, "ok", "Clean") {
		t.Errorf("an unreadable corpus produced a clean verdict: %+v", m.Notes)
	}
	if !repHasNote(m, "warn", "not a clean result") {
		t.Errorf("no note separates 'could not read' from 'not listed': %+v", m.Notes)
	}
}

// RFC 7505: the zone says it receives no mail, so there is no mail server to
// have a reputation. Reporting that as "nothing checked" would be true and
// useless; reporting it as clean would be false.
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
	if !repHasNote(m, "info", "null MX") {
		t.Errorf("no note explains the null MX: %+v", m.Notes)
	}
}

// Two null MX records is a badly written zone, not a zone that takes mail. The
// declaration is "every record says '.'", not "there is exactly one record":
// reading it the narrow way answered a zone that plainly refuses mail with the
// generic "nothing could be checked".
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
	if !repHasNote(m, "info", "null MX") {
		t.Errorf("no note explains the null MX: %+v", m.Notes)
	}
	if repHasNote(m, "warn", "No mail-server address could be checked") {
		t.Errorf("a zone that refuses mail was reported as one we failed to check: %+v", m.Notes)
	}
}

// A null MX next to a real mail server is a contradiction worth naming (RFC
// 7505 §3), and the real host still gets checked.
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
	if !repHasNote(m, "warn", "RFC 7505") {
		t.Errorf("no note explains the contradiction: %+v", m.Notes)
	}
	if m.Checked != 1 {
		t.Errorf("checked = %d, want the real host still read (rows: %+v)", m.Checked, m.Hosts)
	}
}

// A domain with no MX at all is a statement, not a failure, and must not read
// as one.
func TestMXReputationNoMXRecords(t *testing.T) {
	t.Parallel()

	_, a := serveZone(t, testZone{zoneKey("nomx.test", "A"): {"nomx.test. 300 IN A 192.0.2.50"}})
	corpus := &repFakeCorpus{}

	m := newTestService().repRun(context.Background(), "nomx.test", a, corpus)

	if m.MXCount != 0 || corpus.count() != 0 {
		t.Errorf("MXCount=%d corpus reads=%d, want 0 and 0", m.MXCount, corpus.count())
	}
	if !repHasNote(m, "info", "no MX records") {
		t.Errorf("notes = %+v, want one info note saying there is no mail server", m.Notes)
	}
}

// A name that does not exist is not a domain that publishes no MX. Saying the
// latter asserts the domain exists, which is the three-way NXDOMAIN / NODATA /
// NOERROR confusion this package partitions on everywhere else.
func TestMXReputationNXDomainIsNotTheSameAsNoMX(t *testing.T) {
	t.Parallel()

	// A zone serving one unrelated name: anything else answers NXDOMAIN.
	_, a := serveZone(t, testZone{zoneKey("real.test", "A"): {"real.test. 300 IN A 192.0.2.80"}})
	corpus := &repFakeCorpus{}

	m := newTestService().repRun(context.Background(), "gone.example.test", a, corpus)

	if corpus.count() != 0 {
		t.Errorf("%d corpus reads for a name that does not exist", corpus.count())
	}
	if !repHasNote(m, "info", "does not exist") {
		t.Errorf("notes = %+v, want one saying the name does not exist", m.Notes)
	}
	if repHasNote(m, "info", "publishes no MX") {
		t.Errorf("an NXDOMAIN was reported as a domain that publishes no MX: %+v", m.Notes)
	}
}

// An MX pointing somewhere unroutable is never in a public corpus, so checking
// it could only produce a reassuring "clean" about a machine no sender can
// reach. The host is reported instead.
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
	if repHasNote(m, "ok", "Clean") {
		t.Errorf("an unprobed host produced a clean verdict: %+v", m.Notes)
	}
}

// The three reasons a mail server contributes no address are three different
// answers, and only one of them is a claim about what the zone publishes.
// Reporting a SERVFAIL as "no A or AAAA record" states a fact about the zone
// that the data does not support — the record may well exist.
func TestMXReputationSeparatesAFailedLookupFromAMissingRecord(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		zone     testZone
		servfail []string
		want     string
		notWant  string
	}{
		{
			name: "servfail",
			zone: testZone{
				zoneKey("fail.test", "MX"):    {"fail.test. 300 IN MX 10 mx1.fail.test."},
				zoneKey("mx1.fail.test", "A"): {"mx1.fail.test. 300 IN A 198.51.100.7"},
			},
			servfail: []string{zoneKey("mx1.fail.test", "A"), zoneKey("mx1.fail.test", "AAAA")},
			want:     "could not be resolved",
			notWant:  "publishes no A or AAAA record",
		},
		{
			name: "nxdomain",
			zone: testZone{
				zoneKey("ghost.test", "MX"): {"ghost.test. 300 IN MX 10 mx1.ghost.test."},
			},
			want:    "does not exist",
			notWant: "publishes no A or AAAA record",
		},
		{
			name: "nodata",
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
			fail := map[string]bool{}
			for _, k := range c.servfail {
				fail[k] = true
			}
			addr := serveFailingZone(t, c.zone, fail)
			domain := strings.TrimSuffix(strings.SplitN(c.zone.anyMXOwner(), "|", 2)[0], ".")

			m := newTestService().repRun(context.Background(), domain, addr, &repFakeCorpus{})

			if len(m.Hosts) != 1 {
				t.Fatalf("host rows = %d, want 1 (%+v)", len(m.Hosts), m.Hosts)
			}
			if got := m.Hosts[0].Error; !strings.Contains(got, c.want) {
				t.Errorf("host error = %q, want it to contain %q", got, c.want)
			}
			if got := m.Hosts[0].Error; strings.Contains(got, c.notWant) {
				t.Errorf("host error = %q, which asserts %q the answer does not support", got, c.notWant)
			}
			if !repHasNote(m, "warn", c.want) {
				t.Errorf("the note repeats a reason the answer does not support: %+v", m.Notes)
			}
		})
	}
}

// One address published by two mail servers is one machine. Reading it twice
// spends the budget twice and, worse, counts it twice in the denominator of
// the clean sentence: "all 2 addresses checked" over a single address.
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

	if got := corpus.read(); len(got) != 1 {
		t.Errorf("corpus reads = %v, want the shared address read once", got)
	}
	if m.Checked != 1 || m.Listed != 1 {
		t.Errorf("checked=%d listed=%d, want 1 and 1: one address, counted once", m.Checked, m.Listed)
	}
	// It still shows on both rows — what a host resolves to is part of its row
	// — but the second one is marked as the copy it is.
	if len(m.Hosts) != 2 || len(m.Hosts[1].Addrs) != 1 {
		t.Fatalf("rows = %+v, want the address on both hosts", m.Hosts)
	}
	if m.Hosts[0].Addrs[0].Duplicate {
		t.Error("the first occurrence was marked as a duplicate")
	}
	if !m.Hosts[1].Addrs[0].Duplicate {
		t.Error("the repeated address is not marked, so the row count and the checked count look inconsistent")
	}
	// One finding, naming both hosts, rather than the same sentence twice.
	fails := repNoteAt(m, "fail")
	if len(fails) != 1 {
		t.Fatalf("%d failing notes for one listed address: %v", len(fails), fails)
	}
	for _, want := range []string{"a.dup.test", "b.dup.test", "are listed"} {
		if !strings.Contains(fails[0], want) {
			t.Errorf("the finding does not mention %q: %s", want, fails[0])
		}
	}
}

// The truncation note's denominator has to name what it counts. Rows whose
// host never resolved are in len(Hosts) and contributed nothing to the corpus
// reads, so calling them "checked" overstates the coverage.
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

	corpus := &repFakeCorpus{}
	m := newTestService().repRun(context.Background(), "part.test", repAddrOf(t, z), corpus)

	if !m.HostsTruncated || len(m.Hosts) != repMaxHosts {
		t.Fatalf("hosts=%d truncated=%v, want the %d-host cap to bite", len(m.Hosts), m.HostsTruncated, repMaxHosts)
	}
	if m.Checked != 3 || corpus.count() != 3 {
		t.Fatalf("checked=%d reads=%d, want 3: two of the five rows resolve to nothing", m.Checked, corpus.count())
	}
	note := strings.Join(repNoteAt(m, "info"), "\n")
	if !strings.Contains(note, "looked at") {
		t.Errorf("the truncation note counts rows as checked when two were never read: %s", note)
	}
	if strings.Contains(note, "most-preferred were checked") {
		t.Errorf("the note still says five were checked when three were: %s", note)
	}
}

// A cancelled request stops the work. The corpus reads are the expensive part
// and none of them should outlive the caller.
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
	if repHasNote(m, "ok", "Clean") {
		t.Errorf("an abandoned request produced a clean verdict: %+v", m.Notes)
	}
}

// The JSON representation is half the contract (golden rule #2), and the half
// a curl user sees. Slices must marshal as [] rather than null, and the
// caveat has to be in the payload rather than only in the template.
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

	// And the freshness fields a caller needs to weigh a miss: absent when
	// there is nothing to say, present the moment there is.
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

// repAddrOf is serveZone's second return value, for the cases that only need
// the address. Keeps the table-shaped tests above to one line of setup.
func repAddrOf(t *testing.T, z testZone) string {
	t.Helper()
	_, a := serveZone(t, z)
	return a
}

// anyMXOwner returns the zone key of the MX RRset, so a table case can name
// its domain once instead of twice.
func (z testZone) anyMXOwner() string {
	for k := range z {
		if strings.HasSuffix(k, "|MX") {
			return k
		}
	}
	return ""
}

// serveFailingZone is serveZone with an rcode: keys in servfail answer
// SERVFAIL instead of records. testserver_test.go's server has no failure
// path, and the difference between "the zone says nothing" and "we could not
// find out" cannot be tested without one.
func serveFailingZone(t *testing.T, z testZone, servfail map[string]bool) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	names := map[string]bool{}
	for k := range z {
		names[k[:strings.LastIndex(k, "|")]] = true
	}

	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg).SetReply(req)
		m.Authoritative = true
		if len(req.Question) == 1 {
			q := req.Question[0]
			name := strings.ToLower(q.Name)
			key := zoneKey(name, dns.TypeToString[q.Qtype])
			if servfail[key] {
				m.Rcode = dns.RcodeServerFailure
			} else {
				for _, s := range z[key] {
					rr, err := dns.NewRR(s)
					if err != nil {
						t.Errorf("canned record %q: %v", s, err)
						continue
					}
					m.Answer = append(m.Answer, rr)
				}
				if len(m.Answer) == 0 && !names[name] {
					m.Rcode = dns.RcodeNameError
				}
			}
		}
		_ = w.WriteMsg(m)
	})}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() {
		if err := srv.ActivateAndServe(); err != nil {
			t.Logf("test dns server stopped: %v", err)
		}
	}()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}
