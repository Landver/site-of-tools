package tests

// Black-box tests for the mail-server reputation card: the exported surface
// (MXReputation, BlockChecker, BlockCheckerFrom, ErrNoBlocklist) exercised the
// way a caller reaches it. The hermetic cases — caps, clean wording, a dead
// corpus, null MX — are white-box next to the code, because they need to drive
// the feature over a loopback zone.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/dnstools"
	"github.com/Landver/site-of-tools/tools/iptools"
)

// repCorpus: a blocklist corpus a test controls. listAll makes every address
// listed, which is the only way to exercise the "found something" path against
// a live domain whose real addresses are not known in advance.
type repCorpus struct {
	listAll bool
	err     error
	// neverSynced: no feed has ever written to this corpus, which is an empty
	// collection rather than a clean internet. The zero value is the opposite
	// — every feed synced just now — so only the cases about staleness say so.
	neverSynced bool

	mu    sync.Mutex
	calls int
}

func (c *repCorpus) Check(_ context.Context, ip string) (iptools.BlockLookup, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	if c.err != nil {
		return iptools.BlockLookup{}, c.err
	}
	if c.listAll {
		return iptools.BlockLookup{Sources: []string{iptools.BlocklistSourceIPsum}, MaxCount: 3}, nil
	}
	return iptools.BlockLookup{}, nil
}

// LastSync is the other half of the BlockChecker contract: an address missing
// from a corpus nothing has written to is not evidence of anything.
func (c *repCorpus) LastSync(_ context.Context, _ string) (time.Time, error) {
	if c.neverSynced {
		return time.Time{}, nil
	}
	return time.Now(), nil
}

func (c *repCorpus) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func repNotes(m *dnstools.MXReputation, level string) []string {
	var out []string
	for _, n := range m.Notes {
		if n.Level == level {
			out = append(out, n.Text)
		}
	}
	return out
}

// Bad input is the caller's mistake and must be reported as one, with the same
// sentinels the rest of the package uses so statusFor maps them to 400.
func TestMXReputationRejectsBadInput(t *testing.T) {
	t.Parallel()
	svc := dnstools.NewService(2 * time.Second)
	corpus := &repCorpus{}

	cases := []struct {
		name string
		want error
	}{
		{"", dnstools.ErrEmptyName},
		{"   ", dnstools.ErrEmptyName},
		{"8.8.8.8", dnstools.ErrBadType},
		{"2606:4700:4700::1111", dnstools.ErrBadType},
		{"not a domain!", dnstools.ErrBadName},
		{strings.Repeat("a.", 12) + "example.com", dnstools.ErrBadName},
	}
	for _, c := range cases {
		m, err := svc.MXReputation(context.Background(), c.name, corpus)
		if !errors.Is(err, c.want) {
			t.Errorf("MXReputation(%q) error = %v, want %v", c.name, err, c.want)
		}
		if m != nil {
			t.Errorf("MXReputation(%q) returned a result alongside an error", c.name)
		}
	}
	if corpus.count() != 0 {
		t.Errorf("%d corpus reads for input that never got past validation", corpus.count())
	}
}

// Golden rule #5: no Mongo, no corpus, and the app still boots. Here that has
// to mean the card is ABSENT, not that it renders every mail server as clean.
func TestMXReputationWithoutACorpusRefusesRatherThanClaimingClean(t *testing.T) {
	t.Parallel()
	svc := dnstools.NewService(2 * time.Second)

	m, err := svc.MXReputation(context.Background(), "example.com", nil)
	if !errors.Is(err, dnstools.ErrNoBlocklist) {
		t.Fatalf("error = %v, want ErrNoBlocklist", err)
	}
	if m != nil {
		t.Fatalf("got a result with no corpus: %+v", m)
	}
}

// The trap BlockCheckerFrom exists to close: *iptools.BlockList is nil-safe,
// so a nil one placed in an interface is a non-nil BlockChecker that answers
// "not listed" to everything. Wiring must go through the constructor, and the
// constructor must hand back a genuinely nil interface.
func TestBlockCheckerFromANilRepositoryIsNil(t *testing.T) {
	t.Parallel()

	if bc := dnstools.BlockCheckerFrom(nil); bc != nil {
		t.Fatal("a nil *iptools.BlockList produced a non-nil BlockChecker, which would report every mail server as clean")
	}
	// And the same nil repository handed straight to the interface is exactly
	// the mistake: it is non-nil, and its Check answers clean. Asserted so the
	// reason the constructor exists is written down in a test, not only a
	// comment.
	var raw *iptools.BlockList
	var asChecker dnstools.BlockChecker = raw
	if asChecker == nil {
		t.Fatal("a typed nil in an interface should be non-nil; the constructor would be pointless")
	}
	if lk, err := asChecker.Check(context.Background(), "192.0.2.1"); err != nil || lk.Listed() {
		t.Fatalf("nil repository Check = (%+v, %v), want a zero lookup: that is the silent-clean failure", lk, err)
	}
}

// …and the bypass around the constructor, which is the shape a future wiring
// edit will reach for by muscle memory: main.go already hands the bare
// *iptools.BlockList to iptools.Register and botcheck.Register. A card whose
// contract is "a switched-off corpus never renders as clean" cannot rest that
// on the caller remembering an adapter.
func TestMXReputationRefusesARawNilRepository(t *testing.T) {
	t.Parallel()
	svc := dnstools.NewService(2 * time.Second)

	var raw *iptools.BlockList // what NewBlockList returns with Mongo off
	m, err := svc.MXReputation(context.Background(), "example.com", raw)
	if !errors.Is(err, dnstools.ErrNoBlocklist) {
		t.Fatalf("error = %v, want ErrNoBlocklist: a typed nil answers 'not listed' to everything", err)
	}
	if m != nil {
		t.Fatalf("got a result from a disabled corpus: %+v", m)
	}
}

// A real domain, end to end: MX resolved, addresses found, every one of them
// read against the corpus, and a positive finding stating the result.
func TestMXReputationAgainstALiveDomain(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(5 * time.Second)
	corpus := &repCorpus{}

	m, err := svc.MXReputation(context.Background(), "github.com", corpus)
	if err != nil {
		t.Fatalf("reputation check: %v", err)
	}
	if m.MXCount == 0 || len(m.Hosts) == 0 {
		t.Skipf("github.com returned no MX records from this host; nothing to assert (%+v)", m.Notes)
	}
	if m.Checked == 0 {
		t.Fatalf("no address was read against the corpus; hosts: %+v", m.Hosts)
	}
	if m.Checked != corpus.count() {
		t.Errorf("Checked = %d but the corpus was read %d times", m.Checked, corpus.count())
	}
	if m.Listed != 0 {
		t.Errorf("listed = %d against an empty corpus", m.Listed)
	}
	if len(repNotes(m, "ok")) == 0 {
		t.Errorf("a clean result produced no positive finding; notes: %+v", m.Notes)
	}
	// The caveat travels with the data, not only with the HTML.
	for _, want := range []string{iptools.BlocklistSourceIPsum, iptools.BlocklistSourceSpamhausDROP, "not a live query"} {
		if !strings.Contains(m.Corpus, want) {
			t.Errorf("Corpus caveat %q is missing %q", m.Corpus, want)
		}
	}
	// JSON is half the contract, and a nil slice there is a shape every
	// caller has to special-case.
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), ":null") {
		t.Errorf("a slice marshalled as null:\n%s", b)
	}
}

// The failing path against a live domain: every address listed. Asserted
// through a corpus that lists everything, because the real addresses of a real
// mail provider are not knowable in advance and must not be hard-coded.
func TestMXReputationReportsListedMailServersLive(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(5 * time.Second)

	m, err := svc.MXReputation(context.Background(), "github.com", &repCorpus{listAll: true})
	if err != nil {
		t.Fatalf("reputation check: %v", err)
	}
	if m.Checked == 0 {
		t.Skipf("no mail-server address resolved from this host; notes: %+v", m.Notes)
	}
	if m.Listed != m.Checked {
		t.Fatalf("listed = %d of %d checked, want every address listed", m.Listed, m.Checked)
	}
	fails := repNotes(m, "fail")
	if len(fails) == 0 {
		t.Fatalf("listed mail servers produced no failing finding; notes: %+v", m.Notes)
	}
	// The finding has to be actionable: which host, which address, which feed.
	first := m.Hosts[0]
	for _, want := range []string{first.Host, first.Addrs[0].IP, iptools.BlocklistSourceIPsum} {
		if !strings.Contains(strings.Join(fails, "\n"), want) {
			t.Errorf("the failing finding never mentions %q:\n%s", want, strings.Join(fails, "\n"))
		}
	}
	if len(repNotes(m, "ok")) != 0 {
		t.Errorf("a listed domain also produced a clean finding: %v", repNotes(m, "ok"))
	}
}

// A domain that receives no mail is a statement about the zone, and the check
// must not spend a single corpus read on it.
func TestMXReputationOnADomainWithNoMailLive(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(5 * time.Second)
	corpus := &repCorpus{}

	// example.com publishes the RFC 7505 null MX. If that ever changes this
	// skips rather than failing: it would be the internet moving, not the code.
	m, err := svc.MXReputation(context.Background(), "example.com", corpus)
	if err != nil {
		t.Fatalf("reputation check: %v", err)
	}
	if !m.NullMX && m.MXCount != 0 {
		t.Skipf("example.com now publishes %d real MX records; nothing to assert here", m.MXCount)
	}
	if corpus.count() != 0 {
		t.Errorf("%d corpus reads for a domain that receives no mail", corpus.count())
	}
	if len(m.Notes) == 0 {
		t.Error("a domain with no mail server produced no explanation at all")
	}
}

// renderMXRep executes the card the way /email does: the page view model,
// with the result under "MXRep".
func renderMXRep(t *testing.T, vm map[string]any) string {
	t.Helper()
	tpl, err := template.New("mxrep").ParseFS(dnstools.Templates,
		"templates/reputation.html", "templates/notes.html")
	if err != nil {
		t.Fatalf("parse the card template: %v", err)
	}
	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "dns/mxrep", vm); err != nil {
		t.Fatalf("execute the card template: %v", err)
	}
	return buf.String()
}

// The HTML has to keep the same promises the struct does. The card is the
// half most readers see, and a green headline over an unusable corpus would
// undo every careful sentence in the notes below it.
func TestMXRepCardRendersTheSameClaimsAsTheData(t *testing.T) {
	t.Parallel()

	base := func() *dnstools.MXReputation {
		return &dnstools.MXReputation{
			Domain:  "example.test",
			MXCount: 1,
			Checked: 2,
			Feeds:   []string{iptools.BlocklistSourceIPsum, iptools.BlocklistSourceSpamhausDROP},
			Corpus:  "a locally synced copy, not a live query",
			Hosts: []dnstools.MXRepHost{{
				Host: "mx1.example.test", Preference: 10,
				Addrs: []dnstools.MXRepAddr{
					{IP: "198.51.100.1"},
					{IP: "198.51.100.2", Duplicate: true},
				},
			}},
			Notes: []dnstools.Note{{Level: "ok", Text: "Clean: all 2 …"}},
		}
	}

	// A usable corpus: the green headline, and the repeated address labelled
	// rather than silently inflating what the reader counts.
	fresh := base()
	fresh.CorpusSynced = time.Now()
	html := renderMXRep(t, map[string]any{"MXRep": fresh})
	for _, want := range []string{"text-ok", "2 checked, none in this corpus", "counted once", "Corpus last updated"} {
		if !strings.Contains(html, want) {
			t.Errorf("the card is missing %q:\n%s", want, html)
		}
	}

	// The same numbers over a corpus nothing has written to: no green, and
	// the headline says so rather than implying a result.
	dead := base()
	dead.StaleFeeds = dead.Feeds
	html = renderMXRep(t, map[string]any{"MXRep": dead})
	if strings.Contains(html, "none in this corpus") || strings.Contains(html, "none listed") {
		t.Errorf("an unusable corpus still rendered a clean headline:\n%s", html)
	}
	if !strings.Contains(html, "corpus not usable") {
		t.Errorf("the card does not say the corpus cannot back the count:\n%s", html)
	}

	// No key, no card: a switched-off corpus leaves no empty panel behind.
	if got := strings.TrimSpace(renderMXRep(t, map[string]any{})); got != "" {
		t.Errorf("an absent MXRep rendered something: %q", got)
	}
}
