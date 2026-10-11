package tests

// The hermetic cases (caps, wording, dead corpus, null MX) are white-box, next to the code.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/dnstools"
	"github.com/Landver/site-of-tools/tools/iptools"
)

// repCorpus is a corpus a test controls; listAll is the only way to reach "listed" live.
type repCorpus struct {
	listAll bool
	err     error
	// neverSynced: nothing ever wrote here, an empty collection rather than a clean internet.
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

// Bad input gets the package's sentinels, so statusFor maps it to 400.
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
		{"8.8.8.8", dnstools.ErrNeedDomain},
		{"2606:4700:4700::1111", dnstools.ErrNeedDomain},
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

// No Mongo means no card, never every mail server rendered clean.
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

// A typed nil BlockList answers "not listed" to everything, so the constructor returns a true nil.
func TestBlockCheckerFromANilRepositoryIsNil(t *testing.T) {
	t.Parallel()

	if bc := dnstools.BlockCheckerFrom(nil); bc != nil {
		t.Fatal("a nil *iptools.BlockList produced a non-nil BlockChecker, which would report every mail server as clean")
	}
	// The mistake itself, so the constructor's reason is written down in a test.
	var raw *iptools.BlockList
	var asChecker dnstools.BlockChecker = raw
	if asChecker == nil {
		t.Fatal("a typed nil in an interface should be non-nil; the constructor would be pointless")
	}
	if lk, err := asChecker.Check(context.Background(), "192.0.2.1"); err != nil || lk.Listed() {
		t.Fatalf("nil repository Check = (%+v, %v), want a zero lookup: that is the silent-clean failure", lk, err)
	}
}

// The service refuses a typed nil too: main.go hands the bare *iptools.BlockList to other tools.
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

// A real domain end to end: MX, addresses, each read against the corpus, and a positive finding.
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
		t.Skipf("MX hosts came back but none of them resolved to an address (%+v) — flaky network, not a code failure", m.Hosts)
	}
	if m.Checked != corpus.count() {
		t.Errorf("Checked = %d but the corpus was read %d times", m.Checked, corpus.count())
	}
	if m.Listed != 0 {
		t.Errorf("listed = %d against an empty corpus", m.Listed)
	}
	if len(notesAt(m.Notes, "ok")) == 0 {
		t.Errorf("a clean result produced no positive finding; notes: %+v", m.Notes)
	}
	// The caveat travels with the data, not only with the HTML.
	for _, want := range []string{"IPsum", "Spamhaus DROP", "not a live query"} {
		if !strings.Contains(m.Corpus, want) {
			t.Errorf("Corpus caveat %q is missing %q", m.Corpus, want)
		}
	}
	// A nil slice marshals as null, a shape every JSON caller would special-case.
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), ":null") {
		t.Errorf("a slice marshalled as null:\n%s", b)
	}
}

// The listed path live: real addresses aren't knowable in advance, so the corpus lists everything.
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
	fails := notesAt(m.Notes, "fail")
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
	if clean := notesAt(m.Notes, "ok"); len(clean) != 0 {
		t.Errorf("a listed domain also produced a clean finding: %v", clean)
	}
}

// A domain that receives no mail must not cost a single corpus read.
func TestMXReputationOnADomainWithNoMailLive(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(5 * time.Second)
	corpus := &repCorpus{}

	// example.com publishes the RFC 7505 null MX; if that changes, this skips.
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

// The card keeps the struct's promises: no green headline over an unusable corpus.
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

	// A usable corpus: green, with the repeated address labelled rather than counted twice.
	fresh := base()
	fresh.CorpusSynced = time.Now()
	html := renderCard(t, "dns/mxrep", map[string]any{"MXRep": fresh})
	for _, want := range []string{"text-ok", "2 checked, none in this corpus", "counted once", "Corpus last updated"} {
		if !strings.Contains(html, want) {
			t.Errorf("the card is missing %q:\n%s", want, html)
		}
	}

	// The same numbers over a corpus nothing wrote to: no green, and the headline says why.
	dead := base()
	dead.StaleFeeds = dead.Feeds
	html = renderCard(t, "dns/mxrep", map[string]any{"MXRep": dead})
	if strings.Contains(html, "none in this corpus") || strings.Contains(html, "none listed") {
		t.Errorf("an unusable corpus still rendered a clean headline:\n%s", html)
	}
	if !strings.Contains(html, "corpus not usable") {
		t.Errorf("the card does not say the corpus cannot back the count:\n%s", html)
	}

	// No key, no card: a switched-off corpus leaves no empty panel behind.
	if got := strings.TrimSpace(renderCard(t, "dns/mxrep", map[string]any{})); got != "" {
		t.Errorf("an absent MXRep rendered something: %q", got)
	}
}
