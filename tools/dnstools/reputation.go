package dnstools

// MX reputation reads the iptools blocklist corpus, not live DNSBLs: operators forbid bulk
// queries from public tools and answer a blocked querier "not listed".

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Landver/site-of-tools/tools/iptools"
)

// BlockChecker is what this card needs from *iptools.BlockList. LastSync is required: an
// empty corpus answers every Check "not listed", so freshness is the only tell.
type BlockChecker interface {
	Check(ctx context.Context, ip string) (iptools.BlockLookup, error)
	LastSync(ctx context.Context, source string) (time.Time, error)
}

// BlockCheckerFrom returns nil for a nil list: a typed nil would report every address clean.
func BlockCheckerFrom(bl *iptools.BlockList) BlockChecker {
	if bl == nil {
		return nil
	}
	return bl
}

type Reputer interface {
	MXReputation(ctx context.Context, domain string, bl BlockChecker) (*MXReputation, error)
}

// ErrNoBlocklist: no corpus is wired (no MONGODB_URI), so the handler skips the card.
var ErrNoBlocklist = errors.New("the blocklist corpus is not available")

const (
	repMaxAddrsPerHost = 2
	repMaxChecks       = 8 // corpus reads per request; an address already read is free
	repCorpusTimeout   = 3 * time.Second
	repCorpusMaxAge    = 72 * time.Hour // feeds sync daily, so this is several failed runs
)

type MXReputation struct {
	Domain         string      `json:"domain"`
	Hosts          []MXRepHost `json:"hosts"`
	MXCount        int         `json:"mx_count"`
	HostsTruncated bool        `json:"hosts_truncated,omitempty"`
	// AddrsTruncated: the read budget ran out inside a host, so resolved addresses went unread.
	AddrsTruncated bool `json:"addresses_truncated,omitempty"`
	// NullMX: every MX targets "." (RFC 7505), so the domain receives no mail.
	NullMX bool `json:"null_mx,omitempty"`
	// NullMXConflict: a null MX beside real hosts, which RFC 7505 §3 forbids.
	NullMXConflict bool `json:"null_mx_conflict,omitempty"`
	// Checked counts distinct addresses actually read; a failed read goes to Unread instead.
	Checked int      `json:"checked"`
	Listed  int      `json:"listed"`
	Unread  int      `json:"unread,omitempty"`
	Feeds   []string `json:"feeds"`
	// CorpusSynced: the newest write by any feed; zero means the corpus is empty.
	CorpusSynced time.Time `json:"corpus_synced,omitzero"`
	// StaleFeeds: feeds older than repCorpusMaxAge, never written, or unreadable.
	StaleFeeds []string `json:"stale_feeds,omitempty"`
	// Corpus: the scope caveat, so a JSON caller doesn't assume a live Spamhaus query.
	Corpus  string `json:"corpus"`
	Notes   []Note `json:"notes"`
	QueryMS int64  `json:"query_ms"`

	attempted    int // reads started, so a failing corpus can't buy extra reads
	seen         map[string]MXRepAddr
	corpusAgeErr bool
}

type MXRepHost struct {
	Host       string      `json:"host"`
	Preference int         `json:"preference"`
	Addrs      []MXRepAddr `json:"addresses"`
	Error      string      `json:"error,omitempty"`
}

type MXRepAddr struct {
	IP string `json:"ip"`
	// Listed: the corpus holds this address or a netblock containing it.
	Listed  bool   `json:"listed"`
	Sources string `json:"sources,omitempty"`
	// Count: the strongest ipsum confidence; 0 means no listing carried a number.
	Count int `json:"count,omitempty"`
	// Duplicate: an earlier host published this address; shown again, counted once.
	Duplicate bool   `json:"duplicate,omitempty"`
	Error     string `json:"error,omitempty"`
}

func repFeeds() []string {
	return []string{iptools.BlocklistSourceIPsum, iptools.BlocklistSourceSpamhausDROP}
}

func repCorpusLine() string {
	return "Checked against a local copy of two lists, " + strings.Join(repFeedNames(repFeeds()), " and ") +
		": not a live query of every blocklist, so a clean row means absent from these two and nothing wider."
}

func repFeedNames(feeds []string) []string {
	out := make([]string, len(feeds))
	for i, f := range feeds {
		switch f {
		case iptools.BlocklistSourceIPsum:
			out[i] = "IPsum"
		case iptools.BlocklistSourceSpamhausDROP:
			out[i] = "Spamhaus DROP"
		default:
			out[i] = f
		}
	}
	return out
}

// MXReputation does its own MX lookup (cached, so free after /email) because email.go keeps
// only one address per host. A nil bl is ErrNoBlocklist, never a clean result.
func (s *Service) MXReputation(ctx context.Context, domain string, bl BlockChecker) (*MXReputation, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if err := needDomain(domain); err != nil {
		return nil, err
	}
	if bl == nil {
		return nil, ErrNoBlocklist
	}
	// A typed-nil *iptools.BlockList is non-nil here and would answer "not listed" to all.
	if b, ok := bl.(*iptools.BlockList); ok && b == nil {
		return nil, ErrNoBlocklist
	}
	addr, _ := resolverAddr(DefaultResolver)
	return s.repRun(ctx, domain, addr, bl), nil
}

// repRun takes addr so white-box tests can aim it at loopback; production passes only resolverAddr's.
func (s *Service) repRun(ctx context.Context, domain, addr string, bl BlockChecker) *MXReputation {
	out := &MXReputation{
		Domain: domain,
		Hosts:  []MXRepHost{},
		Feeds:  repFeeds(),
		Corpus: repCorpusLine(),
		Notes:  []Note{},
		seen:   map[string]MXRepAddr{},
	}
	start := time.Now()
	defer func() { out.QueryMS = time.Since(start).Milliseconds() }()

	mx, err := s.lookup(ctx, dnsFqdn(domain), "MX", addr)
	switch {
	case errors.Is(err, errNXDomain):
		out.note("info", "This name does not exist, so there is no mail server to check.")
		return out
	case errors.Is(err, errNoData):
		out.note("info", "This domain publishes no MX records, so it has no mail servers to check.")
		return out
	case err != nil:
		out.note("warn", "The MX lookup failed, so this check did not run. That is not evidence the mail servers are clean; re-run it.")
		return out
	}

	out.MXCount = len(mx.Records)
	hosts, nullMX, conflict := mailHosts(mx.Records)
	out.NullMX, out.NullMXConflict = nullMX, conflict
	if len(hosts) > maxMailHosts {
		hosts = hosts[:maxMailHosts]
		out.HostsTruncated = true
	}

	if len(hosts) > 0 {
		out.readCorpusAge(ctx, bl)
	}

	for _, h := range hosts {
		if ctx.Err() != nil {
			out.note("warn", "The check was cut short before every mail server was read, so the list of mail servers is partial.")
			break
		}
		if out.attempted >= repMaxChecks {
			out.HostsTruncated = true
			break
		}
		out.Hosts = append(out.Hosts, s.repCheckHost(ctx, h, addr, bl, out))
	}

	out.repJudge()
	return out
}

func (m *MXReputation) readCorpusAge(ctx context.Context, bl BlockChecker) {
	cctx, cancel := context.WithTimeout(ctx, repCorpusTimeout)
	defer cancel()

	for _, feed := range m.Feeds {
		last, err := bl.LastSync(cctx, feed)
		if err != nil {
			m.corpusAgeErr = true
			m.StaleFeeds = append(m.StaleFeeds, feed)
			continue
		}
		if last.After(m.CorpusSynced) {
			m.CorpusSynced = last
		}
		if last.IsZero() || time.Since(last) > repCorpusMaxAge {
			m.StaleFeeds = append(m.StaleFeeds, feed)
		}
	}
}

// CorpusUsable is false when every feed is stale, empty or unreadable, so a miss means nothing.
func (m *MXReputation) CorpusUsable() bool {
	return len(m.Feeds) > 0 && len(m.StaleFeeds) < len(m.Feeds)
}

// repResolveOutcome: why a host gave no address. NODATA is a fact about the zone; a failure isn't.
type repResolveOutcome int

const (
	repResolved repResolveOutcome = iota
	repHostNXDomain
	repHostNoAddress
	repHostUnroutable
	repHostLookupFailed
)

func (o repResolveOutcome) reason() string {
	switch o {
	case repHostNXDomain:
		return "does not exist"
	case repHostUnroutable:
		return "publishes no routable public address (every A or AAAA record it has is private or otherwise unreachable)"
	case repHostLookupFailed:
		return "could not be resolved (the address lookup failed)"
	default:
		return "publishes no A or AAAA record"
	}
}

// repCheckHost counts on out, so the caps are global rather than per host.
func (s *Service) repCheckHost(ctx context.Context, h mxTarget, addr string, bl BlockChecker, out *MXReputation) MXRepHost {
	row := MXRepHost{Host: h.host, Preference: h.pref, Addrs: []MXRepAddr{}}

	ips, why := s.repAddresses(ctx, h.host, addr)
	if len(ips) == 0 {
		row.Error = why.reason()
		return row
	}

	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		if prev, ok := out.seen[ip]; ok {
			prev.Duplicate = true
			row.Addrs = append(row.Addrs, prev)
			continue
		}
		if out.attempted >= repMaxChecks {
			out.AddrsTruncated = true
			break
		}
		a := repCheckIP(ctx, ip, bl)
		out.attempted++
		if a.Error != "" {
			out.Unread++
		} else {
			out.Checked++
			if a.Listed {
				out.Listed++
			}
		}
		out.seen[ip] = a
		row.Addrs = append(row.Addrs, a)
	}
	return row
}

// repAddresses returns up to repMaxAddrsPerHost routable A, then AAAA, addresses. A private
// address is never in a public corpus, so checking it could only fake a clean result.
func (s *Service) repAddresses(ctx context.Context, host, addr string) ([]string, repResolveOutcome) {
	var ips []string
	seen := map[string]bool{}
	var (
		asked, nx int
		failed    bool
		sawAddrs  bool // an A/AAAA record existed, routable or not
	)
	for _, t := range [...]string{"A", "AAAA"} {
		if ctx.Err() != nil || len(ips) >= repMaxAddrsPerHost {
			break
		}
		asked++
		r, err := s.lookup(ctx, dnsFqdn(host), t, addr)
		switch {
		case errors.Is(err, errNXDomain):
			nx++
			continue
		case errors.Is(err, errNoData):
			continue
		case err != nil:
			failed = true
			continue
		}
		for _, rec := range r.Records {
			if rec.Type != t {
				continue
			}
			sawAddrs = true
			if len(ips) >= repMaxAddrsPerHost {
				break
			}
			if seen[rec.Value] || !iptools.Routable(rec.Value) {
				continue
			}
			seen[rec.Value] = true
			ips = append(ips, rec.Value)
		}
	}

	switch {
	case len(ips) > 0:
		return ips, repResolved
	case failed || ctx.Err() != nil:
		// Any failure means we don't know what the host publishes, which isn't "nothing".
		return nil, repHostLookupFailed
	case asked > 0 && nx == asked:
		return nil, repHostNXDomain
	case sawAddrs:
		return nil, repHostUnroutable
	default:
		return nil, repHostNoAddress
	}
}

func repCheckIP(ctx context.Context, ip string, bl BlockChecker) MXRepAddr {
	a := MXRepAddr{IP: ip}
	cctx, cancel := context.WithTimeout(ctx, repCorpusTimeout)
	defer cancel()

	lk, err := bl.Check(cctx, ip)
	if err != nil {
		a.Error = "the blocklist corpus could not be read for this address"
		return a
	}
	a.Listed = lk.Listed()
	a.Sources = lk.SourcesLabel()
	a.Count = lk.MaxCount
	return a
}

// Show reports whether the card has a mail server or a problem to report.
func (m *MXReputation) Show() bool {
	if m == nil {
		return false
	}
	if len(m.Hosts) > 0 {
		return true
	}
	for _, n := range m.Notes {
		if n.Level == "warn" || n.Level == "fail" {
			return true
		}
	}
	return false
}

// note uses email.go's severity vocabulary, so the shared dns/notes template renders both.
func (m *MXReputation) note(level, text string) {
	m.Notes = append(m.Notes, Note{Level: level, Text: text})
}

// repListing: one listed address and every host publishing it, reported as one finding.
type repListing struct {
	addr  MXRepAddr
	hosts []string
}

func (m *MXReputation) listedAddrs() []repListing {
	var out []repListing
	at := map[string]int{}
	for _, h := range m.Hosts {
		for _, a := range h.Addrs {
			if !a.Listed {
				continue
			}
			if i, ok := at[a.IP]; ok {
				out[i].hosts = append(out[i].hosts, h.Host)
				continue
			}
			at[a.IP] = len(out)
			out = append(out, repListing{addr: a, hosts: []string{h.Host}})
		}
	}
	return out
}

// repNames joins host names for prose: "a", "a and b", "a, b and c".
func repNames(names []string) string {
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

func repAddrPhrase(n int) string {
	if n == 1 {
		return "one mail-server address"
	}
	return fmt.Sprintf("%d mail-server addresses", n)
}

func repRoughAge(d time.Duration) string {
	switch {
	case d < time.Hour:
		return "less than an hour"
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
}

func (m *MXReputation) corpusAgeText() string {
	switch {
	case m.corpusAgeErr:
		return "its freshness could not be read"
	case m.CorpusSynced.IsZero():
		return "no feed has ever written to it, so it is empty"
	default:
		return "it was last updated " + repRoughAge(time.Since(m.CorpusSynced)) + " ago"
	}
}

// repJudge turns the rows into notes. Pure: freshness was read before the first check.
func (m *MXReputation) repJudge() {
	if m.NullMX {
		m.note("info", "This domain publishes a null MX (RFC 7505): it declares that it receives no mail, so there is no mail server to check.")
		return
	}

	if m.NullMXConflict {
		m.note("warn", "This domain publishes a null MX (\".\") alongside real mail servers. RFC 7505 §3 requires the null MX to be the only record, so senders may read this zone as refusing mail altogether. The real hosts are checked below regardless.")
	}

	for _, g := range m.listedAddrs() {
		verb, subject := "is", "this server"
		if len(g.hosts) > 1 {
			verb, subject = "are", "these servers"
		}
		text := fmt.Sprintf("%s (%s) %s listed by %s.", repNames(g.hosts), g.addr.IP, verb, g.addr.Sources)
		if g.addr.Count > 0 {
			text = strings.TrimSuffix(text, ".") + fmt.Sprintf(", with a confidence count of %d.", g.addr.Count)
		}
		m.note("fail", text+" Receivers that use this list may refuse or filter mail from "+subject+": find out why it was listed, fix it, then request removal from that list.")
	}
	if m.Listed > 0 && !m.CorpusUsable() {
		m.note("info", "That listing comes from a corpus that is not being kept up to date ("+m.corpusAgeText()+"), so it may already have been removed upstream.")
	}

	for _, h := range m.Hosts {
		if h.Error != "" {
			m.note("warn", h.Host+" "+h.Error+", so its reputation could not be checked.")
		}
	}
	switch {
	case m.Unread == 1:
		m.note("warn", "One address could not be read against the corpus. That is not a clean result for it, only a missing one.")
	case m.Unread > 1:
		m.note("warn", fmt.Sprintf("%d addresses could not be read against the corpus. That is not a clean result for them, only a missing one.", m.Unread))
	}

	switch {
	case m.Listed > 0: // reported per address above
	case m.Checked == 0:
		m.note("warn", "No mail-server address could be checked, so this card says nothing about reputation either way.")
	case !m.CorpusUsable():
		m.note("warn", fmt.Sprintf(
			"Nothing was found for the %s read here, but the %s corpus cannot support that: %s. Read this as 'not checked' rather than clean.",
			repAddrPhrase(m.Checked), strings.Join(m.Feeds, " and "), m.corpusAgeText()))
	default:
		lists := strings.Join(repFeedNames(m.Feeds), " and ")
		text := "Clean: the one mail-server address checked is absent from " + lists + "."
		switch {
		case m.Checked == 2:
			text = "Clean: both mail-server addresses checked are absent from " + lists + "."
		case m.Checked > 2:
			text = fmt.Sprintf("Clean: all %d mail-server addresses checked are absent from %s.", m.Checked, lists)
		}
		m.note("ok", text)
		if len(m.StaleFeeds) > 0 {
			have := "feed has"
			if len(m.StaleFeeds) > 1 {
				have = "feeds have"
			}
			m.note("warn", fmt.Sprintf(
				"The %s %s not written to this corpus in the last %d hours, so the clean result above rests only on the feeds that have.",
				repNames(m.StaleFeeds), have, int(repCorpusMaxAge.Hours())))
		}
	}

	if m.HostsTruncated {
		// "Looked at", not "checked": hosts that didn't resolve are in len(m.Hosts).
		m.note("info", fmt.Sprintf("This domain publishes %d MX records; only the %d most-preferred were looked at, so the result covers those and not the rest.", m.MXCount, len(m.Hosts)))
	}
	if m.AddrsTruncated {
		m.note("info", fmt.Sprintf("The budget of %d corpus reads per request ran out before every resolved address was read, so some addresses of the mail servers above were not checked.", repMaxChecks))
	}
	sortNotes(m.Notes)
}
