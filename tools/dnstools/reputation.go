package dnstools

// MX reputation reads the iptools blocklist corpus, not live DNSBLs: operators forbid bulk
// queries from public tools and answer a blocked querier "not listed".

import (
	"context"
	"errors"
	"fmt"
	"slices"
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
	repFeedNames       = "IPsum and Spamhaus DROP"
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

	seen map[string]MXRepAddr
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

// MXReputation does its own MX lookup (cached, so free after /email) because email.go keeps
// only one address per host. A nil bl is ErrNoBlocklist, never a clean result.
func (s *Service) MXReputation(ctx context.Context, domain string, bl BlockChecker) (*MXReputation, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if err := needDomain(domain); err != nil {
		return nil, err
	}
	// A typed-nil *iptools.BlockList is non-nil here and would answer "not listed" to all.
	if b, ok := bl.(*iptools.BlockList); bl == nil || ok && b == nil {
		return nil, ErrNoBlocklist
	}
	addr, _ := resolverAddr(DefaultResolver)
	return s.repRun(ctx, domain, addr, bl), nil
}

// repRun takes addr so white-box tests can aim it at loopback.
func (s *Service) repRun(ctx context.Context, domain, addr string, bl BlockChecker) *MXReputation {
	start := time.Now()
	m := &MXReputation{
		Domain: domain, Hosts: []MXRepHost{}, Notes: []Note{}, seen: map[string]MXRepAddr{},
		Feeds:  []string{iptools.BlocklistSourceIPsum, iptools.BlocklistSourceSpamhausDROP},
		Corpus: "Checked against a local copy of two lists, " + repFeedNames + ": not a live query of every blocklist, so a clean row means absent from these two and nothing wider.",
	}
	defer func() { m.QueryMS = time.Since(start).Milliseconds() }()

	mx, err := s.lookup(ctx, dnsFqdn(domain), "MX", addr)
	switch {
	case errors.Is(err, errNXDomain):
		m.note("info", "This name does not exist, so there is no mail server to check.")
		return m
	case errors.Is(err, errNoData):
		m.note("info", "This domain publishes no MX records, so it has no mail servers to check.")
		return m
	case err != nil:
		m.note("warn", "The MX lookup failed, so this check did not run. That is not evidence the mail servers are clean; re-run it.")
		return m
	}

	m.MXCount = len(mx.Records)
	hosts, nullMX, conflict := mailHosts(mx.Records)
	m.NullMX, m.NullMXConflict = nullMX, conflict
	if len(hosts) > maxMailHosts {
		hosts, m.HostsTruncated = hosts[:maxMailHosts], true
	}
	if len(hosts) > 0 {
		m.readCorpusAge(ctx, bl)
	}
	for _, h := range hosts {
		// One note, not a "could not be resolved" per host: MCP runs this under a deadline.
		if ctx.Err() != nil {
			m.note("warn", "The check was cut short before every mail server was read, so this result is partial.")
			break
		}
		if m.Checked+m.Unread >= repMaxChecks {
			m.HostsTruncated = true
			break
		}
		m.Hosts = append(m.Hosts, s.repCheckHost(ctx, h, addr, bl, m))
	}
	m.repJudge()
	return m
}

func (m *MXReputation) readCorpusAge(ctx context.Context, bl BlockChecker) {
	ctx, cancel := context.WithTimeout(ctx, repCorpusTimeout)
	defer cancel()
	for _, feed := range m.Feeds {
		last, err := bl.LastSync(ctx, feed)
		if err == nil && last.After(m.CorpusSynced) {
			m.CorpusSynced = last
		}
		if err != nil || time.Since(last) > repCorpusMaxAge {
			m.StaleFeeds = append(m.StaleFeeds, feed)
		}
	}
}

// CorpusUsable is false when every feed is stale, empty or unreadable, so a miss means nothing.
func (m *MXReputation) CorpusUsable() bool {
	return len(m.StaleFeeds) < len(m.Feeds)
}

// repCheckHost reads up to repMaxAddrsPerHost routable A, then AAAA, addresses of one host.
// A private address is never in a public corpus, so checking it could only fake a clean result.
func (s *Service) repCheckHost(ctx context.Context, h mxTarget, addr string, bl BlockChecker, m *MXReputation) MXRepHost {
	row := MXRepHost{Host: h.host, Preference: h.pref, Addrs: []MXRepAddr{}}
	var ips []string
	var nx int
	var failed, sawAddrs bool
	for _, t := range [...]string{"A", "AAAA"} {
		if len(ips) >= repMaxAddrsPerHost {
			break
		}
		r, err := s.lookup(ctx, dnsFqdn(h.host), t, addr)
		switch {
		case errors.Is(err, errNXDomain):
			nx++
		case err != nil && !errors.Is(err, errNoData):
			failed = true
		}
		for _, rec := range r.Records {
			sawAddrs = true
			if len(ips) < repMaxAddrsPerHost && iptools.Routable(rec.Value) {
				ips = append(ips, rec.Value)
			}
		}
	}
	switch {
	case len(ips) > 0:
	case failed: // we don't know what the host publishes, which isn't "nothing"
		row.Error = "could not be resolved (the address lookup failed)"
	case nx == 2:
		row.Error = "does not exist"
	case sawAddrs:
		row.Error = "publishes no routable public address (every A or AAAA record it has is private or otherwise unreachable)"
	default:
		row.Error = "publishes no A or AAAA record"
	}

	for _, ip := range ips {
		if prev, ok := m.seen[ip]; ok {
			prev.Duplicate = true
			row.Addrs = append(row.Addrs, prev)
			continue
		}
		if m.Checked+m.Unread >= repMaxChecks {
			m.AddrsTruncated = true
			break
		}
		a := MXRepAddr{IP: ip}
		cctx, cancel := context.WithTimeout(ctx, repCorpusTimeout)
		lk, err := bl.Check(cctx, ip)
		cancel()
		if err != nil {
			a.Error = "the blocklist corpus could not be read for this address"
			m.Unread++
		} else {
			a.Listed, a.Sources, a.Count = lk.Listed(), lk.SourcesLabel(), lk.MaxCount
			m.Checked++
			if a.Listed {
				m.Listed++
			}
		}
		m.seen[ip] = a
		row.Addrs = append(row.Addrs, a)
	}
	return row
}

// Show reports whether the card has a mail server or a problem to report.
func (m *MXReputation) Show() bool {
	return m != nil && (len(m.Hosts) > 0 || slices.ContainsFunc(m.Notes, func(n Note) bool { return n.Level == "warn" || n.Level == "fail" }))
}

// note uses email.go's severity vocabulary, so the shared dns/notes template renders both.
func (m *MXReputation) note(level, text string) {
	m.Notes = append(m.Notes, Note{Level: level, Text: text})
}

func (m *MXReputation) corpusAgeText() string {
	if m.CorpusSynced.IsZero() {
		return "no feed has ever written to it, or its freshness could not be read"
	}
	return fmt.Sprintf("it was last updated %d days ago", int(time.Since(m.CorpusSynced).Hours()/24))
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

	// One finding per listed address, naming every host that publishes it.
	var listed []MXRepAddr
	hostsOf := map[string][]string{}
	for _, h := range m.Hosts {
		for _, a := range h.Addrs {
			if a.Listed {
				if hostsOf[a.IP] == nil {
					listed = append(listed, a)
				}
				hostsOf[a.IP] = append(hostsOf[a.IP], h.Host)
			}
		}
	}
	for _, a := range listed {
		verb, subject, count := "is", "this server", ""
		if len(hostsOf[a.IP]) > 1 {
			verb, subject = "are", "these servers"
		}
		if a.Count > 0 {
			count = fmt.Sprintf(", with a confidence count of %d", a.Count)
		}
		m.note("fail", fmt.Sprintf("%s (%s) %s listed by %s%s. Receivers that use this list may refuse or filter mail from %s: find out why it was listed, fix it, then request removal from that list.",
			strings.Join(hostsOf[a.IP], ", "), a.IP, verb, a.Sources, count, subject))
	}
	if m.Listed > 0 && !m.CorpusUsable() {
		m.note("info", "That listing comes from a corpus that is not being kept up to date ("+m.corpusAgeText()+"), so it may already have been removed upstream.")
	}

	for _, h := range m.Hosts {
		if h.Error != "" {
			m.note("warn", h.Host+" "+h.Error+", so its reputation could not be checked.")
		}
	}
	if m.Unread > 0 {
		m.note("warn", fmt.Sprintf("Unread addresses: %d. The corpus could not be read for them, which is not a clean result, only a missing one.", m.Unread))
	}

	switch {
	case m.Listed > 0: // reported per address above
	case m.Checked == 0:
		m.note("warn", "No mail-server address could be checked, so this card says nothing about reputation either way.")
	case !m.CorpusUsable():
		m.note("warn", "No listing was found, but the corpus cannot support that: "+m.corpusAgeText()+". Read this as 'not checked' rather than clean.")
	default:
		text := "Clean: the one mail-server address checked is absent from " + repFeedNames + "."
		if m.Checked > 1 {
			text = fmt.Sprintf("Clean: all %d mail-server addresses checked are absent from %s.", m.Checked, repFeedNames)
		}
		m.note("ok", text)
		// With two feeds, a clean result has at most one stale feed behind it.
		if len(m.StaleFeeds) > 0 {
			m.note("warn", fmt.Sprintf("The %s feed has not written to this corpus in the last %d hours, so the clean result above rests only on the feed that has.",
				strings.Join(m.StaleFeeds, ", "), int(repCorpusMaxAge.Hours())))
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
