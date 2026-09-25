package dnstools

// Mail-server reputation: are this domain's actual mail servers sitting on a
// blocklist?
//
// The rest of /email grades what the zone *says*. This asks the one question
// the records cannot answer: the machines those records point at — are they
// currently flagged anywhere? A perfect SPF/DMARC/DKIM triple in front of a
// listed relay still lands in the spam folder.
//
// What this is NOT, and the card says so in as many words: it is not a live
// query to every DNSBL operator. Operators rate-limit and forbid bulk
// querying from a public web tool, and half of them answer "not listed" to a
// blocked querier, which reads as a clean bill of health. What it IS: a read
// of the blocklist corpus this repo already syncs and already shares
// (tools/iptools/blocklist.go, fed daily by ipsum and Spamhaus DROP). Smaller
// coverage, stated honestly, beats a wide claim we cannot stand behind — the
// same reason /consistency refuses to print a "% propagated" verdict.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Landver/site-of-tools/tools/iptools"
)

// BlockChecker: the two things this feature needs from the shared IP blocklist
// corpus. Declared here, as an interface, for the reason Mailer and Spreader
// are declared in handler.go: dnstools must not open its own Mongo handle, and
// a nil dependency has to mean "this card is not rendered" rather than a
// panic. *iptools.BlockList satisfies it; a test fakes it in six lines.
//
// LastSync is in the interface rather than probed for with a type assertion
// because it is not optional. A reachable but EMPTY corpus answers Check with
// a zero lookup and a nil error for every address, which is indistinguishable
// from a real miss — so without freshness, a feed that has been failing long
// enough for the 60-day TTL to prune the corpus renders as every mail server
// being clean. Requiring the method means a checker that cannot say how fresh
// it is cannot be wired in by accident.
//
// The corpus is deliberately not iptools-owned — the comment on
// blocklistCollection says any service may read or write it — so consuming it
// from here is its intended use, not a layering breach.
type BlockChecker interface {
	Check(ctx context.Context, ip string) (iptools.BlockLookup, error)
	LastSync(ctx context.Context, source string) (time.Time, error)
}

// BlockCheckerFrom adapts the shared repository to the interface above, and
// exists to close one specific trap: *iptools.BlockList is nil-safe, so a nil
// one stuffed into an interface is a NON-nil BlockChecker that answers "not
// listed" to every address. That is the corpus being switched off rendering as
// every mail server being clean, which is the one thing this card must never
// say. A nil repository comes back as a nil interface, and MXReputation then
// refuses to run at all.
//
// MXReputation re-checks for the typed nil itself, so this is the documented
// front door rather than the only lock on it. main.go hands the bare
// *BlockList to iptools.Register and botcheck.Register, so passing it raw here
// is the mistake the house wiring style invites.
func BlockCheckerFrom(bl *iptools.BlockList) BlockChecker {
	if bl == nil {
		return nil
	}
	return bl
}

// Reputer: handler dependency for this card. Separate from Mailer so a test
// can fake either half on its own; *Service satisfies both.
type Reputer interface {
	MXReputation(ctx context.Context, domain string, bl BlockChecker) (*MXReputation, error)
}

// ErrNoBlocklist: the shared corpus is not wired (no MONGODB_URI, so no Mongo,
// so no blocklist). A missing dependency, not a failed lookup and not a clean
// result — the handler skips the card rather than printing one.
var ErrNoBlocklist = errors.New("the blocklist corpus is not available")

// Query budget for one call. DNS: 1 MX + up to repMaxHosts × 2 (A then AAAA)
// = 11 upstream queries worst case, every one of them going through the
// package cache and singleflight. Corpus: at most repMaxChecks reads plus one
// freshness read per feed, each under its own repCorpusTimeout. This is a
// public endpoint, so the ceiling is a constant rather than "however many MX
// records the zone feels like publishing".
const (
	// repMaxHosts: mail servers probed, in MX-preference order. Matches
	// email.go's maxMailHosts on purpose — the two cards should not disagree
	// about which hosts "the mail servers" means — but is its own constant, so
	// tuning one fan-out never silently moves the other.
	repMaxHosts = 5
	// repMaxAddrsPerHost: a big provider's MX name can carry a dozen A
	// records. Two is enough to catch a listed relay without turning one page
	// view into a table nobody reads.
	repMaxAddrsPerHost = 2
	// repMaxChecks: hard ceiling on corpus reads, independent of the two caps
	// above, so their product can never be the real budget. An address already
	// read earlier in the same request does not spend one: it is the same
	// answer about the same machine.
	repMaxChecks = 8
	// repCorpusTimeout: per corpus read. The corpus is a local Mongo query, so
	// this is generous; it exists so a wedged database cannot hold the request
	// open for the whole handler timeout.
	repCorpusTimeout = 3 * time.Second
	// repCorpusMaxAge: how old a feed's newest record may be before a miss
	// against it stops counting as evidence. iptools syncs every feed daily
	// (blocklistSyncInterval), so three days is several consecutive failed
	// runs rather than one slow afternoon.
	repCorpusMaxAge = 72 * time.Hour
)

// MXReputation: the answer for one domain. Serialises straight to JSON on
// /email?name=…, so every slice is non-nil and every caveat is a field rather
// than template prose only a browser would see.
type MXReputation struct {
	Domain string `json:"domain"`
	// Hosts: one row per mail server checked, in MX-preference order.
	Hosts []MXRepHost `json:"hosts"`
	// MXCount / HostsTruncated: how many MX records the zone publishes, and
	// whether repMaxHosts dropped some. A verdict that says "your mail
	// servers" after looking at five of nine is a lie, and this is what stops
	// the card writing that sentence.
	MXCount        int  `json:"mx_count"`
	HostsTruncated bool `json:"hosts_truncated,omitempty"`
	// AddrsTruncated: the corpus-read budget ran out INSIDE a host, so
	// addresses that resolved were never read. Separate from HostsTruncated
	// because that flag only ever describes whole mail servers we skipped, and
	// when the budget runs out on the last host there is no next host to skip
	// — the dropped addresses would otherwise vanish without a trace.
	AddrsTruncated bool `json:"addresses_truncated,omitempty"`
	// NullMX: every MX record the zone publishes targets "." (RFC 7505) — it
	// declares that it receives no mail, so there is no mail server to have a
	// reputation. Not restricted to the single-record case: two null MX
	// records are a badly written zone, not a zone that accepts mail.
	NullMX bool `json:"null_mx,omitempty"`
	// NullMXConflict: a null MX alongside real mail servers. RFC 7505 §3
	// requires the null MX to stand alone, so this is a contradiction in the
	// zone rather than a declaration — worth naming, and not a reason to stop
	// checking the real hosts.
	NullMXConflict bool `json:"null_mx_conflict,omitempty"`
	// Checked / Listed: DISTINCT addresses actually READ against the corpus,
	// and how many came back listed. Checked is the denominator every sentence
	// on the card is allowed to use, which is why an address whose read failed
	// is not in it (counting attempts here let a dead corpus report every mail
	// server as clean) and why one address published by two mail servers
	// counts once (counting it twice inflated the denominator of the clean
	// sentence).
	Checked int `json:"checked"`
	Listed  int `json:"listed"`
	// Unread: addresses the corpus could not be read for. Kept apart from
	// Checked for the reason above, and surfaced so a JSON caller sees the
	// gap rather than inferring a clean result from its absence.
	Unread int `json:"unread,omitempty"`
	// Feeds: the sources this corpus is synced from. Named rather than
	// summarised as "blocklists", because the size of the claim is the whole
	// point.
	Feeds []string `json:"feeds"`
	// CorpusSynced: the newest write any feed has made to the corpus. Zero
	// means no feed has ever written to it, i.e. the corpus is empty.
	CorpusSynced time.Time `json:"corpus_synced,omitzero"`
	// StaleFeeds: feeds whose newest record is older than repCorpusMaxAge, or
	// that have never written at all, or whose freshness could not be read.
	// When that is every feed, a miss is not evidence and the card says so
	// instead of saying "clean".
	StaleFeeds []string `json:"stale_feeds,omitempty"`
	// Corpus: the caveat in one sentence, carried in the JSON as well as on
	// the card. An API caller who only reads this struct must not come away
	// believing we queried Spamhaus ZEN live.
	Corpus  string `json:"corpus"`
	Notes   []Note `json:"notes"`
	QueryMS int64  `json:"query_ms"`

	// attempted: corpus reads started, successful or not. The budget has to
	// count attempts — a failing corpus must not buy extra reads — while
	// every sentence on the card counts Checked. Unexported, so the two can
	// never be confused in JSON.
	attempted int
	// seen: verdict per address already read in this request, so a shared
	// address costs one read and one slot in the denominator however many MX
	// names point at it.
	seen map[string]MXRepAddr
	// corpusAgeErr: the freshness read itself failed, which is its own reason
	// not to treat a miss as evidence.
	corpusAgeErr bool
}

// MXRepHost: one mail server and the addresses it resolves to.
type MXRepHost struct {
	Host string `json:"host"`
	// Preference: the MX preference, so the row order on the card is visibly
	// the order a sender would really try.
	Preference int         `json:"preference"`
	Addrs      []MXRepAddr `json:"addresses"`
	// Error: why this host contributed no address, as a clause about what we
	// found out rather than a claim about the zone. "Does not exist",
	// "publishes no A or AAAA record" and "the lookup failed" are three
	// different answers and only the middle one is a statement about the
	// records. Named, never silently dropped: an MX that does not resolve is
	// itself a finding.
	Error string `json:"error,omitempty"`
}

// MXRepAddr: one address and what the corpus holds on it.
type MXRepAddr struct {
	IP string `json:"ip"`
	// Listed: the corpus holds at least one record for this address, or for a
	// netblock containing it.
	Listed bool `json:"listed"`
	// Sources: which feeds list it ("ipsum, spamhaus-drop"), empty when clean.
	Sources string `json:"sources,omitempty"`
	// Count: the strongest confidence any listing carried (ipsum publishes how
	// many of its ~30 upstream lists flag an address). 0 means no listing
	// carried a number, which is not the same as a weak listing.
	Count int `json:"count,omitempty"`
	// Duplicate: an earlier mail server in this same answer published this
	// address, so the verdict here is a copy of that one read. Shown, because
	// what a host resolves to is part of its row, but never counted twice.
	Duplicate bool `json:"duplicate,omitempty"`
	// Error: the corpus read itself failed. Present so this address is never
	// counted as clean — "we could not find out" and "it is not listed" are
	// different answers and only one of them is good news.
	Error string `json:"error,omitempty"`
}

// repFeeds names the syncs that fill the corpus. Built from iptools' exported
// source constants so a renamed feed cannot leave this card describing one
// that no longer exists.
func repFeeds() []string {
	return []string{iptools.BlocklistSourceIPsum, iptools.BlocklistSourceSpamhausDROP}
}

// repCorpusLine is the honesty line, kept beside the feed list it describes.
func repCorpusLine() string {
	return "Checked against a locally synced copy of " +
		strings.Join(repFeeds(), " and ") +
		", not a live query to every DNSBL operator. A clean result here means these addresses are absent from that corpus, which is narrower than being absent from every blocklist."
}

// MXReputation resolves the domain's mail servers and reads each address
// against the shared blocklist corpus.
//
// It takes the DOMAIN rather than a ready-made MX host list, and does its own
// MX lookup, for three reasons. One: it is then a complete answer to a
// complete question, callable from the JSON API or a test without first
// running EmailAuth. Two: the lookup is not a duplicate in practice —
// s.lookup goes through the same cache and the same singleflight as every
// other query in the package, keyed name|MX|resolver, so when /email has just
// resolved MX the second ask costs nothing and does not leave the box. Three:
// taking a []MailHost would weld this file to email.go's shape, and email.go
// keeps only the first address per host, which is precisely the wrong input
// for a check that has to look at every address.
//
// bl is injected the way spread.go's AddDelegationHealth takes asnOf: the
// domain layer cannot open a database, so the thing it cannot fetch arrives as
// an argument. A nil bl is ErrNoBlocklist, never an empty clean result.
func (s *Service) MXReputation(ctx context.Context, domain string, bl BlockChecker) (*MXReputation, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return nil, ErrEmptyName
	}
	if _, isIP := reverseName(domain); isIP {
		return nil, fmt.Errorf("%w: give a domain name, not an IP", ErrBadType)
	}
	if err := validDomain(domain); err != nil {
		return nil, err
	}
	if bl == nil {
		return nil, ErrNoBlocklist
	}
	// The typed nil BlockCheckerFrom exists to prevent, caught again here: a
	// nil *iptools.BlockList inside an interface is non-nil and nil-safe, so
	// every Check answers "not listed" and every address reads as clean.
	if b, ok := bl.(*iptools.BlockList); ok && b == nil {
		return nil, ErrNoBlocklist
	}
	addr, _ := resolverAddr(DefaultResolver)
	return s.repRun(ctx, domain, addr, bl), nil
}

// repRun is the body, split from the exported method for the reason lookup is
// split from LookupSet: the resolver address becomes a parameter, which is the
// seam a white-box test uses to drive the whole feature over a loopback zone
// instead of the internet. Input is already validated; the address is already
// from the allowlist. It never returns an error — past validation, everything
// that can go wrong is a finding on the card, not a failed request.
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
	// On every return path: the time spent is a fact about the request, not
	// about whether it found anything.
	defer func() { out.QueryMS = time.Since(start).Milliseconds() }()

	mx, err := s.lookup(ctx, dnsFqdn(domain), "MX", addr)
	switch {
	case errors.Is(err, errNXDomain):
		// Split from NODATA deliberately. "This domain publishes no MX
		// records" asserts that the domain exists, which for an NXDOMAIN is a
		// claim the answer flatly contradicts — the same three-way confusion
		// dns.go calls the most common bug in this category.
		out.note("info", "This name does not exist, so there is no mail server to check.")
		return out
	case errors.Is(err, errNoData):
		out.note("info", "This domain publishes no MX records, so it has no mail servers to check.")
		return out
	case err != nil:
		// Not "clean". The distinction email.go's judge() insists on: a failed
		// query is never evidence of absence.
		out.note("warn", "The MX lookup failed, so this check did not run. That is not evidence the mail servers are clean; re-run it.")
		return out
	}

	out.MXCount = len(mx.Records)
	hosts, nullMX := repMailHosts(mx.Records)
	switch {
	case nullMX && len(hosts) == 0:
		// The declaration: every record says "no mail here".
		out.NullMX = true
	case nullMX:
		// The contradiction: a null MX next to a real mail server.
		out.NullMXConflict = true
	}
	if len(hosts) > repMaxHosts {
		hosts = hosts[:repMaxHosts]
		out.HostsTruncated = true
	}

	// Freshness before the first read, and only when there is something to
	// read: on an empty or long-unsynced corpus every Check below answers
	// "not listed" with a nil error, and the clean sentence this card would
	// otherwise print is the worst thing it can say.
	if len(hosts) > 0 {
		out.readCorpusAge(ctx, bl)
	}

	for _, h := range hosts {
		// The caller going away ends the walk. Checked below is what every
		// sentence on the card counts, so an abandoned request reports the
		// rows it really got rather than a verdict over a truncated set.
		if ctx.Err() != nil {
			out.note("warn", "The check was cut short before every mail server was read, so the rows below are partial.")
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

// readCorpusAge asks each feed when it last wrote, and records the feeds that
// cannot back a clean verdict. One FindOne per feed, all of them under one
// repCorpusTimeout, and the result is only ever used to weaken a claim.
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
		// A zero time is "this feed has never written a record", which for a
		// corpus fed by a daily sync means either a deploy that has not synced
		// yet or a sync that has been failing for longer than the 60-day TTL
		// takes to prune it. Both are the same thing to a reader: no evidence.
		if last.IsZero() || time.Since(last) > repCorpusMaxAge {
			m.StaleFeeds = append(m.StaleFeeds, feed)
		}
	}
}

// CorpusUsable reports whether a miss against this corpus is worth anything.
// False when every feed is stale, empty or unreadable — the state in which
// Check answers "not listed" to everything for reasons that have nothing to do
// with the addresses. Exported because the template has to colour the headline
// number on the same rule the notes are written on.
func (m *MXReputation) CorpusUsable() bool {
	return len(m.Feeds) > 0 && len(m.StaleFeeds) < len(m.Feeds)
}

// repHost: one MX record reduced to what this check needs.
type repHost struct {
	host string
	pref int
}

// repMailHosts turns the MX RRset into probe targets in preference order, and
// reports whether any record is the RFC 7505 null MX.
//
// Sorted before anything is capped, for the reason email.go's checkMailHosts
// gives: taking them in RRset order makes the subset we look at rotate with
// every query, and with it the verdict.
//
// KNOWN DUPLICATION: email.go's checkMailHosts opens with the same three
// steps, and the two must not disagree about which hosts "the mail servers"
// means. The fix is one helper in email.go — it owns mxPref/mxHost — returning
// the ordered, filtered list plus the null-MX flag, each caller capping it
// itself.
func repMailHosts(recs []Record) (hosts []repHost, nullMX bool) {
	byPref := slices.Clone(recs)
	slices.SortStableFunc(byPref, func(a, b Record) int { return mxPref(a.Value) - mxPref(b.Value) })

	hosts = make([]repHost, 0, len(byPref))
	for _, rec := range byPref {
		// mxHost returns "." for the null MX and "" for no target at all.
		// Neither is a machine that can have a reputation.
		switch h := mxHost(rec.Value); h {
		case "":
		case ".":
			nullMX = true
		default:
			hosts = append(hosts, repHost{host: h, pref: mxPref(rec.Value)})
		}
	}
	return hosts, nullMX
}

// repResolveOutcome: why a mail server contributed no address. Four answers,
// not one, because "publishes no A or AAAA record" is a claim about the zone,
// while a SERVFAIL, a timeout or a refusal is the tool failing to find out.
// The package splits NXDOMAIN from NODATA from failure everywhere else
// (dns.go, email.go, repRun's own MX branch) for exactly this reason.
type repResolveOutcome int

const (
	repResolved repResolveOutcome = iota
	repHostNXDomain
	repHostNoAddress
	repHostUnroutable
	repHostLookupFailed
)

// reason is the clause both the card row and the note use, written so that
// "<host> " + reason reads as a sentence.
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

// repCheckHost resolves one mail server and reads its addresses against the
// corpus. Every counter it moves lives on out, so the caps stay global rather
// than per host.
func (s *Service) repCheckHost(ctx context.Context, h repHost, addr string, bl BlockChecker, out *MXReputation) MXRepHost {
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
		// An address an earlier mail server already published is shown on this
		// row too — what a host resolves to belongs in its row — but it is the
		// same machine, so it costs neither a corpus read nor a second place
		// in the denominator of the clean sentence.
		if prev, ok := out.seen[ip]; ok {
			prev.Duplicate = true
			row.Addrs = append(row.Addrs, prev)
			continue
		}
		if out.attempted >= repMaxChecks {
			// The budget ran out inside this host. Recorded here because the
			// outer loop can only notice when another host remains, and the
			// last host's dropped addresses would otherwise leave no trace.
			out.AddrsTruncated = true
			break
		}
		a := repCheckIP(ctx, ip, bl)
		out.attempted++
		switch {
		case a.Error != "":
			out.Unread++
		case a.Listed:
			out.Checked++
			out.Listed++
		default:
			out.Checked++
		}
		out.seen[ip] = a
		row.Addrs = append(row.Addrs, a)
	}
	return row
}

// repAddresses resolves one mail server to the addresses worth checking: A
// first, then AAAA, capped at repMaxAddrsPerHost. The second return value says
// why an empty result is empty.
//
// Both families, unlike email.go's FCrDNS probe which stops at the first
// address: a provider that keeps a listed relay on its second A record is
// exactly the case this card exists to surface. Non-routable answers are
// dropped — a private address is never in a public corpus, so checking it
// could only ever produce a reassuring "clean" about a machine nobody outside
// the network can reach.
func (s *Service) repAddresses(ctx context.Context, host, addr string) ([]string, repResolveOutcome) {
	var ips []string
	seen := map[string]bool{}
	var (
		asked    int  // lookups actually sent
		nx       int  // …that came back NXDOMAIN
		failed   bool // …that failed for any other reason
		sawAddrs bool // at least one A/AAAA record existed, routable or not
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
			if seen[rec.Value] || !routable(rec.Value) {
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
		// A failure anywhere means we do not know what this host publishes,
		// and the card must not report that as publishing nothing.
		return nil, repHostLookupFailed
	case asked > 0 && nx == asked:
		return nil, repHostNXDomain
	case sawAddrs:
		return nil, repHostUnroutable
	default:
		return nil, repHostNoAddress
	}
}

// repCheckIP reads one address against the corpus under its own timeout.
//
// A read that fails is reported as a failure on the row, never folded into
// "clean": BlockList.Check is nil-safe and returns a zero lookup for a
// disabled store, so an unexamined address and an absent one are
// indistinguishable at the call site. The only defence is to keep the two
// apart here.
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

// note appends a finding. Same severity vocabulary as email.go's judge(), so
// the shared dns/notes template renders both.
func (m *MXReputation) note(level, text string) {
	m.Notes = append(m.Notes, Note{Level: level, Text: text})
}

// repListing: one listed address and every mail server that publishes it. Two
// MX names on one listed IP is one finding with two names on it, not the same
// sentence printed twice.
type repListing struct {
	addr  MXRepAddr
	hosts []string
}

// listedAddrs groups the listed addresses across rows, in the order a reader
// meets them.
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
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// repAddrPhrase: "one mail-server address" / "3 mail-server addresses".
func repAddrPhrase(n int) string {
	if n == 1 {
		return "one mail-server address"
	}
	return fmt.Sprintf("%d mail-server addresses", n)
}

// repRoughAge is a duration a reader can act on, not a precise one.
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

// corpusAgeText says, in one clause, why the corpus is not evidence.
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

// repJudge turns the rows into findings. Pure: no queries, no corpus reads —
// freshness included, which repRun reads before the first check so that this
// stays a function of the data in front of it.
//
// The hard rule it enforces is that a clean result reads as clean AND that
// nothing else does. "No listings found" stated as a positive finding, with
// the number of addresses behind it, is the sentence a reader can act on; an
// empty card is one they have to guess about; and that same sentence printed
// over an empty corpus is the one outright lie this card can tell.
func (m *MXReputation) repJudge() {
	// No MX at all never reaches here: lookup returns errNoData when the
	// type-filtered answer is empty, and repRun says so and returns.
	if m.NullMX {
		m.note("info", "This domain publishes a null MX (RFC 7505): it declares that it receives no mail, so there is no mail server to check.")
		return
	}

	if m.NullMXConflict {
		m.note("warn", "This domain publishes a null MX (\".\") alongside real mail servers. RFC 7505 §3 requires the null MX to be the only record, so senders may read this zone as refusing mail altogether. The real hosts are checked below regardless.")
	}

	// Listed addresses first, named, with the feed that lists them.
	for _, g := range m.listedAddrs() {
		verb, subject := "is", "this server"
		if len(g.hosts) > 1 {
			verb, subject = "are", "these servers"
		}
		text := fmt.Sprintf("%s (%s) %s listed by %s.", repNames(g.hosts), g.addr.IP, verb, g.addr.Sources)
		if g.addr.Count > 0 {
			text = strings.TrimSuffix(text, ".") + fmt.Sprintf(", with a confidence count of %d.", g.addr.Count)
		}
		m.note("fail", text+" Mail from "+subject+" is likely to be rejected or filtered. Find out why it was listed, fix it, then request delisting from that feed.")
	}
	if m.Listed > 0 && !m.CorpusUsable() {
		m.note("info", "The listing above comes from a corpus that is not being kept up to date ("+m.corpusAgeText()+"), so it may already have been removed upstream.")
	}

	// Rows we could not read are their own finding, because they are the
	// reason the clean verdict below has to be qualified.
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

	feeds := strings.Join(m.Feeds, " and ")
	switch {
	case m.Listed > 0:
		// Already said, per address, above.
	case m.Checked == 0:
		m.note("warn", "No mail-server address could be checked, so this card says nothing about reputation either way.")
	case !m.CorpusUsable():
		// The failure mode this whole feature is built around: an empty or
		// abandoned corpus answers "not listed" to everything, and the clean
		// sentence below would be a claim about addresses nobody looked at.
		m.note("warn", fmt.Sprintf(
			"Nothing was found for the %s read here, but the %s corpus cannot support that: %s. Read this as 'not checked' rather than clean.",
			repAddrPhrase(m.Checked), feeds, m.corpusAgeText()))
	default:
		// The sentence names the corpus it read, every time. "Clean" on its
		// own would be a claim about every blocklist in the world, which is
		// several orders of magnitude wider than what was actually checked.
		text := fmt.Sprintf("Clean: the one mail-server address checked is absent from the %s corpus.", feeds)
		if m.Checked > 1 {
			text = fmt.Sprintf("Clean: all %d mail-server addresses checked are absent from the %s corpus.", m.Checked, feeds)
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
		// "Looked at", not "checked": a row whose host did not resolve is in
		// this count and contributed nothing to the corpus reads. Every number
		// on this card has to name what it counts.
		m.note("info", fmt.Sprintf("This domain publishes %d MX records; only the %d most-preferred were looked at, so the result covers those and not the rest.", m.MXCount, len(m.Hosts)))
	}
	if m.AddrsTruncated {
		m.note("info", fmt.Sprintf("The budget of %d corpus reads per request ran out before every resolved address was read, so some addresses of the mail servers above were not checked.", repMaxChecks))
	}
}
