package mailtools

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var systemResolvers = func() []string {
	if cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cfg.Servers) > 0 {
		var servers []string
		for _, s := range cfg.Servers {
			servers = append(servers, net.JoinHostPort(s, cfg.Port))
		}
		if len(servers) > 0 {
			return servers
		}
	}
	return []string{"1.1.1.1:53", "8.8.8.8:53"}
}()

// DNSBLResult is the individual audit outcome for one DNSBL list.
type DNSBLResult struct {
	Name        string `json:"name"`
	Zone        string `json:"zone"`
	Listed      bool   `json:"listed"`
	ReturnCode  string `json:"return_code,omitempty"`
	Category    string `json:"category"`
	IsWarning   bool   `json:"is_warning,omitempty"`
	DelistURL   string `json:"delist_url,omitempty"`
	Description string `json:"description,omitempty"`
	LatencyMS   int64  `json:"latency_ms"`
}

// DNSBLReport summarizes the overall multi-blacklist check.
type DNSBLReport struct {
	Target       string        `json:"target"`
	IsIP         bool          `json:"is_ip"`
	TotalChecked int           `json:"total_checked"`
	ListedCount  int           `json:"listed_count"`
	WarningCount int           `json:"warning_count"`
	Results      []DNSBLResult `json:"results"`
	DurationMS   int64         `json:"duration_ms"`
}

const notListed = "Clean / Not Listed"

func (r *DNSBLResult) list(category string)   { r.Listed, r.Category = true, category }
func (r *DNSBLResult) notice(category string) { r.IsWarning, r.Category = true, category }

// A dnsblDecoder reads one zone's answer code into r, which starts out clean.
type dnsblDecoder func(r *DNSBLResult, code string)

// dnsblZone is one blacklist: where to ask, and how to read what it answers.
type dnsblZone struct {
	name, host string
	dqs        string // the Spamhaus DQS zone, asked instead of host when a key is set
	delist     string
	desc       string
	decode     dnsblDecoder
}

var ipZones = []dnsblZone{
	{"Spamhaus ZEN", "zen.spamhaus.org", "zen", "https://check.spamhaus.org/", "SBL direct spam, XBL botnets, PBL dynamic IPs", spamhaus},
	{"Barracuda BRBL", "b.barracudacentral.org", "", "https://www.barracudacentral.org/rbl/removal-request", "Honeypot and appliance telemetry network", generic},
	{"SpamCop SCBL", "bl.spamcop.net", "", "https://www.spamcop.net/bl.shtml", "Real-time user reported spam traps", generic},
	{"Mailspike Rep", "rep.mailspike.net", "", "https://mailspike.org/an-ip-is-listed.html", "Sender reputation rating (L1-L5 bad, H1-H5 good)", mailspikeRep},
	{"Mailspike BL", "bl.mailspike.net", "", "https://mailspike.org/an-ip-is-listed.html", "Spam bot and zombie list", generic},
	{"Backscatterer", "ips.backscatterer.org", "", "http://www.backscatterer.org/?target=test", "Abusive NDR backscatter bounces", generic},
	{"Truncate GBUdb", "truncate.gbudb.net", "", "http://www.gbudb.com/truncate/", "Automated spam emission probability engine", generic},
	{"PSBL", "psbl.surriel.com", "", "https://psbl.org/", "Passive Spam Block List honeypots", generic},
	{"DroneBL", "dnsbl.dronebl.org", "", "https://dronebl.org/lookup", "Compromised botnets and open proxies", dronebl},
	{"Blocklist.de", "bl.blocklist.de", "", "https://www.blocklist.de/en/search.html", "Fail2ban abusive attack network", generic},
	{"s5h.net", "all.s5h.net", "", "http://www.s5h.net/rbl", "Spam emission and infected host reputation", generic},
	{"SPFBL DNSBL", "dnsbl.spfbl.net", "", "https://matrix.spfbl.net/", "Peer-to-peer anti-spam sender reputation", generic},
	{"NordSpam IP", "bl.nordspam.com", "", "https://nordspam.com/", "Automated spam emitter tracker", generic},
	{"UCEPROTECT L1", "dnsbl-1.uceprotect.net", "", "http://www.uceprotect.net/en/rblcheck.php", "Directly detected spam emission sources", generic},
	{"UCEPROTECT L2", "dnsbl-2.uceprotect.net", "", "http://www.uceprotect.net/en/rblcheck.php", "Escalation list for networks with spam outbreaks", generic},
}

var domainZones = []dnsblZone{
	{"Spamhaus DBL", "dbl.spamhaus.org", "dbl", "https://check.spamhaus.org/", "Domains associated with spam, malware and phishing", spamhaus},
	{"SURBL Multi", "multi.surbl.org", "", "http://www.surbl.org/surbl-analysis", "Domains in unsolicited email bodies and malware sites", surbl},
	{"URIBL Multi", "multi.uribl.com", "", "https://admin.uribl.com/", "Real-time black/grey/red domain reputation", uribl},
	{"URIBL Black", "black.uribl.com", "", "https://admin.uribl.com/", "Zero-false-positive strict domain spam blacklist", uribl},
}

var (
	spamhausListings = map[string]string{
		"127.0.0.2":   "Listed: Direct UBE spam source / SBL",
		"127.0.0.3":   "Listed: Snowshoe spam emitter / CSS",
		"127.0.0.4":   "Listed: Botnet / Malware exploit infection / XBL",
		"127.0.0.5":   "Listed: Botnet / Malware exploit infection / XBL",
		"127.0.0.6":   "Listed: Botnet / Malware exploit infection / XBL",
		"127.0.0.7":   "Listed: Botnet / Malware exploit infection / XBL",
		"127.0.1.2":   "Listed: Spam domain (Spamhaus DBL)",
		"127.0.1.4":   "Listed: Phishing domain (Spamhaus DBL)",
		"127.0.1.5":   "Listed: Malware distribution domain (Spamhaus DBL)",
		"127.0.1.6":   "Listed: Botnet C2 domain (Spamhaus DBL)",
		"127.0.1.102": "Listed: Abused legit web host / redirector",
		"127.0.1.103": "Listed: Abused legit web host / redirector",
		"127.0.1.104": "Listed: Abused legit web host / redirector",
	}
	spamhausNotices = map[string]string{
		"127.0.0.10":      "Spamhaus PBL Notice: Inbound or non-outbound IP policy range",
		"127.0.0.11":      "Spamhaus PBL Notice: Inbound or non-outbound IP policy range",
		"127.255.255.254": "Spamhaus Open Resolver Notice: Query blocked via public DNS (requires Spamhaus DQS key)",
		"127.255.255.255": "Spamhaus Query Limit Exceeded: Query volume limit exceeded",
	}
)

func spamhaus(r *DNSBLResult, code string) {
	if msg, ok := spamhausNotices[code]; ok {
		r.notice(msg)
	} else if msg, ok := spamhausListings[code]; ok {
		r.list(msg)
	} else {
		generic(r, code)
	}
}

// generic reads the common convention: any 127.0.0.0/8 answer but the 127.0.0.1 test address is a listing.
func generic(r *DNSBLResult, code string) {
	switch {
	case code == "127.0.0.1":
		r.notice("Notice: Query refused or test loopback")
	case strings.HasPrefix(code, "127."):
		r.list("Listed in blacklist (code " + code + ")")
	}
}

// dronebl: each code names a kind of compromise, and every one is a listing.
func dronebl(r *DNSBLResult, code string) {
	if strings.HasPrefix(code, "127.") {
		r.list("Listed in DroneBL: Compromised botnet or open proxy")
	}
}

// mailspikeRep reads a reputation scale: .10-.14 bad (L5-L1), .15-.16 neutral, .17-.20 good (H1-H5).
func mailspikeRep(r *DNSBLResult, code string) {
	if !strings.HasPrefix(code, "127.0.0.") {
		return
	}
	switch n := lastOctet(code); {
	case n >= 10 && n <= 14:
		r.list("Listed in Mailspike: Bad sender reputation (L1-L5)")
	case n == 15 || n == 16:
		r.notice("Mailspike Notice: Neutral / suspicious sender reputation")
	case n >= 17 && n <= 20:
		r.Category = "Clean: High sender reputation (H1-H5 in Mailspike)"
	}
}

type dnsblFlag struct {
	bit  int
	name string
}

// bitmask reads lists that OR their sub-lists into the last octet; 127.0.0.1 means the query was refused.
func bitmask(list string, flags []dnsblFlag) dnsblDecoder {
	return func(r *DNSBLResult, code string) {
		if code == "127.0.0.1" {
			r.notice(list + " Notice: Public resolver query refused by zone operator")
			return
		}
		var names []string
		for _, f := range flags {
			if lastOctet(code)&f.bit != 0 {
				names = append(names, f.name)
			}
		}
		if len(names) > 0 {
			r.list("Listed in " + list + ": " + strings.Join(names, " / "))
		}
	}
}

var (
	uribl = bitmask("URIBL", []dnsblFlag{{2, "Black (Spam)"}, {4, "Grey (Suspicious)"}, {8, "Red (Malware)"}})
	surbl = bitmask("SURBL", []dnsblFlag{{2, "SpamCop"}, {4, "Web Spam"}, {8, "Phishing"}, {16, "Malware"},
		{32, "Click Tracker"}, {64, "Abuse"}, {128, "Cracked"}})
)

func lastOctet(code string) int {
	n, _ := strconv.Atoi(code[strings.LastIndex(code, ".")+1:])
	return n
}

// DNSBL checks an IP, or a domain and its primary MX's address, against every list.
func (s *Service) DNSBL(ctx context.Context, target string) (*DNSBLReport, error) {
	return s.dnsbl(ctx, target, func(domain string) []MXRecord {
		mx, _ := lookupMX(ctx, domain)
		return mx
	})
}

// dnsbl asks for a domain's MX only on a cache miss; a health audit passes the records it already has.
func (s *Service) dnsbl(ctx context.Context, target string, mx func(domain string) []MXRecord) (*DNSBLReport, error) {
	target, ip, err := dnsblTarget(target)
	if err != nil {
		return nil, err
	}
	return s.store.cachedDNSBL(ctx, target, func() *DNSBLReport {
		if ip != nil {
			return queryDNSBL(ctx, target, true, s.dnsblLookups(ipZones, reversed(ip), "", ""))
		}
		lookups := s.dnsblLookups(domainZones, target, " (Domain)", "")
		if host, addr := primaryMXAddr(ctx, mx(target)); addr != nil {
			about := fmt.Sprintf("Mail server %s [%s] — ", host, addr)
			lookups = append(lookups, s.dnsblLookups(ipZones, reversed(addr), " (MX IP)", about)...)
		}
		return queryDNSBL(ctx, target, false, lookups)
	}), nil
}

// dnsblTarget normalizes the cache key: an IPv4 address in canonical form, or the domain of an address or URL.
func dnsblTarget(raw string) (string, net.IP, error) {
	t := strings.Trim(strings.TrimSpace(strings.ToLower(raw)), "[]")
	if t == "" {
		return "", nil, errors.New("target domain or IP address is required")
	}
	if ip := net.ParseIP(t); ip != nil {
		if ip.To4() == nil {
			return "", nil, errors.New("IPv6 addresses can't be checked: these blacklists list IPv4 addresses only")
		}
		return ip.String(), ip, nil
	}
	d := ExtractDomain(t)
	if d == "" || strings.ContainsAny(d, " \t\r\n\x00;\"'\\") || len(d) > 253 {
		return "", nil, errors.New("invalid domain name format for DNSBL lookup")
	}
	return d, nil, nil
}

// reversed is an IPv4 address in DNSBL query order: 192.0.2.1 is asked as 1.2.0.192.
func reversed(ip net.IP) string {
	v4 := ip.To4()
	return fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0])
}

// primaryMXAddr returns the most preferred MX host and its first IPv4 address, the one the IP lists can judge.
func primaryMXAddr(ctx context.Context, mx []MXRecord) (string, net.IP) {
	if len(mx) == 0 {
		return "", nil
	}
	host := mx[0].Host
	addrs, _ := net.DefaultResolver.LookupIPAddr(ctx, host)
	for _, a := range addrs {
		if v4 := a.IP.To4(); v4 != nil {
			return host, v4
		}
	}
	return host, nil
}

// dnsblLookup is one question to one zone, its result filled in but for the answer.
type dnsblLookup struct {
	qname  string
	decode dnsblDecoder
	result DNSBLResult
}

func (s *Service) dnsblLookups(zones []dnsblZone, name, suffix, about string) []dnsblLookup {
	lookups := make([]dnsblLookup, len(zones))
	for i, z := range zones {
		host := z.host
		if z.dqs != "" && s.dqsKey != "" {
			host = s.dqsKey + "." + z.dqs + ".dq.spamhaus.net"
		}
		lookups[i] = dnsblLookup{
			qname:  name + "." + host + ".",
			decode: z.decode,
			result: DNSBLResult{Name: z.name + suffix, Zone: z.host, Category: notListed, DelistURL: z.delist, Description: about + z.desc},
		}
	}
	return lookups
}

func queryDNSBL(ctx context.Context, target string, isIP bool, lookups []dnsblLookup) *DNSBLReport {
	start := time.Now()
	rep := &DNSBLReport{Target: target, IsIP: isIP, TotalChecked: len(lookups), Results: make([]DNSBLResult, len(lookups))}
	c := &dns.Client{Net: "udp", Timeout: 1200 * time.Millisecond}
	var wg sync.WaitGroup
	for i, l := range lookups {
		wg.Go(func() { rep.Results[i] = l.ask(ctx, c) })
	}
	wg.Wait()
	for _, r := range rep.Results {
		switch {
		case r.Listed:
			rep.ListedCount++
		case r.IsWarning:
			rep.WarningCount++
		}
	}
	rep.DurationMS = time.Since(start).Milliseconds()
	return rep
}

func (l dnsblLookup) ask(ctx context.Context, c *dns.Client) DNSBLResult {
	r := l.result
	start := time.Now()
	in, err := exchange(ctx, c, l.qname)
	r.LatencyMS = time.Since(start).Milliseconds()
	switch {
	case err != nil:
		r.notice("DNS Timeout / Network Error")
	case refused(in):
		r.notice("DNS Server Failure / Refused")
	default:
		for _, ans := range in.Answer {
			if a, ok := ans.(*dns.A); ok {
				r.ReturnCode = a.A.String()
				l.decode(&r, r.ReturnCode)
				break
			}
		}
	}
	return r
}

// exchange asks each resolver in turn, moving on from one that fails or refuses.
func exchange(ctx context.Context, c *dns.Client, qname string) (in *dns.Msg, err error) {
	m := new(dns.Msg).SetQuestion(qname, dns.TypeA)
	for _, srv := range systemResolvers {
		if in, _, err = c.ExchangeContext(ctx, m, srv); err == nil && !refused(in) {
			break
		}
	}
	return in, err
}

func refused(in *dns.Msg) bool {
	return in.Rcode == dns.RcodeServerFailure || in.Rcode == dns.RcodeRefused
}
