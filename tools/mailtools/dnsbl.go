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

// DNSBLZone defines an individual real-time blacklist or reputation zone.
type DNSBLZone struct {
	Name        string // Human-readable name
	Host        string // DNS zone root
	IsDomain    bool   // True if for domains, false if for IPs
	DelistURL   string // URL to removal/lookup page
	Description string // What this list identifies
}

// DNSBLResult is the individual audit outcome for one DNSBL list.
type DNSBLResult struct {
	Name        string `bson:"name" json:"name"`
	Zone        string `bson:"zone" json:"zone"`
	Listed      bool   `bson:"listed" json:"listed"`
	ReturnCode  string `bson:"return_code,omitempty" json:"return_code,omitempty"`
	Category    string `bson:"category" json:"category"`
	IsWarning   bool   `bson:"is_warning,omitempty" json:"is_warning,omitempty"`
	DelistURL   string `bson:"delist_url,omitempty" json:"delist_url,omitempty"`
	Description string `bson:"description,omitempty" json:"description,omitempty"`
	LatencyMS   int64  `bson:"latency_ms" json:"latency_ms"`
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

var ipDNSBLs = []DNSBLZone{
	{
		Name:        "Spamhaus ZEN",
		Host:        "zen.spamhaus.org",
		DelistURL:   "https://check.spamhaus.org/",
		Description: "Gold standard IP reputation (SBL direct spam, XBL botnet exploits, PBL dynamic IPs)",
	},
	{
		Name:        "Barracuda Reputation (BRBL)",
		Host:        "b.barracudacentral.org",
		DelistURL:   "https://www.barracudacentral.org/rbl/removal-request",
		Description: "Global enterprise honeypot and appliance telemetry network",
	},
	{
		Name:        "SpamCop (SCBL)",
		Host:        "bl.spamcop.net",
		DelistURL:   "https://www.spamcop.net/bl.shtml",
		Description: "Real-time user reported spam trap network",
	},
	{
		Name:        "Mailspike IP Reputation",
		Host:        "rep.mailspike.net",
		DelistURL:   "https://mailspike.org/an-ip-is-listed.html",
		Description: "Granular sliding-scale sender reputation (L1-L5 bad, H1-H5 good)",
	},
	{
		Name:        "Mailspike Blacklist (BL)",
		Host:        "bl.mailspike.net",
		DelistURL:   "https://mailspike.org/an-ip-is-listed.html",
		Description: "High-confidence persistent spam bot and zombie list",
	},
	{
		Name:        "Backscatterer",
		Host:        "ips.backscatterer.org",
		DelistURL:   "http://www.backscatterer.org/?target=test",
		Description: "Misconfigured mail servers sending abusive NDR backscatter bounces",
	},
	{
		Name:        "Truncate (GBUdb)",
		Host:        "truncate.gbudb.net",
		DelistURL:   "http://www.gbudb.com/truncate/",
		Description: "Real-time automated spam emission probability engine",
	},
	{
		Name:        "Passive Spam Block List (PSBL)",
		Host:        "psbl.surriel.com",
		DelistURL:   "https://psbl.org/",
		Description: "Easy-on, easy-off honeypot-based automated spam list",
	},
	{
		Name:        "DroneBL",
		Host:        "dnsbl.dronebl.org",
		DelistURL:   "https://dronebl.org/lookup",
		Description: "Compromised botnet nodes, open proxies, and worm infections",
	},
}

var domainDNSBLs = []DNSBLZone{
	{
		Name:        "Spamhaus DBL",
		Host:        "dbl.spamhaus.org",
		IsDomain:    true,
		DelistURL:   "https://check.spamhaus.org/",
		Description: "Real-time database of domains associated with spam, malware and phishing",
	},
	{
		Name:        "SURBL Multi",
		Host:        "multi.surbl.org",
		IsDomain:    true,
		DelistURL:   "http://www.surbl.org/surbl-analysis",
		Description: "Domains spotted in unsolicited email bodies, malware sites and phishing",
	},
	{
		Name:        "URIBL Multi",
		Host:        "multi.uribl.com",
		IsDomain:    true,
		DelistURL:   "https://admin.uribl.com/",
		Description: "Real-time black/grey/red domain reputation used by SpamAssassin",
	},
}

// CachedDNSBLAudit queries cache first, falling back to parallel DNSBL audits and updating MongoDB cache.
func CachedDNSBLAudit(ctx context.Context, store *Store, target, dqsKey string) (*DNSBLReport, error) {
	if store != nil {
		cached, _ := store.GetDNSBLCache(ctx, target)
		if cached != nil {
			return &DNSBLReport{
				Target:       cached.Target,
				IsIP:         net.ParseIP(target) != nil,
				TotalChecked: cached.TotalChecked,
				ListedCount:  cached.ListedCount,
				Results:      cached.Results,
			}, nil
		}
	}

	res, err := QueryDNSBLAudits(ctx, target, dqsKey)
	if err != nil || res == nil {
		return res, err
	}

	if store != nil {
		store.SaveDNSBLCache(ctx, target, res.Results, res.ListedCount, res.TotalChecked)
	}
	return res, nil
}

// QueryDNSBLAudits performs parallel DNSBL checks for an IP or domain target.
func QueryDNSBLAudits(ctx context.Context, target string, dqsKey string) (*DNSBLReport, error) {
	start := time.Now()
	target = strings.Trim(strings.TrimSpace(strings.ToLower(target)), "[]")
	if target == "" {
		return nil, errors.New("target domain or IP address is required")
	}

	parsedIP := net.ParseIP(target)
	isIP := parsedIP != nil

	var zones []DNSBLZone
	if isIP {
		zones = ipDNSBLs
	} else {
		target = ExtractDomain(target)
		if target == "" || strings.ContainsAny(target, " \t\r\n\x00;\"'\\") || len(target) > 253 {
			return nil, errors.New("invalid domain name format for DNSBL lookup")
		}
		zones = domainDNSBLs
	}

	report := &DNSBLReport{
		Target:       target,
		IsIP:         isIP,
		TotalChecked: len(zones),
		Results:      make([]DNSBLResult, len(zones)),
	}

	// We use 8.8.8.8 / 1.1.1.1 fallback or local recursor
	// Note: Spamhaus queries with DQS key override host to <key>.<zone>.dq.spamhaus.net
	c := &dns.Client{
		Net:     "udp",
		Timeout: 1200 * time.Millisecond,
	}

	var wg sync.WaitGroup
	wg.Add(len(zones))

	for idx, z := range zones {
		go func(i int, zone DNSBLZone) {
			defer wg.Done()
			res := queryOneDNSBL(ctx, c, target, parsedIP, zone, dqsKey)
			report.Results[i] = res
		}(idx, z)
	}

	wg.Wait()

	for _, r := range report.Results {
		if r.Listed {
			report.ListedCount++
		}
		if r.IsWarning {
			report.WarningCount++
		}
	}

	report.DurationMS = time.Since(start).Milliseconds()
	return report, nil
}

var (
	uriblBits = []struct {
		mask int
		name string
	}{
		{2, "Black (Spam)"},
		{4, "Grey (Suspicious)"},
		{8, "Red (Malware)"},
	}
	surblBits = []struct {
		mask int
		name string
	}{
		{2, "SpamCop"},
		{4, "Web Spam"},
		{8, "Phishing"},
		{16, "Malware"},
		{32, "Click Tracker"},
		{64, "Abuse"},
		{128, "Cracked"},
	}
)

func lastOctet(ipStr string) int {
	if idx := strings.LastIndex(ipStr, "."); idx != -1 {
		if n, err := strconv.Atoi(ipStr[idx+1:]); err == nil {
			return n
		}
	}
	return 0
}

func queryOneDNSBL(ctx context.Context, client *dns.Client, target string, ip net.IP, zone DNSBLZone, dqsKey string) DNSBLResult {
	start := time.Now()
	res := DNSBLResult{
		Name:        zone.Name,
		Zone:        zone.Host,
		Category:    "Clean / Not Listed",
		DelistURL:   zone.DelistURL,
		Description: zone.Description,
	}

	lookupHost := zone.Host
	if strings.Contains(zone.Host, "spamhaus.org") && dqsKey != "" {
		// Use dedicated DQS zone for Spamhaus
		if zone.IsDomain {
			lookupHost = fmt.Sprintf("%s.dbl.dq.spamhaus.net", dqsKey)
		} else {
			lookupHost = fmt.Sprintf("%s.zen.dq.spamhaus.net", dqsKey)
		}
	}

	var queryName string
	if ip != nil {
		if v4 := ip.To4(); v4 != nil {
			queryName = fmt.Sprintf("%d.%d.%d.%d.%s.", v4[3], v4[2], v4[1], v4[0], lookupHost)
		} else {
			res.LatencyMS = time.Since(start).Milliseconds()
			res.Category = "IPv6 querying not supported by legacy zone"
			return res
		}
	} else {
		queryName = fmt.Sprintf("%s.%s.", target, lookupHost)
	}

	m := new(dns.Msg)
	m.SetQuestion(queryName, dns.TypeA)
	m.RecursionDesired = true

	// Query recursive resolvers (preferring system resolver, then public fallbacks)
	var in *dns.Msg
	var err error
	for _, srv := range systemResolvers {
		in, _, err = client.ExchangeContext(ctx, m, srv)
		if err == nil && in != nil {
			break
		}
	}

	res.LatencyMS = time.Since(start).Milliseconds()

	if err != nil || in == nil {
		res.Category = "DNS Timeout / Network Error"
		res.IsWarning = true
		return res
	}

	if in.Rcode == dns.RcodeServerFailure || in.Rcode == dns.RcodeRefused {
		res.Category = "DNS Server Failure / Refused"
		res.IsWarning = true
		return res
	}

	// Check answers
	for _, ans := range in.Answer {
		if a, ok := ans.(*dns.A); ok {
			code := a.A.String()
			res.ReturnCode = code
			parseReturnCode(&res, code)
			break
		}
	}

	return res
}

func parseReturnCode(res *DNSBLResult, code string) {
	// 1. Spamhaus Special Administrative Signals
	if code == "127.255.255.254" {
		res.Listed = false
		res.IsWarning = true
		res.Category = "Spamhaus Open Resolver Notice: Query blocked via public DNS (requires Spamhaus DQS key)"
		return
	}
	if code == "127.255.255.255" {
		res.Listed = false
		res.IsWarning = true
		res.Category = "Spamhaus Query Limit Exceeded: Query volume limit exceeded"
		return
	}

	// 2. URIBL Multi (multi.uribl.com)
	// Note: 127.0.0.1 is "Query Refused / Blocked" from public resolver; NEVER a listing!
	if strings.Contains(res.Zone, "uribl.com") {
		if code == "127.0.0.1" {
			res.Listed = false
			res.IsWarning = true
			res.Category = "URIBL Notice: Public resolver query refused by zone operator"
			return
		}
		if octet := lastOctet(code); octet > 0 {
			var flags []string
			for _, b := range uriblBits {
				if octet&b.mask != 0 {
					flags = append(flags, b.name)
				}
			}
			if len(flags) > 0 {
				res.Listed = true
				res.Category = "Listed in URIBL: " + strings.Join(flags, " / ")
				return
			}
		}
		res.Listed = false
		res.Category = "Clean / Not Listed"
		return
	}

	// 3. SURBL Multi (multi.surbl.org)
	// Note: 127.0.0.1 is "Query Blocked" on public resolvers; NEVER a listing!
	if strings.Contains(res.Zone, "surbl.org") {
		if code == "127.0.0.1" {
			res.Listed = false
			res.IsWarning = true
			res.Category = "SURBL Notice: Public resolver query blocked by zone operator"
			return
		}
		if octet := lastOctet(code); octet >= 2 {
			res.Listed = true
			var types []string
			for _, b := range surblBits {
				if octet&b.mask != 0 {
					types = append(types, b.name)
				}
			}
			if len(types) > 0 {
				res.Category = "Listed in SURBL: " + strings.Join(types, ", ")
			} else {
				res.Category = "Listed in SURBL Multi"
			}
			return
		}
		res.Listed = false
		res.Category = "Clean / Not Listed"
		return
	}

	// 4. General / IP DNSBL return codes
	if strings.HasPrefix(code, "127.") {
		// Generic 127.0.0.1 on a DNSBL is administrative refusal or test loopback, not a listing
		if code == "127.0.0.1" {
			res.Listed = false
			res.IsWarning = true
			res.Category = "Notice: Query refused or test loopback"
			return
		}
		res.Listed = true
		switch code {
		case "127.0.0.2":
			res.Category = "Listed: Direct UBE spam source / SBL"
		case "127.0.0.3":
			res.Category = "Listed: Snowshoe spam emitter / CSS"
		case "127.0.0.4", "127.0.0.5", "127.0.0.6", "127.0.0.7":
			res.Category = "Listed: Botnet / Malware exploit infection / XBL"
		case "127.0.0.10", "127.0.0.11":
			res.Category = "Listed: End-user dynamic IP range / PBL"
		case "127.0.1.2":
			res.Category = "Listed: Spam domain (Spamhaus DBL)"
		case "127.0.1.4":
			res.Category = "Listed: Phishing domain (Spamhaus DBL)"
		case "127.0.1.5":
			res.Category = "Listed: Malware distribution domain (Spamhaus DBL)"
		case "127.0.1.6":
			res.Category = "Listed: Botnet C2 domain (Spamhaus DBL)"
		case "127.0.1.102", "127.0.1.103", "127.0.1.104":
			res.Category = "Listed: Abused legit web host / redirector"
		default:
			res.Category = fmt.Sprintf("Listed in blacklist (code %s)", code)
		}
	} else if code != "" {
		res.Category = "Clean / Not Listed"
	}
}
