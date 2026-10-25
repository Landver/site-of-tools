package mailtools

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
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
	Name        string
	Host        string
	IsDomain    bool
	DelistURL   string
	Description string
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
	{"Spamhaus ZEN", "zen.spamhaus.org", false, "https://check.spamhaus.org/", "SBL direct spam, XBL botnets, PBL dynamic IPs"},
	{"Barracuda BRBL", "b.barracudacentral.org", false, "https://www.barracudacentral.org/rbl/removal-request", "Honeypot and appliance telemetry network"},
	{"SpamCop SCBL", "bl.spamcop.net", false, "https://www.spamcop.net/bl.shtml", "Real-time user reported spam traps"},
	{"Mailspike Rep", "rep.mailspike.net", false, "https://mailspike.org/an-ip-is-listed.html", "Sender reputation rating (L1-L5 bad, H1-H5 good)"},
	{"Mailspike BL", "bl.mailspike.net", false, "https://mailspike.org/an-ip-is-listed.html", "Spam bot and zombie list"},
	{"Backscatterer", "ips.backscatterer.org", false, "http://www.backscatterer.org/?target=test", "Abusive NDR backscatter bounces"},
	{"Truncate GBUdb", "truncate.gbudb.net", false, "http://www.gbudb.com/truncate/", "Automated spam emission probability engine"},
	{"PSBL", "psbl.surriel.com", false, "https://psbl.org/", "Passive Spam Block List honeypots"},
	{"DroneBL", "dnsbl.dronebl.org", false, "https://dronebl.org/lookup", "Compromised botnets and open proxies"},
	{"Blocklist.de", "bl.blocklist.de", false, "https://www.blocklist.de/en/search.html", "Fail2ban abusive attack network"},
	{"s5h.net", "all.s5h.net", false, "http://www.s5h.net/rbl", "Spam emission and infected host reputation"},
	{"SPFBL DNSBL", "dnsbl.spfbl.net", false, "https://matrix.spfbl.net/", "Peer-to-peer anti-spam sender reputation"},
	{"NordSpam IP", "bl.nordspam.com", false, "https://nordspam.com/", "Automated spam emitter tracker"},
	{"UCEPROTECT L1", "dnsbl-1.uceprotect.net", false, "http://www.uceprotect.net/en/rblcheck.php", "Directly detected spam emission sources"},
	{"UCEPROTECT L2", "dnsbl-2.uceprotect.net", false, "http://www.uceprotect.net/en/rblcheck.php", "Escalation list for networks with spam outbreaks"},
}

var domainDNSBLs = []DNSBLZone{
	{"Spamhaus DBL", "dbl.spamhaus.org", true, "https://check.spamhaus.org/", "Domains associated with spam, malware and phishing"},
	{"SURBL Multi", "multi.surbl.org", true, "http://www.surbl.org/surbl-analysis", "Domains in unsolicited email bodies and malware sites"},
	{"URIBL Multi", "multi.uribl.com", true, "https://admin.uribl.com/", "Real-time black/grey/red domain reputation"},
	{"URIBL Black", "black.uribl.com", true, "https://admin.uribl.com/", "Zero-false-positive strict domain spam blacklist"},
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

type auditTask struct {
	target string
	ip     net.IP
	zone   DNSBLZone
	suffix string
	desc   string
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

	var tasks []auditTask
	if isIP {
		for _, z := range ipDNSBLs {
			tasks = append(tasks, auditTask{target: target, ip: parsedIP, zone: z})
		}
	} else {
		target = ExtractDomain(target)
		if target == "" || strings.ContainsAny(target, " \t\r\n\x00;\"'\\") || len(target) > 253 {
			return nil, errors.New("invalid domain name format for DNSBL lookup")
		}
		for _, z := range domainDNSBLs {
			tasks = append(tasks, auditTask{target: target, zone: z, suffix: " (Domain)"})
		}
		if mxHost, mxIP := resolveMXIP(ctx, target); mxIP != nil {
			for _, z := range ipDNSBLs {
				tasks = append(tasks, auditTask{
					target: mxHost,
					ip:     mxIP,
					zone:   z,
					suffix: " (MX IP)",
					desc:   fmt.Sprintf("Mail server %s [%s] — %s", mxHost, mxIP.String(), z.Description),
				})
			}
		}
	}

	report := &DNSBLReport{
		Target:       target,
		IsIP:         isIP,
		TotalChecked: len(tasks),
		Results:      make([]DNSBLResult, len(tasks)),
	}

	c := &dns.Client{
		Net:     "udp",
		Timeout: 1200 * time.Millisecond,
	}

	var wg sync.WaitGroup
	wg.Add(len(tasks))
	for i, t := range tasks {
		go func(idx int, task auditTask) {
			defer wg.Done()
			res := queryOneDNSBL(ctx, c, task.target, task.ip, task.zone, dqsKey)
			if task.suffix != "" {
				res.Name += task.suffix
			}
			if task.desc != "" {
				res.Description = task.desc
			}
			report.Results[idx] = res
		}(i, t)
	}
	wg.Wait()

	for _, r := range report.Results {
		if r.Listed {
			report.ListedCount++
		} else if r.IsWarning {
			report.WarningCount++
		}
	}

	report.DurationMS = time.Since(start).Milliseconds()
	return report, nil
}

func resolveMXIP(ctx context.Context, domain string) (string, net.IP) {
	mxs, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err != nil || len(mxs) == 0 {
		return "", nil
	}
	slices.SortFunc(mxs, func(a, b *net.MX) int {
		return cmp.Or(cmp.Compare(a.Pref, b.Pref), strings.Compare(a.Host, b.Host))
	})
	host := strings.TrimSuffix(mxs[0].Host, ".")
	if addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host); err == nil {
		for _, a := range addrs {
			if v4 := a.IP.To4(); v4 != nil {
				return host, v4
			}
		}
	}
	return host, nil
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

var spamCodes = map[string]string{
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

func parseReturnCode(res *DNSBLResult, code string) {
	if code == "127.255.255.254" {
		res.IsWarning = true
		res.Category = "Spamhaus Open Resolver Notice: Query blocked via public DNS (requires Spamhaus DQS key)"
		return
	}
	if code == "127.255.255.255" {
		res.IsWarning = true
		res.Category = "Spamhaus Query Limit Exceeded: Query volume limit exceeded"
		return
	}

	if strings.Contains(res.Zone, "uribl.com") {
		if code == "127.0.0.1" {
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
		res.Category = "Clean / Not Listed"
		return
	}

	if strings.Contains(res.Zone, "surbl.org") {
		if code == "127.0.0.1" {
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
		res.Category = "Clean / Not Listed"
		return
	}

	if strings.Contains(res.Zone, "dronebl.org") && (code == "127.0.0.1" || code == "127.0.0.2") {
		res.Listed = true
		res.Category = "Listed in DroneBL: Compromised botnet or open proxy"
		return
	}

	if strings.HasPrefix(code, "127.") {
		if code == "127.0.0.1" {
			res.IsWarning = true
			res.Category = "Notice: Query refused or test loopback"
			return
		}
		if code == "127.0.0.10" || code == "127.0.0.11" {
			res.IsWarning = true
			res.Category = "Spamhaus PBL Notice: Inbound or non-outbound IP policy range"
			return
		}
		res.Listed = true
		if desc, ok := spamCodes[code]; ok {
			res.Category = desc
		} else {
			res.Category = fmt.Sprintf("Listed in blacklist (code %s)", code)
		}
	} else if code != "" {
		res.Category = "Clean / Not Listed"
	}
}
