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
			return s.query(ctx, target, true, auditTasks(ipDNSBLs, ip.String(), ip, "", ""))
		}
		tasks := auditTasks(domainDNSBLs, target, nil, " (Domain)", "")
		if host, addr := primaryMXAddr(ctx, mx(target)); addr != nil {
			tasks = append(tasks, auditTasks(ipDNSBLs, host, addr, " (MX IP)", fmt.Sprintf("Mail server %s [%s] — ", host, addr))...)
		}
		return s.query(ctx, target, false, tasks)
	}), nil
}

// dnsblTarget normalizes the cache key: an IP in canonical form, or the domain of an address or URL.
func dnsblTarget(raw string) (string, net.IP, error) {
	t := strings.Trim(strings.TrimSpace(strings.ToLower(raw)), "[]")
	if t == "" {
		return "", nil, errors.New("target domain or IP address is required")
	}
	if ip := net.ParseIP(t); ip != nil {
		return ip.String(), ip, nil
	}
	d := ExtractDomain(t)
	if d == "" || strings.ContainsAny(d, " \t\r\n\x00;\"'\\") || len(d) > 253 {
		return "", nil, errors.New("invalid domain name format for DNSBL lookup")
	}
	return d, nil, nil
}

type auditTask struct {
	target string
	ip     net.IP
	zone   DNSBLZone
	name   string
	desc   string
}

func auditTasks(zones []DNSBLZone, target string, ip net.IP, suffix, about string) []auditTask {
	tasks := make([]auditTask, len(zones))
	for i, z := range zones {
		tasks[i] = auditTask{target: target, ip: ip, zone: z, name: z.Name + suffix, desc: about + z.Description}
	}
	return tasks
}

// primaryMXAddr returns the most preferred MX host and its first IPv4 address, the one the IP lists can judge.
func primaryMXAddr(ctx context.Context, mx []MXRecord) (string, net.IP) {
	if len(mx) == 0 {
		return "", nil
	}
	host := mx[0].Host
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return host, nil
	}
	for _, a := range addrs {
		if v4 := a.IP.To4(); v4 != nil {
			return host, v4
		}
	}
	return host, nil
}

func (s *Service) query(ctx context.Context, target string, isIP bool, tasks []auditTask) *DNSBLReport {
	start := time.Now()
	report := &DNSBLReport{
		Target:       target,
		IsIP:         isIP,
		TotalChecked: len(tasks),
		Results:      make([]DNSBLResult, len(tasks)),
	}
	c := &dns.Client{Net: "udp", Timeout: 1200 * time.Millisecond}
	var wg sync.WaitGroup
	for i, t := range tasks {
		wg.Go(func() { report.Results[i] = queryOneDNSBL(ctx, c, t, s.dqsKey) })
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
	return report
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

func queryOneDNSBL(ctx context.Context, client *dns.Client, task auditTask, dqsKey string) DNSBLResult {
	start := time.Now()
	zone, target, ip := task.zone, task.target, task.ip
	res := DNSBLResult{
		Name:        task.name,
		Zone:        zone.Host,
		Category:    "Clean / Not Listed",
		DelistURL:   zone.DelistURL,
		Description: task.desc,
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
		if err == nil && in != nil && in.Rcode != dns.RcodeServerFailure && in.Rcode != dns.RcodeRefused {
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

	if strings.Contains(res.Zone, "rep.mailspike.net") {
		switch code {
		case "127.0.0.10", "127.0.0.11", "127.0.0.12", "127.0.0.13", "127.0.0.14":
			res.Listed = true
			res.Category = "Listed in Mailspike: Bad sender reputation (L1-L5)"
		case "127.0.0.15", "127.0.0.16":
			res.IsWarning = true
			res.Category = "Mailspike Notice: Neutral / suspicious sender reputation"
		case "127.0.0.17", "127.0.0.18", "127.0.0.19", "127.0.0.20":
			res.Listed = false
			res.Category = "Clean: High sender reputation (H1-H5 in Mailspike)"
		default:
			res.Category = "Clean / Not Listed"
		}
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
