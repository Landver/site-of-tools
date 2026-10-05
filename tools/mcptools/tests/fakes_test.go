package tests

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/botcheck"
	"github.com/Landver/site-of-tools/tools/ciphertools"
	"github.com/Landver/site-of-tools/tools/dnstools"
	"github.com/Landver/site-of-tools/tools/iptools"
	"github.com/Landver/site-of-tools/tools/linktools"
)

// fakeDNS answers every interface dnstools.Register looks for, from data built
// fresh per call (enrichment writes into it). heavy gives the zone the sixty
// TXT records of a domain verified with every SaaS vendor going.
type fakeDNS struct {
	heavy bool
	err   error // every check answers this
}

// lookOnly is a Looker and nothing else, so the walk, mail and trace checks
// have nothing to run on.
type lookOnly struct{ f *fakeDNS }

func (l lookOnly) LookupSet(ctx context.Context, name, resolver string, types []string) (*dnstools.ResultSet, error) {
	return l.f.LookupSet(ctx, name, resolver, types)
}

var vendors = []string{"google-site-verification", "facebook-domain-verification", "atlassian-domain-verification",
	"docusign", "stripe-verification", "adobe-idp-site-verification", "globalsign-domain-verification", "apple-domain-verification"}

func (f *fakeDNS) txt() []string {
	vals := []string{`"v=spf1 include:_spf.example.net ip4:192.0.2.0/24 ~all"`}
	if f.heavy {
		for i := range 59 {
			vals = append(vals, fmt.Sprintf(`"%s=%s%02d"`, vendors[i%len(vendors)], strings.Repeat("k3Yx9QpL", 12), i))
		}
	}
	slices.Sort(vals)
	return vals
}

func (f *fakeDNS) records(qtype string) []dnstools.Record {
	rec := func(typ, value, target string, ttl uint32) dnstools.Record {
		return dnstools.Record{Type: typ, Value: value, TTL: ttl, TTLHuman: fmt.Sprintf("%dm", ttl/60), Target: target}
	}
	switch qtype {
	case "A":
		return []dnstools.Record{rec("A", "192.0.2.10", "", 300), rec("A", "192.0.2.11", "", 300)}
	case "AAAA":
		return []dnstools.Record{rec("AAAA", "2001:db8::10", "", 300)}
	case "MX":
		return []dnstools.Record{rec("MX", "10 mail.example.com.", "mail.example.com", 3600)}
	case "NS":
		return []dnstools.Record{rec("NS", "ns1.example.com.", "ns1.example.com", 86400), rec("NS", "ns2.example.com.", "ns2.example.com", 86400)}
	case "SOA":
		return []dnstools.Record{rec("SOA", "ns1.example.com. hostmaster.example.com. 2026100501 7200 3600 1209600 300", "", 3600)}
	case "TXT":
		var out []dnstools.Record
		for _, v := range f.txt() {
			out = append(out, rec("TXT", v, "", 300))
		}
		return out
	}
	return nil
}

// LookupSet renders dig lines and zone text the way the real one does, since
// those re-renderings are what a concise dns_lookup leaves out.
func (f *fakeDNS) LookupSet(_ context.Context, name, resolver string, types []string) (*dnstools.ResultSet, error) {
	if f.err != nil {
		return nil, f.err
	}
	asked := types
	if len(asked) == 0 {
		asked = dnstools.FanoutTypes
	}
	qname := name + "."
	set := &dnstools.ResultSet{
		Name: name, QName: qname, Resolver: resolver, ResolverName: dnstools.ResolverName(resolver),
		Flags: "qr rd ra", Asked: len(asked), Found: []dnstools.Result{}, Missing: []string{}, QueryMS: 9,
	}
	if net.ParseIP(name) != nil {
		set.QName, set.Reversed, asked = "10.2.0.192.in-addr.arpa.", true, []string{"PTR"}
		set.Asked = 1
		set.Found = append(set.Found, dnstools.Result{Type: "PTR", Records: []dnstools.Record{
			{Type: "PTR", Value: "host.example.com.", TTL: 3600, TTLHuman: "1h", Target: "host.example.com"}}})
	}
	var zone strings.Builder
	for _, t := range asked {
		set.Dig = append(set.Dig, "dig @1.1.1.1 "+set.QName+" "+t)
		recs := f.records(t)
		if len(recs) == 0 {
			if t != "PTR" {
				set.Missing = append(set.Missing, t)
			}
			continue
		}
		set.Found = append(set.Found, dnstools.Result{Type: t, Records: recs})
	}
	for _, r := range set.Found {
		for _, rec := range r.Records {
			fmt.Fprintf(&zone, "%s\t%d\tIN\t%s\t%s\n", set.QName, rec.TTL, rec.Type, rec.Value)
		}
	}
	set.Zone = zone.String()
	return set, nil
}

func (f *fakeDNS) check(name string) error {
	if f.err != nil {
		return f.err
	}
	if net.ParseIP(name) != nil {
		return dnstools.ErrNeedDomain
	}
	return nil
}

// Spread: the zone's servers agree, one resolver still holds an older answer,
// and one nameserver timed out.
func (f *fakeDNS) Spread(_ context.Context, name, qtype string) (*dnstools.Spread, error) {
	if err := f.check(name); err != nil {
		return nil, err
	}
	now := []string{"192.0.2.10", "192.0.2.11"}
	if qtype == "TXT" {
		now = f.txt()
	}
	old := now[:len(now)-1]
	auth := func(label, addr string) dnstools.ServerAnswer {
		return dnstools.ServerAnswer{Label: label, Addr: addr, Values: now, TTL: 300, AA: true, Serial: 2026100501, RTTMS: 5}
	}
	res := func(label, addr string, vals []string, ttl uint32) dnstools.ServerAnswer {
		return dnstools.ServerAnswer{Label: label, Addr: addr, Values: vals, TTL: ttl, RTTMS: 3}
	}
	return &dnstools.Spread{
		Name: name, QName: name + ".", Type: qtype, Zone: "example.com.",
		Authoritative: []dnstools.ServerAnswer{
			auth("ns1.example.com", "192.0.2.53:53"), auth("ns2.example.com", "198.51.100.53:53"),
			{Label: "ns3.example.com", Addr: "203.0.113.53:53", Error: "i/o timeout", RTTMS: 5000},
		},
		Resolvers: []dnstools.ServerAnswer{
			res("Cloudflare (1.1.1.1)", "1.1.1.1:53", now, 250),
			res("Google (8.8.8.8)", "8.8.8.8:53", now, 120),
			res("Quad9 (9.9.9.9)", "9.9.9.9:53", old, 3000),
		},
		NSTotal: 3,
		Groups: []dnstools.AnswerGroup{
			{Values: now, Servers: []string{"ns1.example.com", "ns2.example.com", "Cloudflare (1.1.1.1)", "Google (8.8.8.8)"}},
			{Values: old, Servers: []string{"Quad9 (9.9.9.9)"}},
		},
		ResolverGroups: 2, AuthConsistent: true, AuthAnswered: 2, SerialsAgree: true, SerialsSeen: 2,
		Answered: 5, Asked: 6, StaleFor: "50m", QueryMS: 40,
	}, nil
}

func (f *fakeDNS) ECS(_ context.Context, name, qtype string) (*dnstools.ECS, error) {
	if err := f.check(name); err != nil {
		return nil, err
	}
	if !slices.Contains([]string{"A", "AAAA", "CNAME", "HTTPS"}, qtype) {
		return nil, dnstools.ErrBadType
	}
	return &dnstools.ECS{
		Name: name, QName: name + ".", Type: qtype, Resolver: "Google (8.8.8.8)", ResolverAddr: "8.8.8.8:53",
		Vantages: []dnstools.ECSAnswer{{Region: "Europe", Place: "Amsterdam, NL", Subnet: "192.87.0.0/24",
			Values: []string{"192.0.2.10"}, TTL: 300, Echoed: true, RTTMS: 20}},
		Groups:  []dnstools.ECSGroup{{Values: []string{"192.0.2.10"}, Vantages: []string{"Amsterdam, NL"}}},
		Verdict: dnstools.ECSVerdictInconclusive, Echoed: 1, WithRecords: 1, Answered: 1, Asked: 1, QueryMS: 25,
	}, nil
}

func (f *fakeDNS) Trace(_ context.Context, name, qtype string) (*dnstools.Trace, error) {
	if err := f.check(name); err != nil {
		return nil, err
	}
	if qtype == "" {
		qtype = "A"
	}
	return &dnstools.Trace{
		Name: name, QName: name + ".", Type: qtype,
		Hops: []dnstools.TraceHop{
			{Zone: ".", Server: "a.root-servers.net", ServerIP: "198.41.0.4", RTTMS: 10, Referral: "com.",
				Nameservers: []string{"a.gtld-servers.net"}, Glue: []string{"192.5.6.30"}},
			{Zone: "example.com.", Server: "ns1.example.com", ServerIP: "192.0.2.53", RTTMS: 8, Authoritative: true,
				Nameservers: []string{}, Glue: []string{}},
		},
		Chain: []dnstools.TraceLink{}, DNSSEC: "insecure",
		Verdict:    dnstools.Note{Level: "info", Text: "This name is not signed."},
		RootServer: "a.root-servers.net", Answer: []string{"192.0.2.10"}, Notes: []dnstools.Note{}, Queries: 4, QueryMS: 30,
	}, nil
}

func (f *fakeDNS) EmailAuth(_ context.Context, domain string) (*dnstools.EmailAuth, error) {
	if err := f.check(domain); err != nil {
		return nil, err
	}
	return &dnstools.EmailAuth{
		Domain: domain,
		SPF:    &dnstools.SPFResult{Record: "v=spf1 mx -all", Lookups: 1, Limit: 10, All: "-all"},
		DMARC:  &dnstools.DMARCResult{Record: "v=DMARC1; p=reject", Name: "_dmarc." + domain, Policy: "reject"},
		HasMX:  true, MXCount: 1,
		MailHosts: []dnstools.MailHost{{Host: "mail.example.com", IP: "192.0.2.25", PTR: "mail.example.com", FCrDNS: true}},
		Notes:     []dnstools.Note{{Level: "warn", Text: "No DKIM key at the common selectors."}, {Level: "ok", Text: "SPF ends in -all."}},
		QueryMS:   40,
	}, nil
}

func (f *fakeDNS) MXReputation(_ context.Context, domain string, _ dnstools.BlockChecker) (*dnstools.MXReputation, error) {
	return &dnstools.MXReputation{
		Domain:  domain,
		Hosts:   []dnstools.MXRepHost{{Host: "mail.example.com", Preference: 10, Addrs: []dnstools.MXRepAddr{{IP: "192.0.2.25"}}}},
		MXCount: 1, Checked: 1, Feeds: []string{"spamhaus-drop"}, Corpus: "spamhaus-drop, synced daily",
		Notes: []dnstools.Note{{Level: "ok", Text: "No mail server is listed."}}, QueryMS: 3,
	}, nil
}

// netGeo labels the fake zone's addresses with their networks.
type netGeo map[string]*iptools.Result

func (g netGeo) Lookup(ip string) (*iptools.Result, error) {
	if r, ok := g[ip]; ok {
		c := *r
		return &c, nil
	}
	return nil, errors.New("not in the test table")
}

var dnsGeo = netGeo{
	"192.0.2.10":    {ASN: "64500", ASName: "Example Net", Country: "Exampleland"},
	"192.0.2.11":    {ASN: "64500", ASName: "Example Net", Country: "Exampleland"},
	"192.0.2.53":    {ASN: "64500", ASName: "Example Net", Country: "Exampleland"},
	"198.51.100.53": {ASN: "64501", ASName: "Other Net", Country: "Elsewhere"},
}

// fakeBlock is a blocklist corpus that lists nothing and synced an hour ago.
type fakeBlock struct{}

func (fakeBlock) Check(context.Context, string) (iptools.BlockLookup, error) {
	return iptools.BlockLookup{}, nil
}

func (fakeBlock) LastSync(context.Context, string) (time.Time, error) {
	return time.Now().Add(-time.Hour), nil
}

// upstream serves RDAP and crt.sh on loopback: a registration for whatever
// domain is asked, and `names` Certificate Transparency names under it. A
// half that is down answers 500.
type upstream struct {
	names            int
	rdapDown, ctDown bool
}

func (u upstream) client(t *testing.T) *dnstools.DomainClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if name, ok := strings.CutPrefix(r.URL.Path, "/domain/"); ok {
			if u.rdapDown {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(w, `{"objectClassName":"domain","ldhName":%q,"status":["client transfer prohibited"],
				"events":[{"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"}],
				"entities":[{"roles":["registrar"],"vcardArray":["vcard",[["fn",{},"text","Example Registrar, Inc."]]]}],
				"nameservers":[{"ldhName":"NS1.EXAMPLE.COM"},{"ldhName":"ns2.example.com."}]}`, name)
			return
		}
		if u.ctDown {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		base := strings.TrimPrefix(r.URL.Query().Get("q"), "%.")
		rows := make([]map[string]string, u.names)
		for i := range rows {
			rows[i] = map[string]string{"name_value": fmt.Sprintf("host-%03d.dev.%s", i, base),
				"not_before": "2026-01-01T00:00:00", "not_after": "2026-12-31T00:00:00", "serial_number": fmt.Sprint(i)}
		}
		_ = json.NewEncoder(w).Encode(rows)
	}))
	t.Cleanup(srv.Close)
	return dnstools.NewDomainClient(srv.URL, srv.URL, 5*time.Second)
}

// ownHosts are what main.go's outbound guards refuse: every vhost, here and in
// production.
var ownHosts = []string{mcpHost, ipHost, dnsHost, linkHost, "mcp.localhost:8080", "mcp.corpberry.com", "link.corpberry.com"}

// guardedTracer is the real tracer behind the real guard, as main.go builds
// it. Every URL the tests trace is refused before a connection is made.
func guardedTracer() *linktools.Tracer {
	return linktools.NewTracer(platform.NewEgressGuard([]string{"80", "443"}, ownHosts), 2*time.Second)
}

// roomy limits leave tests that aren't about limits room for several calls;
// the walk budget is three a client.
func roomyDNS() *dnstools.Limits {
	return &dnstools.Limits{Lookup: platform.NewLimiter(100, 1000), Walk: platform.NewLimiter(100, 1000),
		LookupCap: platform.NewCap(8), WalkCap: platform.NewCap(4), DomainCap: platform.NewCap(4)}
}

func roomyLink() *linktools.Limits {
	l := linktools.NewLimits()
	l.Pure, l.Fetch, l.Short = platform.NewLimiter(100, 1000), platform.NewLimiter(100, 1000), platform.NewLimiter(100, 1000)
	return l
}

// roomyCipher keeps the real heavy byte budget, which TestHeavyCipherOps fills.
func roomyCipher() *ciphertools.Limits {
	l := ciphertools.NewLimits()
	l.Pure, l.Heavy = platform.NewLimiter(100, 1000), platform.NewLimiter(100, 1000)
	return l
}

func roomyBot() *botcheck.Limits {
	return &botcheck.Limits{Check: platform.NewLimiter(100, 1000), CheckCap: platform.NewCap(8)}
}
