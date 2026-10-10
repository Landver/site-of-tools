package tests

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/platform/goldentest"
	"github.com/Landver/site-of-tools/tools/dnstools"
	"github.com/Landver/site-of-tools/tools/iptools"
)

// goldenDNS serves every check from fixed data built fresh per call.
type goldenDNS struct {
	lookErr   error
	delegated bool
	spreadErr error
	ecsErr    error
	traceErr  error
	mailErr   error
	repErr    error
}

func goldenRecords(t string) []dnstools.Record {
	switch t {
	case "A":
		return []dnstools.Record{{Type: "A", Value: "192.0.2.10", TTL: 300, TTLHuman: "5m"}}
	case "AAAA":
		return []dnstools.Record{{Type: "AAAA", Value: "2001:db8::10", TTL: 300, TTLHuman: "5m"}}
	case "MX":
		return []dnstools.Record{{Type: "MX", Value: "10 mail.example.com.", TTL: 3600, TTLHuman: "1h", Target: "mail.example.com"}}
	case "NS":
		return []dnstools.Record{{Type: "NS", Value: "ns1.example.com.", TTL: 86400, TTLHuman: "1d", Target: "ns1.example.com"}}
	}
	return nil
}

func (f *goldenDNS) LookupSet(_ context.Context, name, resolver string, types []string) (*dnstools.ResultSet, error) {
	if f.lookErr != nil {
		return nil, f.lookErr
	}
	asked := types
	if asked == nil {
		asked = dnstools.FanoutTypes
	}
	set := &dnstools.ResultSet{
		Name: name, QName: name + ".", Resolver: resolver, ResolverName: dnstools.ResolverName(resolver),
		Flags: "qr rd ra", Asked: len(asked), Found: []dnstools.Result{}, Missing: []string{}, QueryMS: 7,
		Dig: []string{"dig @1.1.1.1 " + name + ". " + strings.Join(asked, ",")},
	}
	for _, t := range asked {
		recs := goldenRecords(t)
		if recs == nil || (t == "NS" && !f.delegated) {
			set.Missing = append(set.Missing, t)
			continue
		}
		set.Found = append(set.Found, dnstools.Result{Type: t, Records: recs})
	}
	return set, nil
}

func (f *goldenDNS) Spread(_ context.Context, name, qtype string) (*dnstools.Spread, error) {
	if f.spreadErr != nil {
		return nil, f.spreadErr
	}
	vals := []string{"192.0.2.10"}
	return &dnstools.Spread{
		Name: name, QName: name + ".", Type: qtype, Zone: "example.com.",
		Authoritative: []dnstools.ServerAnswer{
			{Label: "ns1.example.com", Addr: "192.0.2.53:53", Values: vals, TTL: 300, AA: true, Serial: 2026100401, RTTMS: 4},
			{Label: "ns2.example.com", Addr: "198.51.100.53:53", Values: vals, TTL: 300, AA: true, Serial: 2026100401, RTTMS: 6},
		},
		Resolvers: []dnstools.ServerAnswer{
			{Label: "Cloudflare (1.1.1.1)", Addr: "1.1.1.1:53", Values: vals, TTL: 250, CacheAge: "50s", RTTMS: 2},
		},
		NSTotal:        2,
		Groups:         []dnstools.AnswerGroup{{Values: vals, Servers: []string{"ns1.example.com", "ns2.example.com", "Cloudflare (1.1.1.1)"}}},
		ResolverGroups: 1, Consistent: true, AuthConsistent: true, AuthAnswered: 2,
		SerialsAgree: true, SerialsSeen: 1, Answered: 3, Asked: 3, QueryMS: 12,
	}, nil
}

func (f *goldenDNS) ECS(_ context.Context, name, qtype string) (*dnstools.ECS, error) {
	if f.ecsErr != nil {
		return nil, f.ecsErr
	}
	return &dnstools.ECS{
		Name: name, QName: name + ".", Type: qtype, Resolver: "Google (8.8.8.8)", ResolverAddr: "8.8.8.8:53",
		Vantages: []dnstools.ECSAnswer{{
			Region: "Europe", Place: "Amsterdam, NL", Subnet: "192.87.0.0/24",
			Values: []string{"192.0.2.10"}, TTL: 300, Echoed: true, RTTMS: 20,
		}},
		Groups:  []dnstools.ECSGroup{{Values: []string{"192.0.2.10"}, Vantages: []string{"Europe"}}},
		Verdict: "same", Echoed: 1, WithRecords: 1, Answered: 1, Asked: 1, QueryMS: 25,
	}, nil
}

func (f *goldenDNS) Trace(_ context.Context, name, qtype string) (*dnstools.Trace, error) {
	if f.traceErr != nil {
		return nil, f.traceErr
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
		RootServer: "a.root-servers.net", Answer: []string{"192.0.2.10"}, Notes: []dnstools.Note{}, QueryMS: 30,
	}, nil
}

func (f *goldenDNS) EmailAuth(_ context.Context, domain string) (*dnstools.EmailAuth, error) {
	if f.mailErr != nil {
		return nil, f.mailErr
	}
	return &dnstools.EmailAuth{
		Domain: domain,
		SPF:    &dnstools.SPFResult{Record: "v=spf1 mx -all", Lookups: 1, Limit: 10, All: "-all"},
		DMARC:  &dnstools.DMARCResult{Record: "v=DMARC1; p=reject", Name: "_dmarc." + domain, Policy: "reject"},
		HasMX:  true, MXCount: 1,
		MailHosts: []dnstools.MailHost{{Host: "mail.example.com", IP: "192.0.2.25", PTR: "mail.example.com", FCrDNS: true}},
		Notes: []dnstools.Note{
			{Level: "ok", Text: "SPF ends in -all."},
			{Level: "warn", Text: "No DKIM key at the common selectors."},
		},
		QueryMS: 40,
	}, nil
}

func (f *goldenDNS) MXReputation(_ context.Context, domain string, _ dnstools.BlockChecker) (*dnstools.MXReputation, error) {
	if f.repErr != nil {
		return nil, f.repErr
	}
	return &dnstools.MXReputation{
		Domain: domain,
		Hosts: []dnstools.MXRepHost{{Host: "mail.example.com", Preference: 10,
			Addrs: []dnstools.MXRepAddr{{IP: "192.0.2.25"}}}},
		MXCount: 1, Checked: 1, Feeds: []string{"ipsum"}, Corpus: "ipsum, synced daily",
		Notes: []dnstools.Note{{Level: "ok", Text: "No mail server is listed."}}, QueryMS: 3,
	}, nil
}

type goldenGeo map[string]*iptools.Result

func (g goldenGeo) Lookup(ip string) (*iptools.Result, error) {
	if r, ok := g[ip]; ok {
		return r, nil
	}
	return nil, errors.New("not in the test table")
}

func testGeo() goldenGeo {
	net1 := &iptools.Result{ASN: "64500", ASName: "Example Net", Country: "Exampleland"}
	return goldenGeo{
		"192.0.2.10": net1, "2001:db8::10": net1, "192.0.2.53": net1,
		"198.51.100.53": {ASN: "64501", ASName: "Other Net", Country: "Elsewhere"},
	}
}

const goldenRDAP = `{
  "objectClassName": "domain",
  "ldhName": "example.com",
  "status": ["client transfer prohibited"],
  "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"}],
  "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar, Inc."]]]}],
  "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}, {"ldhName": "ns2.example.com."}]
}`

const goldenCT = `[
  {"name_value": "www.example.com\nexample.com", "not_before": "2026-01-01T00:00:00", "not_after": "2026-12-31T00:00:00", "serial_number": "01"},
  {"name_value": "*.example.com", "not_before": "2026-01-01T00:00:00", "not_after": "2026-12-31T00:00:00", "serial_number": "02"},
  {"name_value": "api.example.com", "not_before": "2026-02-01T00:00:00", "not_after": "2027-02-01T00:00:00", "serial_number": "03"}
]`

// goldenUpstream also returns the host:port the upstream's error messages embed, for scrubbing.
func goldenUpstream(t *testing.T, rdapCode, ctCode int) (*dnstools.DomainClient, string) {
	t.Helper()
	dc, up := canned(t, goldenRDAP, rdapCode, goldenCT, ctCode)
	return dc, up.host
}

type dnsCase struct {
	name   string
	target string
	svc    dnstools.Looker
	geo    iptools.Looker
	dom    *dnstools.DomainClient
	bl     dnstools.BlockChecker
	scrub  string
}

func runDNSGolden(t *testing.T, file string, cases []dnsCase) {
	t.Helper()
	got := map[string]goldentest.Response{}
	for _, tc := range cases {
		rec := do(t, registerApp(tc.svc, tc.geo, tc.dom, tc.bl, nil), tc.target, nil)
		body := rec.Body.String()
		if tc.scrub != "" {
			body = strings.ReplaceAll(body, tc.scrub, "upstream.test")
		}
		got[tc.name] = goldentest.Response{Status: rec.Code, Body: json.RawMessage(body)}
	}
	goldentest.JSON(t, file, got)
}

func TestGoldenLookupJSON(t *testing.T) {
	t.Parallel()
	runDNSGolden(t, "dns_lookup", []dnsCase{
		{name: "fanout_enriched", target: "/?name=" + url.QueryEscape("https://Example.COM/pricing"), svc: &goldenDNS{}, geo: testGeo()},
		{name: "type_and_resolver", target: "/?name=example.com&type=mx&resolver=%20GOOGLE%20", svc: &goldenDNS{}, geo: testGeo()},
		{name: "type_all_no_geo", target: "/?name=example.com&type=all", svc: &goldenDNS{}},
		{name: "reverse", target: "/?name=192.0.2.10&type=PTR", svc: &goldenDNS{}},
		{name: "trailing_junk", target: "/?name=" + url.QueryEscape("example.com /x"), svc: &goldenDNS{}},
		{name: "bad_type", target: "/?name=example.com&type=ANY", svc: &goldenDNS{lookErr: dnstools.ErrBadType}},
		{name: "upstream_failure", target: "/?name=example.com", svc: &goldenDNS{lookErr: errUpstream{}}},
		{name: "no_name", target: "/", svc: &goldenDNS{}},
	})
}

func TestGoldenConsistencyJSON(t *testing.T) {
	t.Parallel()
	dom, host := goldenUpstream(t, http.StatusOK, http.StatusOK)
	runDNSGolden(t, "dns_consistency", []dnsCase{
		{name: "full", target: "/consistency?name=Example.com&type=a", svc: &goldenDNS{}, geo: testGeo(), dom: dom, scrub: host},
		{name: "ecs_failed", target: "/consistency?name=example.com", svc: &goldenDNS{ecsErr: errors.New("not measurable")}, geo: testGeo(), dom: dom, scrub: host},
		{name: "no_geo_no_rdap", target: "/consistency?name=example.com&type=AAAA", svc: &goldenDNS{}},
		{name: "spread_error", target: "/consistency?name=192.0.2.1", svc: &goldenDNS{spreadErr: dnstools.ErrNeedDomain}},
		{name: "unavailable", target: "/consistency?name=example.com", svc: &fakeLooker{}},
		{name: "no_name", target: "/consistency", svc: &goldenDNS{}},
	})
}

func TestGoldenTraceJSON(t *testing.T) {
	t.Parallel()
	runDNSGolden(t, "dns_trace", []dnsCase{
		{name: "ok", target: "/trace?name=WWW.example.com&type=aaaa", svc: &goldenDNS{}},
		{name: "default_type", target: "/trace?name=example.com", svc: &goldenDNS{}},
		{name: "error", target: "/trace?name=example.com&type=ANY", svc: &goldenDNS{traceErr: dnstools.ErrBadType}},
		{name: "unavailable", target: "/trace?name=example.com", svc: &fakeLooker{}},
		{name: "no_name", target: "/trace", svc: &goldenDNS{}},
	})
}

func TestGoldenDomainJSON(t *testing.T) {
	t.Parallel()
	ok, okHost := goldenUpstream(t, http.StatusOK, http.StatusOK)
	rdapDown, rdapDownHost := goldenUpstream(t, http.StatusInternalServerError, http.StatusOK)
	bothDown, bothDownHost := goldenUpstream(t, http.StatusInternalServerError, http.StatusBadGateway)
	absentCTDown, absentCTDownHost := goldenUpstream(t, http.StatusNotFound, http.StatusInternalServerError)
	absent, absentHost := goldenUpstream(t, http.StatusNotFound, http.StatusOK)
	runDNSGolden(t, "dns_domain", []dnsCase{
		{name: "subdomain_both_ok", target: "/domain?name=www.Example.com", svc: &goldenDNS{}, dom: ok, scrub: okHost},
		{name: "apex_both_ok", target: "/domain?name=example.com", svc: &goldenDNS{}, dom: ok, scrub: okHost},
		{name: "rdap_down", target: "/domain?name=example.com", svc: &goldenDNS{}, dom: rdapDown, scrub: rdapDownHost},
		{name: "both_down", target: "/domain?name=example.com", svc: &goldenDNS{}, dom: bothDown, scrub: bothDownHost},
		{name: "absent_but_delegated", target: "/domain?name=example.com", svc: &goldenDNS{delegated: true}, dom: absentCTDown, scrub: absentCTDownHost},
		{name: "absent_undelegated", target: "/domain?name=example.com", svc: &goldenDNS{}, dom: absent, scrub: absentHost},
		{name: "absent_lookup_failed", target: "/domain?name=example.com", svc: &goldenDNS{lookErr: errUpstream{}}, dom: absentCTDown, scrub: absentCTDownHost},
		{name: "disabled", target: "/domain?name=example.com", svc: &goldenDNS{}},
		{name: "ip", target: "/domain?name=1.1.1.1", svc: &goldenDNS{}, dom: ok},
		{name: "bad_name", target: "/domain?name=a..b", svc: &goldenDNS{}, dom: ok},
		{name: "no_name", target: "/domain", svc: &goldenDNS{}, dom: ok},
	})
}

func TestGoldenEmailJSON(t *testing.T) {
	t.Parallel()
	runDNSGolden(t, "dns_email", []dnsCase{
		{name: "with_reputation", target: "/email?name=Example.com", svc: &goldenDNS{}, bl: &repCorpus{}},
		{name: "reputation_failed", target: "/email?name=example.com", svc: &goldenDNS{repErr: dnstools.ErrNoBlocklist}, bl: &repCorpus{}},
		{name: "no_corpus", target: "/email?name=example.com", svc: &goldenDNS{}},
		{name: "error", target: "/email?name=192.0.2.1", svc: &goldenDNS{mailErr: dnstools.ErrNeedDomain}, bl: &repCorpus{}},
		{name: "unavailable", target: "/email?name=example.com", svc: &fakeLooker{}},
		{name: "no_name", target: "/email", svc: &goldenDNS{}},
	})
}
