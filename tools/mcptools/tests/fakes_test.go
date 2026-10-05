package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/Landver/site-of-tools/tools/dnstools"
	"github.com/Landver/site-of-tools/tools/iptools"
	"github.com/Landver/site-of-tools/tools/linktools"
)

type fakeGeo struct {
	res   iptools.Result
	panic bool
}

func (f *fakeGeo) Lookup(ip string) (*iptools.Result, error) {
	if f.panic {
		panic("fake lookup exploded")
	}
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("%q is not a valid IP address", ip)
	}
	r := f.res
	r.IP = ip
	return &r, nil
}

type fakeChecker struct{ lk iptools.BlockLookup }

func (f fakeChecker) Check(context.Context, string) (iptools.BlockLookup, error) { return f.lk, nil }

func (fakeChecker) LastSync(context.Context, string) (time.Time, error) { return time.Time{}, nil }

var richResult = iptools.Result{
	CountryCode: "US", Country: "United States", Region: "California", City: "Mountain View",
	Zip: "94043", Timezone: "-07:00", Latitude: 37.386, Longitude: -122.0838,
	ASN: "15169", ASName: "Google LLC",
	Proxy:  &iptools.Proxy{IsProxy: true, ProxyType: "VPN", Provider: "Acme VPN"},
	Shodan: &iptools.ShodanInfo{Found: true, Ports: []int{53, 443}, Hostnames: []string{"dns.google"}},
}

// offlineStore is unreachable: the gate only asks an owner Shortener whether a key is right.
var offlineStore = sync.OnceValue(func() *linktools.LinkStore {
	client, err := mongo.Connect(options.Client().
		ApplyURI("mongodb://127.0.0.1:1/").
		SetServerSelectionTimeout(200 * time.Millisecond).
		SetConnectTimeout(200 * time.Millisecond))
	if err != nil {
		return nil
	}
	return linktools.NewLinkStore(context.Background(), client.Database("site-of-tools-offline"))
})

func offlineOwner(t *testing.T) *linktools.Shortener {
	t.Helper()
	s := linktools.NewShortener(offlineStore(), ownerKey, linkBase)
	if !s.HasKey() {
		t.Fatal("could not build an owner Shortener with a key")
	}
	return s
}

type fakeDNS struct{ heavy bool } // heavy adds sixty long TXT records

// lookOnly is a Looker and nothing else, so the other DNS tools have nothing to run on.
type lookOnly struct{ f *fakeDNS }

func (l lookOnly) LookupSet(ctx context.Context, name, resolver string, types []string) (*dnstools.ResultSet, error) {
	return l.f.LookupSet(ctx, name, resolver, types)
}

func (f *fakeDNS) values(qtype string) []string {
	switch qtype {
	case "A":
		return []string{"192.0.2.10", "192.0.2.11"}
	case "TXT":
		vals := []string{`"v=spf1 include:_spf.example.net ip4:192.0.2.0/24 ~all"`}
		if f.heavy {
			for i := range 59 {
				vals = append(vals, fmt.Sprintf(`"vendor%02d-domain-verification=%s"`, i, strings.Repeat("k3Yx9QpL", 13)))
			}
		}
		return vals
	}
	return nil
}

func (f *fakeDNS) LookupSet(_ context.Context, name, resolver string, types []string) (*dnstools.ResultSet, error) {
	if len(types) == 0 {
		types = dnstools.FanoutTypes
	}
	set := &dnstools.ResultSet{
		Name: name, QName: name + ".", Resolver: resolver, ResolverName: dnstools.ResolverName(resolver),
		Asked: len(types), Found: []dnstools.Result{}, Missing: []string{},
	}
	var zone strings.Builder
	for _, qtype := range types {
		set.Dig = append(set.Dig, "dig @1.1.1.1 "+set.QName+" "+qtype)
		vals := f.values(qtype)
		if vals == nil {
			set.Missing = append(set.Missing, qtype)
			continue
		}
		r := dnstools.Result{Type: qtype}
		for _, v := range vals {
			r.Records = append(r.Records, dnstools.Record{Type: qtype, Value: v, TTL: 300, TTLHuman: "5m"})
			fmt.Fprintf(&zone, "%s\t300\tIN\t%s\t%s\n", set.QName, qtype, v)
		}
		set.Found = append(set.Found, r)
	}
	set.Zone = zone.String()
	return set, nil
}

// Spread: the zone agrees, one resolver holds an older answer, one nameserver timed out.
func (f *fakeDNS) Spread(_ context.Context, name, qtype string) (*dnstools.Spread, error) {
	now := f.values("A")
	if qtype == "TXT" {
		now = f.values("TXT")
	}
	old := now[:len(now)-1]
	answer := func(label string, vals []string) dnstools.ServerAnswer {
		return dnstools.ServerAnswer{Label: label, Addr: "192.0.2.53:53", Values: vals, TTL: 300}
	}
	return &dnstools.Spread{
		Name: name, QName: name + ".", Type: qtype, Zone: "example.com.",
		Authoritative: []dnstools.ServerAnswer{answer("ns1.example.com", now), {Label: "ns2.example.com", Error: "i/o timeout"}},
		Resolvers:     []dnstools.ServerAnswer{answer("Cloudflare (1.1.1.1)", now), answer("Quad9 (9.9.9.9)", old)},
		Groups: []dnstools.AnswerGroup{
			{Values: now, Servers: []string{"ns1.example.com", "Cloudflare (1.1.1.1)"}},
			{Values: old, Servers: []string{"Quad9 (9.9.9.9)"}},
		},
	}, nil
}

func (f *fakeDNS) Trace(_ context.Context, name, qtype string) (*dnstools.Trace, error) {
	return &dnstools.Trace{Name: name, QName: name + ".", Type: qtype, DNSSEC: "insecure", Answer: []string{"192.0.2.10"}}, nil
}

func (f *fakeDNS) EmailAuth(_ context.Context, domain string) (*dnstools.EmailAuth, error) {
	return &dnstools.EmailAuth{Domain: domain, SPF: &dnstools.SPFResult{Record: "v=spf1 mx -all", All: "-all"}, HasMX: true, MXCount: 1}, nil
}

// upstream serves RDAP and crt.sh on loopback.
type upstream struct {
	names            int // CT names per domain
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
			fmt.Fprintf(w, `{"objectClassName":"domain","ldhName":%q,"nameservers":[{"ldhName":"ns1.example.com"}]}`, name)
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
