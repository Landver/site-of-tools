package tests

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/tools/iptools"
)

// copyLooker hands out a fresh copy of res per call, so enrichment of one
// response can't leak into the next.
type copyLooker struct {
	res iptools.Result
	err error
}

func (l copyLooker) Lookup(ip string) (*iptools.Result, error) {
	if l.err != nil {
		return nil, l.err
	}
	r := l.res
	r.IP = ip
	return &r, nil
}

type fakeChecker struct {
	lk  iptools.BlockLookup
	err error
}

func (f fakeChecker) Check(context.Context, string) (iptools.BlockLookup, error) { return f.lk, f.err }

var richResult = iptools.Result{
	CountryCode: "US", Country: "United States", Region: "California", City: "Mountain View",
	Zip: "94043", Timezone: "-07:00", Latitude: 37.386, Longitude: -122.0838,
	ASN: "15169", ASName: "Google LLC",
	Proxy: &iptools.Proxy{
		IsProxy: true, ProxyType: "VPN", UsageType: "DCH", Threat: "SPAM", Provider: "Acme VPN",
		FraudScore: "12", ISP: "Acme Hosting", Domain: "acme.example", LastSeen: "3",
	},
	Shodan: &iptools.ShodanInfo{Found: true, Ports: []int{53, 443}, Hostnames: []string{"dns.google"}, Tags: []string{"vpn"}},
}

func goldenIPApp(svc iptools.Looker, chk iptools.Checker) *echo.Echo {
	e := echo.New()
	iptools.Register(e, svc, nil, chk)
	return e
}

func getJSON(app *echo.Echo, target, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Accept", "application/json")
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	return rec
}

func TestLookupJSONGolden(t *testing.T) {
	rich := copyLooker{res: richResult}
	listed := fakeChecker{lk: iptools.BlockLookup{Sources: []string{"ipsum", "spamhaus-drop"}, MaxCount: 7}}
	cases := []struct {
		name, target, remote string
		svc                  iptools.Looker
		chk                  iptools.Checker
	}{
		{"lookup", "/?ip=8.8.8.8", "", rich, nil},
		{"lookup_trims_space", "/?ip=%208.8.8.8%20", "", rich, nil},
		{"lookup_bare_result", "/?ip=2001:db8::1", "", copyLooker{}, nil},
		{"invalid_ip", "/?ip=nope", "", copyLooker{err: errors.New(`"nope" is not a valid IP address`)}, listed},
		{"unavailable", "/?ip=1.2.3.4", "", copyLooker{err: iptools.ErrUnavailable}, listed},
		{"self_routable", "/", "203.0.113.7:5555", rich, nil},
		{"self_loopback", "/", "127.0.0.1:5555", rich, listed},
		{"self_private", "/", "10.1.2.3:5555", rich, nil},
		{"blocklisted", "/?ip=8.8.8.8", "", rich, listed},
		{"blocklist_clean", "/?ip=8.8.8.8", "", rich, fakeChecker{}},
		{"blocklist_read_failed", "/?ip=8.8.8.8", "", rich, fakeChecker{err: errors.New("mongo down")}},
		{"self_blocklisted", "/", "203.0.113.7:5555", copyLooker{}, listed},
	}
	got := map[string]*httptest.ResponseRecorder{}
	for _, tc := range cases {
		got[tc.name] = getJSON(goldenIPApp(tc.svc, tc.chk), tc.target, tc.remote)
	}
	checkGolden(t, "lookup", got)
}

func TestCIDRJSONGolden(t *testing.T) {
	app := goldenIPApp(copyLooker{}, nil)
	got := map[string]*httptest.ResponseRecorder{}
	for name, q := range map[string]string{
		"v4_24":       "192.168.1.0/24",
		"v4_unmasked": "192.168.1.77/24",
		"v4_31":       "10.0.0.0/31",
		"v4_bare_ip":  "10.0.0.1",
		"v6_32":       "2001:db8::/32",
		"v6_bare_ip":  "2001:db8::1",
		"invalid":     "nope",
	} {
		got[name] = getJSON(app, "/cidr?cidr="+q, "")
	}
	got["empty"] = getJSON(app, "/cidr", "")
	checkGolden(t, "cidr", got)
}
