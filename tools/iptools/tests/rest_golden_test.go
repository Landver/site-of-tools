package tests

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Landver/site-of-tools/platform/goldentest"
	"github.com/Landver/site-of-tools/tools/iptools"
)

func TestLookupJSONGolden(t *testing.T) {
	rich := &iptools.Result{
		IP: "8.8.8.8", CountryCode: "US", Country: "United States", Region: "California", City: "Mountain View",
		Zip: "94043", Timezone: "-07:00", Latitude: 37.386, Longitude: -122.0838,
		ASN: "15169", ASName: "Google LLC",
		Proxy: &iptools.Proxy{
			IsProxy: true, ProxyType: "VPN", UsageType: "DCH", Threat: "SPAM", Provider: "Acme VPN",
			FraudScore: "12", ISP: "Acme Hosting", Domain: "acme.example", LastSeen: "3",
		},
		Shodan: &iptools.ShodanInfo{Found: true, Ports: []int{53, 443}, Hostnames: []string{"dns.google"}, Tags: []string{"vpn"}},
	}
	listed := &recordingChecker{lk: iptools.BlockLookup{Sources: []string{"ipsum", "spamhaus-drop"}, MaxCount: 7}}
	loopback := newTestApp(fakeLooker{})
	loopback.IPExtractor = func(*http.Request) string { return "127.0.0.1" }
	got := map[string]*httptest.ResponseRecorder{
		"blocklisted":   do(newAppWith(fakeLooker{res: rich}, listed, nil), "/?ip=8.8.8.8", asJSON),
		"invalid_ip":    do(newTestApp(fakeLooker{err: errors.New(`"nope" is not a valid IP address`)}), "/?ip=nope", asJSON),
		"self_loopback": do(loopback, "/", asJSON),
	}
	goldentest.JSON(t, "lookup", goldentest.Recorded(got))
}

func TestCIDRJSONGolden(t *testing.T) {
	app := newTestApp(fakeLooker{})
	got := map[string]*httptest.ResponseRecorder{"empty": do(app, "/cidr", asJSON)}
	for name, q := range map[string]string{"v4_24": "192.168.1.0/24", "v6_32": "2001:db8::/32", "invalid": "nope"} {
		got[name] = do(app, "/cidr?cidr="+q, asJSON)
	}
	goldentest.JSON(t, "cidr", goldentest.Recorded(got))
}
