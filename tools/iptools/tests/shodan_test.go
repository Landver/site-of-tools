package tests

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/Landver/site-of-tools/tools/iptools"
)

// shodan_test.go covers the Shodan InternetDB enrichment: the offline client
// (against an httptest server), its nil-safe/disabled shape, and the handler
// card + JSON wiring (Result.Shodan pre-set, like the blocklist handler tests).
// One live test, opt-in via SHODAN_LIVE_TEST, hits the real endpoint.

// stubInternetDB serves canned InternetDB responses: data for 8.8.8.8, 404 for
// 198.51.100.9 (no record), 500 otherwise (upstream failure).
func stubInternetDB(t *testing.T) *iptools.Shodan {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/8.8.8.8":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ip":"8.8.8.8","ports":[53,443],"hostnames":["dns.google"],"cpes":[],"tags":[],"vulns":["CVE-2021-1234"]}`)
		case "/198.51.100.9":
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"detail":"No information available"}`)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	return iptools.NewShodan(srv.URL, 2*time.Second)
}

func TestShodanLookupParsesInternetDB(t *testing.T) {
	sh := stubInternetDB(t)

	got, err := sh.Lookup(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	want := &iptools.ShodanInfo{
		Found:     true,
		Ports:     []int{53, 443},
		Hostnames: []string{"dns.google"},
		Vulns:     []string{"CVE-2021-1234"},
	}
	// EquateEmpty: JSON "[]" decodes to a non-nil empty slice; treat it as the
	// nil the want omits (CPEs/Tags here) so the comparison is about content.
	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("ShodanInfo mismatch (-want +got):\n%s", diff)
	}
}

func TestShodanLookup404IsCheckedNoData(t *testing.T) {
	sh := stubInternetDB(t)
	got, err := sh.Lookup(context.Background(), "198.51.100.9")
	if err != nil {
		t.Fatalf("404 lookup should not error: %v", err)
	}
	if got == nil || got.Found {
		t.Errorf("404 → checked-but-no-data (Found=false), got %+v", got)
	}
}

func TestShodanLookupErrorOmits(t *testing.T) {
	sh := stubInternetDB(t)
	// 500 → error, and (nil, err) so the handler omits the card rather than
	// implying "no open ports".
	got, err := sh.Lookup(context.Background(), "10.0.0.1")
	if err == nil {
		t.Errorf("unexpected status should return an error")
	}
	if got != nil {
		t.Errorf("error case should return nil ShodanInfo, got %+v", got)
	}
}

func TestShodanNilAndEmptyURLDisabled(t *testing.T) {
	var sh *iptools.Shodan // disabled (nil receiver)
	if got, err := sh.Lookup(context.Background(), "8.8.8.8"); got != nil || err != nil {
		t.Errorf("nil Shodan must no-op, got (%v, %v)", got, err)
	}
	if iptools.NewShodan("", time.Second) != nil {
		t.Errorf("empty base URL must disable (return nil)")
	}
	if iptools.NewShodan("   ", time.Second) != nil {
		t.Errorf("blank base URL must disable (return nil)")
	}
}

func TestHandlerShowsShodanCard(t *testing.T) {
	res := &iptools.Result{
		IP:     "8.8.8.8",
		Shodan: &iptools.ShodanInfo{Found: true, Ports: []int{53, 443}, Hostnames: []string{"dns.google"}, Vulns: []string{"CVE-2021-1234"}},
	}
	// HTML: card with ports, a CVE, and the mandatory Shodan attribution.
	rec := do(newTestApp(fakeLooker{res: res}), "/?ip=8.8.8.8", map[string]string{"Accept": "text/html"})
	body := rec.Body.String()
	for _, want := range []string{"open ports · shodan", "53, 443", "dns.google", "CVE-2021-1234", "Shodan InternetDB", "© Shodan"} {
		if !strings.Contains(body, want) {
			t.Errorf("shodan card missing %q in:\n%s", want, body)
		}
	}
	// JSON: nested shodan object flows through content negotiation for free.
	recj := do(newTestApp(fakeLooker{res: res}), "/?ip=8.8.8.8", map[string]string{"Accept": "application/json"})
	jb := strings.ReplaceAll(recj.Body.String(), " ", "")
	if !strings.Contains(jb, `"shodan":{`) || !strings.Contains(jb, `"found":true`) || !strings.Contains(jb, `"ports":[53,443]`) {
		t.Errorf("json missing shodan object: %s", recj.Body.String())
	}
}

func TestHandlerShodanNoDataState(t *testing.T) {
	// Checked-but-empty (404) renders the "No open ports on record" state — the
	// counterpart to the blocklist card's checked-but-clean row.
	res := &iptools.Result{IP: "198.51.100.9", Shodan: &iptools.ShodanInfo{Found: false}}
	rec := do(newTestApp(fakeLooker{res: res}), "/?ip=198.51.100.9", map[string]string{"Accept": "text/html"})
	body := rec.Body.String()
	if !strings.Contains(body, "open ports · shodan") || !strings.Contains(body, "No open ports on record") {
		t.Errorf("no-data shodan card should render, got:\n%s", body)
	}
}

func TestHandlerNoShodanNoCard(t *testing.T) {
	// nil Shodan (not checked) → no card at all, and no shodan key in JSON.
	res := &iptools.Result{IP: "8.8.8.8"}
	rec := do(newTestApp(fakeLooker{res: res}), "/?ip=8.8.8.8", map[string]string{"Accept": "text/html"})
	if strings.Contains(rec.Body.String(), "open ports · shodan") {
		t.Errorf("no Shodan data should render no card")
	}
	recj := do(newTestApp(fakeLooker{res: res}), "/?ip=8.8.8.8", map[string]string{"Accept": "application/json"})
	if strings.Contains(recj.Body.String(), `"shodan"`) {
		t.Errorf("no Shodan data should omit the json key, got: %s", recj.Body.String())
	}
}

func TestFullPageShowsShodanCredit(t *testing.T) {
	// Shodan's ToS requires a visible credit when their data is shown. The shared
	// footer carries it (like the IP2Location/Spamhaus credits), gated on a
	// Shodan-specific flag — not the shared .Attribution — so it shows only when a
	// lookup actually consulted InternetDB, and never on botcheck.
	withData := &iptools.Result{IP: "8.8.8.8", Shodan: &iptools.ShodanInfo{Found: true, Ports: []int{443}}}
	rec := do(newTestApp(fakeLooker{res: withData}), "/?ip=8.8.8.8", map[string]string{"Accept": "text/html"})
	if !strings.Contains(rec.Body.String(), "uses © Shodan's") {
		t.Errorf("full page with Shodan data must carry the © Shodan footer credit, got:\n%s", rec.Body.String())
	}

	// A lookup that never consulted Shodan (no Result.Shodan) gets no credit —
	// unlike IP2Location, which is always credited on IP-tool pages.
	rec2 := do(newTestApp(fakeLooker{res: &iptools.Result{IP: "8.8.8.8"}}), "/?ip=8.8.8.8", map[string]string{"Accept": "text/html"})
	if strings.Contains(rec2.Body.String(), "uses © Shodan's") {
		t.Errorf("page without Shodan data must not carry the Shodan footer credit")
	}
}

// TestShodanLookupLive hits the real InternetDB endpoint; opt-in only (network).
// Run with SHODAN_LIVE_TEST=1 go test ./tools/iptools/...
func TestShodanLookupLive(t *testing.T) {
	if os.Getenv("SHODAN_LIVE_TEST") == "" {
		t.Skip("set SHODAN_LIVE_TEST=1 to hit the real Shodan InternetDB endpoint")
	}
	sh := iptools.NewShodan("https://internetdb.shodan.io", 6*time.Second)
	got, err := sh.Lookup(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("live lookup: %v", err)
	}
	if got == nil || !got.Found || len(got.Ports) == 0 {
		t.Errorf("8.8.8.8 should have open ports on record, got %+v", got)
	}
}
