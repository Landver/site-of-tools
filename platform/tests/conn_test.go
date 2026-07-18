package tests

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/shared"
)

// conn_test.go covers the G38/G44 conn-inspector enrichment: the additive
// ConnInfo network fields, the IP2Proxy type-code mapping, and the partial's
// rendering guards (empty ⇒ unchanged output for every existing tool).

func TestConnTransportFields(t *testing.T) {
	e := echo.New()
	e.GET("/c", func(c *echo.Context) error {
		ci := platform.Conn(c)
		return c.JSON(http.StatusOK, ci)
	})
	req := httptest.NewRequest(http.MethodGet, "/c", nil)
	req.Header.Set("CF-Connecting-IP", "203.0.113.7")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("User-Agent", "TestBrowser/1.0")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	body := rec.Body.String()
	for _, want := range []string{`"Via":"Cloudflare"`, `"Scheme":"https"`, `"Language":"en-US"`, `"Browser":"TestBrowser/1.0"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Conn JSON missing %s:\n%s", want, body)
		}
	}
}

func TestWithNetworkMapsProxyTypes(t *testing.T) {
	tests := []struct {
		code, want string
	}{
		{"VPN", "VPN"},
		{"TOR", "Tor exit node"},
		{"DCH", "datacenter / hosting"},
		{"RES", "residential proxy"},
		{"AIC", "AI crawler"},
		{"", ""},             // no proxy data ⇒ no row
		{"FUTURE", "FUTURE"}, // an unknown code surfaces verbatim, never hidden
	}
	for _, tt := range tests {
		if got := platform.ProxyKindLabel(tt.code); got != tt.want {
			t.Errorf("ProxyKindLabel(%q) = %q, want %q", tt.code, got, tt.want)
		}
	}

	ci := platform.ConnInfo{IP: "203.0.113.7"}.WithNetwork(platform.ConnNetwork{
		ASN: "12345", ASName: "Example ISP", ProxyType: "VPN", Provider: "NordVPN",
	})
	if ci.ASN != "12345" || ci.ASName != "Example ISP" || ci.ProxyKind != "VPN" || ci.ProxyProvider != "NordVPN" {
		t.Errorf("WithNetwork = %+v, want the enrichment carried through with the mapped kind", ci)
	}
	// An empty enrichment must leave every field empty — the unchanged-render
	// guarantee for tools that never resolve the IP.
	if ci := (platform.ConnInfo{}).WithNetwork(platform.ConnNetwork{}); ci.ASN != "" || ci.ProxyKind != "" {
		t.Errorf("WithNetwork(empty) = %+v, want all network fields empty", ci)
	}
}

func renderConn(t *testing.T, ci platform.ConnInfo) string {
	t.Helper()
	r := platform.NewRenderer(false, nil,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
	)
	var buf bytes.Buffer
	if err := r.Render(nil, &buf, "partials/conn", ci); err != nil {
		t.Fatalf("render conn partial: %v", err)
	}
	return buf.String()
}

func TestConnPartialUnenrichedRendersUnchanged(t *testing.T) {
	// Every tool today renders the partial with transport fields only — the
	// G38/G44 rows must not appear (not even their labels) when empty.
	body := renderConn(t, platform.ConnInfo{
		IP: "203.0.113.7", Via: "direct", Scheme: "https",
		Host: "ip.corpberry.com", Browser: "TestBrowser/1.0", Language: "en-US",
	})
	for _, absent := range []string{"<dt>ASN</dt>", "<dt>Proxy</dt>"} {
		if strings.Contains(body, absent) {
			t.Errorf("unenriched conn partial must not contain %q:\n%s", absent, body)
		}
	}
	for _, want := range []string{"203.0.113.7", "direct", "https", "TestBrowser/1.0"} {
		if !strings.Contains(body, want) {
			t.Errorf("conn partial missing %q:\n%s", want, body)
		}
	}
}

func TestConnPartialRendersNetworkRows(t *testing.T) {
	body := renderConn(t, platform.ConnInfo{
		IP: "203.0.113.7", Via: "direct", Scheme: "https",
		Host: "botcheck.corpberry.com", Browser: "TestBrowser/1.0",
	}.WithNetwork(platform.ConnNetwork{
		ASN: "12345", ASName: "Example ISP", ProxyType: "VPN", Provider: "NordVPN",
	}))
	for _, want := range []string{"<dt>ASN</dt>", "AS12345 (Example ISP)", "<dt>Proxy</dt>", "VPN — NordVPN"} {
		if !strings.Contains(body, want) {
			t.Errorf("enriched conn partial missing %q:\n%s", want, body)
		}
	}

	// Partial enrichment: an ASN without a name, and no proxy data at all —
	// only what's really there renders.
	body = renderConn(t, platform.ConnInfo{IP: "203.0.113.7"}.WithNetwork(platform.ConnNetwork{ASN: "714"}))
	if !strings.Contains(body, "AS714") {
		t.Errorf("a bare ASN should render without a name:\n%s", body)
	}
	if strings.Contains(body, "<dt>Proxy</dt>") {
		t.Errorf("no proxy data must mean no proxy row:\n%s", body)
	}
}
