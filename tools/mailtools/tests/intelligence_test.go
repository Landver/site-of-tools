package tests

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/mailtools"
)

func TestDisposableAndFreemailClassification(t *testing.T) {
	classifier := mailtools.ActiveClassifier()

	tests := []struct {
		input        string
		wantType     mailtools.DomainType
		isDisposable bool
		isFreemail   bool
	}{
		// Canonical disposable
		{"test@mailinator.com", mailtools.DomainTypeDisposable, true, false},
		{"user@0-mail.com", mailtools.DomainTypeDisposable, true, false},
		{"sub.33mail.com", mailtools.DomainTypeDisposable, true, false}, // wildcard pattern

		// Free consumer webmail
		{"alex@gmail.com", mailtools.DomainTypeFreemail, false, true},
		{"contact@yahoo.com", mailtools.DomainTypeFreemail, false, true},
		{"dev@proton.me", mailtools.DomainTypeFreemail, false, true},
		{"user@mail.ru", mailtools.DomainTypeFreemail, false, true},

		// Corporate custom domains
		{"security@stripe.com", mailtools.DomainTypeCorporate, false, false},
		{"admin@uber.com", mailtools.DomainTypeCorporate, false, false},
		{"press@github.com", mailtools.DomainTypeCorporate, false, false},

		// Whitelist immunity
		{"admin@google.com", mailtools.DomainTypeCorporate, false, false},
		{"support@corpberry.com", mailtools.DomainTypeCorporate, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			res := classifier.Classify(tt.input)
			if res.Type != tt.wantType {
				t.Errorf("Classify(%q).Type = %v, want %v", tt.input, res.Type, tt.wantType)
			}
			if res.IsDisposable != tt.isDisposable {
				t.Errorf("Classify(%q).IsDisposable = %v, want %v", tt.input, res.IsDisposable, tt.isDisposable)
			}
			if res.IsFreemail != tt.isFreemail {
				t.Errorf("Classify(%q).IsFreemail = %v, want %v", tt.input, res.IsFreemail, tt.isFreemail)
			}
		})
	}
}

func TestGatewayDetectionLogic(t *testing.T) {
	ctx := context.Background()

	// 1. Google Workspace MX
	gw, err := mailtools.DetectGateway(ctx, "google.com")
	if err == nil && gw != nil && len(gw.MXRecords) > 0 {
		if gw.Vendor != mailtools.VendorGoogle {
			t.Errorf("DetectGateway(google.com).Vendor = %v, want %v", gw.Vendor, mailtools.VendorGoogle)
		}
	}

	// 2. Microsoft 365 Defender MX
	gw, err = mailtools.DetectGateway(ctx, "microsoft.com")
	if err == nil && gw != nil && len(gw.MXRecords) > 0 {
		if gw.Vendor != mailtools.VendorMicrosoft {
			t.Errorf("DetectGateway(microsoft.com).Vendor = %v, want %v", gw.Vendor, mailtools.VendorMicrosoft)
		}
	}
}

func TestDNSBLReturnCodeSemantics(t *testing.T) {
	// Query local test IP 127.0.0.2 against DNSBL audit logic
	ctx := context.Background()
	rep, err := newService(nil).DNSBL(ctx, "127.0.0.2")
	if err != nil {
		t.Fatalf("DNSBL failed: %v", err)
	}

	if rep.TotalChecked == 0 {
		t.Errorf("expected > 0 zones checked, got %d", rep.TotalChecked)
	}

	// Verify that 127.255.255.254 is never marked as a spam listing
	for _, r := range rep.Results {
		if r.ReturnCode == "127.255.255.254" && r.Listed {
			t.Errorf("Spamhaus open-resolver notice (127.255.255.254) must not be marked as Listed: %+v", r)
		}
	}
}

func TestEmailIntelligenceHTTPHandlers(t *testing.T) {
	e := newMailApp(t)

	// 1. GET /disposable
	req := httptest.NewRequest(http.MethodGet, "/disposable?input=test@mailinator.com", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /disposable: want 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Disposable / Burner Email") {
		t.Errorf("GET /disposable body missing disposable badge: %s", rec.Body.String())
	}

	// 2. POST /classifier JSON
	form := url.Values{"input": {"alex@proton.me"}}
	req = httptest.NewRequest(http.MethodPost, "/classifier", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("POST /classifier: want 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"type":"freemail"`) {
		t.Errorf("POST /classifier response missing freemail type: %s", rec.Body.String())
	}

	// 3. POST /health JSON
	form = url.Values{"domain": {"stripe.com"}}
	req = httptest.NewRequest(http.MethodPost, "/health", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("POST /health: want 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"domain":"stripe.com"`) {
		t.Errorf("POST /health response missing domain: %s", rec.Body.String())
	}
}

// -----------------------------------------------------------------------------
// 1. DomainClassifier: Edge Cases, URLs, Subdomains, Whitelist Precedence
// -----------------------------------------------------------------------------

func TestDomainClassifier_EdgeCasesAndPrecedence(t *testing.T) {
	// 1. ExtractDomain parsing variants
	cases := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"   ", ""},
		{"@", ""},
		{"@@", ""},
		{"user@", ""},
		{"@domain.com", "domain.com"},
		{"alex@company.co.uk", "company.co.uk"},
		{"  SUPPORT@Stripe.COM  ", "stripe.com"},
		{"https://google.com/path?query=123", "google.com"},
		{"http://sub.domain.org/index.html", "sub.domain.org"},
		{"https://example.com:8443/api/v1", "example.com"},
		{"http://127.0.0.1:8080/test", "127.0.0.1"},
		{"*.disposable.com", "disposable.com"},
		{".leadingdot.org", "leadingdot.org"},
	}

	for _, tc := range cases {
		got := mailtools.ExtractDomain(tc.input)
		if got != tc.want {
			t.Errorf("ExtractDomain(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}

	// 2. Multi-level Subdomains and Whitelist Immunity over Disposable
	custom := mailtools.NewDomainClassifier(
		[]string{"burner.com", "disposable.net", "whitelisted-burner.com", "*.wildcard-temp.org"},
		[]string{"freemail.org"},
		[]string{"whitelisted-burner.com", "trusted-enterprise.com"},
	)

	// Whitelisted domain MUST NOT be flagged as disposable even if in disposable seed
	if custom.IsWhitelisted("whitelisted-burner.com") != true {
		t.Errorf("whitelisted-burner.com expected to be whitelisted")
	}
	isDisp, _ := custom.IsDisposable("whitelisted-burner.com")
	if isDisp {
		t.Errorf("whitelisted-burner.com MUST NOT be flagged as disposable due to whitelist protection")
	}

	// Multi-level subdomain inheriting whitelist protection from root
	if !custom.IsWhitelisted("deep.sub.trusted-enterprise.com") {
		t.Errorf("deep.sub.trusted-enterprise.com should inherit root whitelist")
	}

	// Multi-level subdomain inheriting disposable classification from parent
	isDisp, reason := custom.IsDisposable("a.b.c.burner.com")
	if !isDisp || !strings.Contains(reason, "parent domain is in disposable blocklist") {
		t.Errorf("a.b.c.burner.com should be flagged as parent disposable, got %v (%s)", isDisp, reason)
	}

	// Wildcard matching
	isDisp, _ = custom.IsDisposable("prefix.wildcard-temp.org")
	if !isDisp {
		t.Errorf("prefix.wildcard-temp.org should match wildcard")
	}

	// Unknown corporate fallback
	rep := custom.Classify("unknown-corp-identity.io")
	if rep.Type != mailtools.DomainTypeCorporate || rep.IsDisposable || rep.IsFreemail {
		t.Errorf("unknown-corp-identity.io should fall back to Corporate: %+v", rep)
	}

	// Empty and malformed inputs
	repEmpty := custom.Classify("")
	if repEmpty.Domain != "" || repEmpty.Type != mailtools.DomainTypeCorporate {
		t.Errorf("empty input classification unexpected: %+v", repEmpty)
	}

	// The embedded seed is indexed at package load: no init call comes first.
	if mailtools.ActiveClassifier() == nil {
		t.Errorf("ActiveClassifier() must never return nil")
	}
}

// -----------------------------------------------------------------------------
// 2. Sitemap Pages Registry
// -----------------------------------------------------------------------------

func TestSitemapPages_Registry(t *testing.T) {
	pages, err := mailtools.SitemapPages()
	if err != nil {
		t.Fatalf("SitemapPages failed: %v", err)
	}
	if len(pages) < 7 {
		t.Errorf("SitemapPages returned %d pages, expected at least 7", len(pages))
	}

	expected := map[string]bool{
		"/":           false,
		"/disposable": false,
		"/classifier": false,
		"/blacklist":  false,
		"/dmarc":      false,
		"/bimi":       false,
		"/arc":        false,
	}

	for _, p := range pages {
		expected[p.Path] = true
	}

	for path, found := range expected {
		if !found {
			t.Errorf("missing route %s in SitemapPages", path)
		}
	}
}

// -----------------------------------------------------------------------------
// 4. Engine Fragment & Error Rendering
// -----------------------------------------------------------------------------

func TestEngine_FragmentRenderingAndErrors(t *testing.T) {
	tmpl, err := mailtools.FragmentTemplates()
	if err != nil {
		t.Fatalf("FragmentTemplates() failed: %v", err)
	}

	// 1. DMARC valid and invalid
	validDMARC := `<?xml version="1.0"?><feedback><report_metadata><org_name>test</org_name><email>t@t.com</email><report_id>1</report_id><date_range><begin>0</begin><end>1</end></date_range></report_metadata><policy_published><domain>test.com</domain><p>none</p></policy_published></feedback>`
	html, err := mailtools.RenderDMARC(tmpl, strings.NewReader(validDMARC))
	if err != nil || !strings.Contains(html, "test.com") {
		t.Errorf("RenderDMARC valid failed: %v, html: %s", err, html)
	}

	errHTML, err := mailtools.RenderDMARC(tmpl, strings.NewReader("invalid-xml"))
	if err == nil || !strings.Contains(errHTML, "alert-error") {
		t.Errorf("RenderDMARC error rendering expected, got: %v (%s)", err, errHTML)
	}

	// 2. BIMI valid and invalid
	validSVG := `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100"><title>T</title><circle cx="50" cy="50" r="40"/></svg>`
	html, err = mailtools.RenderBIMI(tmpl, validSVG)
	if err != nil || !strings.Contains(html, "BIMI SVG Tiny P/S Compliant") {
		t.Errorf("RenderBIMI valid failed: %v", err)
	}

	errHTML, err = mailtools.RenderBIMI(tmpl, "<not-svg>")
	if err == nil || !strings.Contains(errHTML, "alert-error") {
		t.Errorf("RenderBIMI error rendering expected, got: %v (%s)", err, errHTML)
	}

	// 3. ARC valid and invalid
	validARC := "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=arc; b=dGVzdA==\nARC-Authentication-Results: i=1; mx.google.com; dkim=pass\nARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=arc; b=dGVzdA=="
	html, err = mailtools.RenderARC(tmpl, validARC)
	if err != nil || !strings.Contains(html, "example.com") {
		t.Errorf("RenderARC valid failed: %v", err)
	}

	errHTML, err = mailtools.RenderARC(tmpl, "Not-ARC: headers")
	if err == nil || !strings.Contains(errHTML, "alert-error") {
		t.Errorf("RenderARC error rendering expected, got: %v (%s)", err, errHTML)
	}
}

// -----------------------------------------------------------------------------
// 5. MongoDB Store Nil Safety & Context Cancellation
// -----------------------------------------------------------------------------

func TestStore_NilSafety(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // every DNS query fails at once

	// 1. NewStore with nil DB
	store := mailtools.NewStore(ctx, nil)
	if store != nil {
		t.Errorf("NewStore(nil) should return nil")
	}

	// 2. A Service on a nil Store runs every check uncached
	for range 2 {
		if rep, err := newService(store).DNSBL(ctx, "target.com"); err != nil || rep == nil {
			t.Errorf("uncached DNSBL = %v, %v; want a report", rep, err)
		}
	}
}

// The cache is keyed by the normalized target and keeps the report as it was answered.
func TestDNSBL_CacheKeyedByNormalizedTarget(t *testing.T) {
	uri := os.Getenv("MONGODB_TEST_URI")
	if uri == "" {
		t.Skip("MONGODB_TEST_URI not set")
	}
	ctx := context.Background()
	m, err := platform.OpenMongo(ctx, uri, "site-of-tools-test")
	if err != nil {
		t.Fatalf("OpenMongo: %v", err)
	}
	t.Cleanup(func() { m.Close(ctx) })
	_ = m.DB().Collection("email_dnsbl_cache").Drop(ctx)
	svc := newService(mailtools.NewStore(ctx, m.DB()))

	first, err := svc.DNSBL(ctx, "  [127.0.0.2] ")
	if err != nil {
		t.Fatalf("DNSBL: %v", err)
	}
	again, err := svc.DNSBL(ctx, "127.0.0.2")
	if err != nil {
		t.Fatalf("DNSBL: %v", err)
	}
	if diff := cmp.Diff(first, again); diff != "" {
		t.Errorf("second call was not served from the cache (-first +again):\n%s", diff)
	}
}

func TestSyncWorker_CanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	// Must start and exit without blocking or panicking
	mailtools.StartSyncWorker(ctx, 0)
}

// An IPv6 target is refused in one clear error, before any query.
func TestDNSBL_IPv6Refused(t *testing.T) {
	for _, target := range []string{"2001:db8::1", "[2001:db8::25]"} {
		rep, err := newService(nil).DNSBL(context.Background(), target)
		if err == nil || !strings.Contains(err.Error(), "IPv6") {
			t.Errorf("DNSBL(%q) = %+v, %v; want an IPv6 error", target, rep, err)
		}
	}
}

func TestDNSBL_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled before execution

	svc := mailtools.NewService(platform.NewEgressGuard([]string{"443"}, nil), nil, "dqskey")
	rep, err := svc.DNSBL(ctx, "127.0.0.2")
	if err != nil {
		t.Fatalf("DNSBL returned error on canceled context: %v", err)
	}
	if rep == nil || rep.TotalChecked == 0 {
		t.Errorf("expected report with zones checked, got: %+v", rep)
	}
}

// -----------------------------------------------------------------------------
// 6. HTTP Handlers: All Routes, Form/Query, Content-Types, Errors, Rate Limit
// -----------------------------------------------------------------------------

func TestHTTPHandlers_RoutesAndEdgeCases(t *testing.T) {
	e := newMailApp(t)

	// Helper to execute request
	exec := func(method, target string, body io.Reader, contentType, accept, hx string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, body)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if hx != "" {
			req.Header.Set("HX-Request", hx)
		}
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}

	// 1. GET /
	rec := exec(http.MethodGet, "/", nil, "", "text/html", "")
	if rec.Code != http.StatusOK {
		t.Errorf("GET /: want 200, got %d", rec.Code)
	}

	// 2. Health routes
	// Bad request: missing domain
	rec = exec(http.MethodPost, "/health", strings.NewReader(""), "application/x-www-form-urlencoded", "application/json", "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST /health missing domain: want 400, got %d", rec.Code)
	}

	// Valid POST / via Query param fallback
	rec = exec(http.MethodPost, "/?domain=stripe.com", nil, "", "application/json", "")
	if rec.Code != http.StatusOK {
		t.Errorf("POST /?domain=stripe.com: want 200, got %d", rec.Code)
	}

	// Valid GET /?domain=stripe.com
	rec = exec(http.MethodGet, "/?domain=stripe.com", nil, "", "application/json", "")
	if rec.Code != http.StatusOK {
		t.Errorf("GET /?domain=stripe.com: want 200, got %d", rec.Code)
	}

	// Valid GET /health?domain=google.com via HTMX
	rec = exec(http.MethodGet, "/health?domain=google.com", nil, "", "text/html", "true")
	if rec.Code != http.StatusOK {
		t.Errorf("GET /health?domain=google.com HTMX: want 200, got %d", rec.Code)
	}

	// Valid POST /health via HTMX
	form := url.Values{"domain": {"google.com"}}
	rec = exec(http.MethodPost, "/health", strings.NewReader(form.Encode()), "application/x-www-form-urlencoded", "text/html", "true")
	if rec.Code != http.StatusOK {
		t.Errorf("POST /health HTMX: want 200, got %d", rec.Code)
	}

	// 3. Disposable routes
	// GET empty
	rec = exec(http.MethodGet, "/disposable", nil, "", "text/html", "")
	if rec.Code != http.StatusOK {
		t.Errorf("GET /disposable empty: want 200, got %d", rec.Code)
	}

	// POST empty
	rec = exec(http.MethodPost, "/disposable", strings.NewReader(""), "application/x-www-form-urlencoded", "application/json", "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST /disposable empty: want 400, got %d", rec.Code)
	}

	// POST valid corporate
	form = url.Values{"input": {"security@stripe.com"}}
	rec = exec(http.MethodPost, "/disposable", strings.NewReader(form.Encode()), "application/x-www-form-urlencoded", "application/json", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"is_disposable":false`) {
		t.Errorf("POST /disposable valid corporate failed: %d, body: %s", rec.Code, rec.Body.String())
	}

	// 4. Classifier routes
	// GET empty
	rec = exec(http.MethodGet, "/classifier", nil, "", "text/html", "")
	if rec.Code != http.StatusOK {
		t.Errorf("GET /classifier empty: want 200, got %d", rec.Code)
	}

	// GET with input
	rec = exec(http.MethodGet, "/classifier?input=test@mailinator.com", nil, "", "application/json", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"type":"disposable"`) {
		t.Errorf("GET /classifier with input: want 200 disposable, got %d: %s", rec.Code, rec.Body.String())
	}

	// POST empty
	rec = exec(http.MethodPost, "/classifier", strings.NewReader(""), "application/x-www-form-urlencoded", "application/json", "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST /classifier empty: want 400, got %d", rec.Code)
	}

	// 5. Blacklist routes
	// GET empty
	rec = exec(http.MethodGet, "/blacklist", nil, "", "text/html", "")
	if rec.Code != http.StatusOK {
		t.Errorf("GET /blacklist empty: want 200, got %d", rec.Code)
	}

	// GET with target
	rec = exec(http.MethodGet, "/blacklist?target=127.0.0.2", nil, "", "application/json", "")
	if rec.Code != http.StatusOK {
		t.Errorf("GET /blacklist with target: want 200, got %d", rec.Code)
	}

	// POST empty
	rec = exec(http.MethodPost, "/blacklist", strings.NewReader(""), "application/x-www-form-urlencoded", "application/json", "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST /blacklist empty: want 400, got %d", rec.Code)
	}

	// POST valid IP
	form = url.Values{"target": {"127.0.0.2"}}
	rec = exec(http.MethodPost, "/blacklist", strings.NewReader(form.Encode()), "application/x-www-form-urlencoded", "application/json", "")
	if rec.Code != http.StatusOK {
		t.Errorf("POST /blacklist valid IP: want 200, got %d", rec.Code)
	}

	// 6. DMARC routes
	// GET /dmarc
	rec = exec(http.MethodGet, "/dmarc", nil, "", "text/html", "")
	if rec.Code != http.StatusOK {
		t.Errorf("GET /dmarc: want 200, got %d", rec.Code)
	}

	// POST /dmarc empty
	rec = exec(http.MethodPost, "/dmarc", strings.NewReader(""), "application/x-www-form-urlencoded", "application/json", "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST /dmarc empty: want 400, got %d", rec.Code)
	}

	// POST /dmarc valid pasted xml
	validXML := `<?xml version="1.0"?><feedback><report_metadata><org_name>o</org_name><email>e</email><report_id>1</report_id><date_range><begin>0</begin><end>1</end></date_range></report_metadata><policy_published><domain>test.com</domain><p>none</p></policy_published></feedback>`
	form = url.Values{"xml": {validXML}}
	rec = exec(http.MethodPost, "/dmarc", strings.NewReader(form.Encode()), "application/x-www-form-urlencoded", "application/json", "")
	if rec.Code != http.StatusOK {
		t.Errorf("POST /dmarc valid xml: want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// POST /dmarc file upload
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	part, _ := w.CreateFormFile("report_file", "report.xml")
	part.Write([]byte(validXML))
	w.Close()
	rec = exec(http.MethodPost, "/dmarc", &b, w.FormDataContentType(), "text/html", "")
	if rec.Code != http.StatusOK {
		t.Errorf("POST /dmarc file upload: want 200, got %d", rec.Code)
	}

	// POST /dmarc/parse empty body
	rec = exec(http.MethodPost, "/dmarc/parse", strings.NewReader(""), "", "application/json", "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST /dmarc/parse empty: want 400, got %d", rec.Code)
	}

	// POST /dmarc/parse raw body
	rec = exec(http.MethodPost, "/dmarc/parse", strings.NewReader(validXML), "application/xml", "application/json", "")
	if rec.Code != http.StatusOK {
		t.Errorf("POST /dmarc/parse raw body: want 200, got %d", rec.Code)
	}

	// 7. BIMI routes
	// GET /bimi
	rec = exec(http.MethodGet, "/bimi", nil, "", "text/html", "")
	if rec.Code != http.StatusOK {
		t.Errorf("GET /bimi: want 200, got %d", rec.Code)
	}

	// POST /bimi empty
	rec = exec(http.MethodPost, "/bimi", strings.NewReader(""), "application/x-www-form-urlencoded", "application/json", "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST /bimi empty: want 400, got %d", rec.Code)
	}

	// POST /bimi valid SVG form
	validSVG := `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100"><title>L</title><circle cx="50" cy="50" r="40"/></svg>`
	form = url.Values{"svg": {validSVG}}
	rec = exec(http.MethodPost, "/bimi", strings.NewReader(form.Encode()), "application/x-www-form-urlencoded", "application/json", "")
	if rec.Code != http.StatusOK {
		t.Errorf("POST /bimi valid svg: want 200, got %d", rec.Code)
	}

	// POST /bimi/fix empty
	rec = exec(http.MethodPost, "/bimi/fix", strings.NewReader(""), "application/x-www-form-urlencoded", "application/json", "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST /bimi/fix empty: want 400, got %d", rec.Code)
	}

	// POST /bimi/fix invalid SVG
	form = url.Values{"svg": {"<not-a-valid-xml"}}
	rec = exec(http.MethodPost, "/bimi/fix", strings.NewReader(form.Encode()), "application/x-www-form-urlencoded", "application/json", "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST /bimi/fix invalid XML: want 400, got %d", rec.Code)
	}

	// 8. ARC routes
	// GET /arc
	rec = exec(http.MethodGet, "/arc", nil, "", "text/html", "")
	if rec.Code != http.StatusOK {
		t.Errorf("GET /arc: want 200, got %d", rec.Code)
	}

	// POST /arc empty
	rec = exec(http.MethodPost, "/arc", strings.NewReader(""), "application/x-www-form-urlencoded", "application/json", "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST /arc empty: want 400, got %d", rec.Code)
	}

	// POST /arc valid
	validARC := "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=arc; b=dGVzdA==\nARC-Authentication-Results: i=1; mx.google.com; dkim=pass\nARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=arc; b=dGVzdA=="
	form = url.Values{"headers": {validARC}}
	rec = exec(http.MethodPost, "/arc", strings.NewReader(form.Encode()), "application/x-www-form-urlencoded", "application/json", "")
	if rec.Code != http.StatusOK {
		t.Errorf("POST /arc valid: want 200, got %d", rec.Code)
	}

	// POST /arc/parse empty
	rec = exec(http.MethodPost, "/arc/parse", strings.NewReader(""), "", "application/json", "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST /arc/parse empty: want 400, got %d", rec.Code)
	}

	// POST /arc/parse raw body
	rec = exec(http.MethodPost, "/arc/parse", strings.NewReader(validARC), "text/plain", "application/json", "")
	if rec.Code != http.StatusOK {
		t.Errorf("POST /arc/parse raw: want 200, got %d", rec.Code)
	}
}

func BenchmarkDomainClassification(b *testing.B) {
	classifier := mailtools.ActiveClassifier()
	samples := []string{
		"test@mailinator.com",
		"security@stripe.com",
		"dev@proton.me",
		"sub.33mail.com",
		"admin@google.com",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = classifier.Classify(samples[i%len(samples)])
	}
}
