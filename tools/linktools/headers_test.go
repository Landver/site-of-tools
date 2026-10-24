package linktools

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/platform"
)

func TestAnalyzeCacheDirectives(t *testing.T) {
	h := make(http.Header)
	h.Set("Cache-Control", "public, max-age=3600, must-revalidate, immutable")
	h.Set("CDN-Cache-Control", "max-age=86400, stale-while-revalidate=600")
	h.Set("Age", "300")
	h.Set("ETag", `"abc-123"`)
	h.Set("Vary", "Accept-Encoding, Origin")

	res := AnalyzeCache(http.StatusOK, h)
	if res.TTL.BrowserTTLSeconds != 3600 {
		t.Errorf("BrowserTTL: want 3600, got %d", res.TTL.BrowserTTLSeconds)
	}
	if res.TTL.EdgeTTLSeconds != 86400 {
		t.Errorf("EdgeTTL: want 86400, got %d", res.TTL.EdgeTTLSeconds)
	}
	if res.TTL.RemainingSeconds != 3300 {
		t.Errorf("RemainingSeconds: want 3300, got %d", res.TTL.RemainingSeconds)
	}
	if res.TTL.StaleWhileReval != 600 {
		t.Errorf("StaleWhileReval: want 600, got %d", res.TTL.StaleWhileReval)
	}
	if res.IsWeakETag {
		t.Errorf("IsWeakETag: want false, got true")
	}
}

func TestCacheAntiPatterns(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		headers   map[string]string
		wantTitle string
	}{
		{
			name:      "no-cache with immutable",
			status:    200,
			headers:   map[string]string{"Cache-Control": "no-cache, immutable"},
			wantTitle: "Contradiction: no-cache combined with immutable",
		},
		{
			name:      "no-store with max-age",
			status:    200,
			headers:   map[string]string{"Cache-Control": "no-store, max-age=3600"},
			wantTitle: "Contradictory directives: no-store with max-age",
		},
		{
			name:      "public with Set-Cookie",
			status:    200,
			headers:   map[string]string{"Cache-Control": "public, max-age=3600", "Set-Cookie": "session=abc"},
			wantTitle: "Security Risk: public cache-control with Set-Cookie",
		},
		{
			name:      "CORS without Vary Origin",
			status:    200,
			headers:   map[string]string{"Access-Control-Allow-Origin": "*", "Cache-Control": "public, max-age=300"},
			wantTitle: "Cache Poisoning Risk: CORS header without Vary: Origin",
		},
		{
			name:      "gzip without Vary Accept-Encoding",
			status:    200,
			headers:   map[string]string{"Content-Encoding": "gzip", "Cache-Control": "max-age=60"},
			wantTitle: "Missing Vary: Accept-Encoding on compressed content",
		},
		{
			name:      "error status 500 cached publicly",
			status:    500,
			headers:   map[string]string{"Cache-Control": "public, max-age=3600"},
			wantTitle: "Caching HTTP error status 500",
		},
		{
			name:      "heuristic caching",
			status:    200,
			headers:   map[string]string{"Content-Type": "text/html"},
			wantTitle: "Heuristic caching active",
		},
		{
			name:      "weak etag",
			status:    200,
			headers:   map[string]string{"ETag": `W/"weak123"`},
			wantTitle: "Weak ETag (W/\"...\") detected",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := make(http.Header)
			for k, v := range tc.headers {
				h.Set(k, v)
			}
			res := AnalyzeCache(tc.status, h)
			found := false
			for _, note := range res.Findings {
				if note.Title == tc.wantTitle || (tc.name == "heuristic caching" && note.Title == "Heuristic caching active (no explicit cache lifetime)") {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected finding %q, got: %+v", tc.wantTitle, res.Findings)
			}
		})
	}
}

func TestAnalyzeSecurity(t *testing.T) {
	// 1. Cross-Origin Isolated site
	h := make(http.Header)
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Embedder-Policy", "require-corp")
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'strict-dynamic'; object-src 'none'; base-uri 'none'")
	h.Set("Permissions-Policy", "camera=(), microphone=()")
	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")

	sec := AnalyzeSecurity(h)
	if !sec.Isolation.Isolated {
		t.Errorf("Isolation: want true, got false")
	}
	if !sec.CSP.StrictDynamic || !sec.CSP.ObjectSrcNone || !sec.CSP.BaseUriNone {
		t.Errorf("CSP flags wrong: %+v", sec.CSP)
	}
	if !sec.HSTS.Present || !sec.HSTS.Preload || sec.HSTS.MaxAgeSeconds != 31536000 {
		t.Errorf("HSTS flags wrong: %+v", sec.HSTS)
	}

	// 2. Cookie prefix violations & SameSite=None without Secure
	hCookie := make(http.Header)
	hCookie.Add("Set-Cookie", "__Host-id=123; Path=/")                                      // Missing Secure
	hCookie.Add("Set-Cookie", "__Host-valid=123; Secure; Path=/")                           // Valid
	hCookie.Add("Set-Cookie", "__Host-bad-domain=123; Secure; Domain=example.com; Path=/") // Domain forbidden
	hCookie.Add("Set-Cookie", "tracker=xyz; SameSite=None")                                 // SameSite=None without Secure

	secCookie := AnalyzeSecurity(hCookie)
	if len(secCookie.Cookies) != 4 {
		t.Fatalf("Cookies count: want 4, got %d", len(secCookie.Cookies))
	}
	if secCookie.Cookies[0].PrefixValid {
		t.Errorf("expected first __Host- cookie to fail PrefixValid")
	}
	if !secCookie.Cookies[1].PrefixValid {
		t.Errorf("expected second __Host- cookie to pass PrefixValid")
	}
	if secCookie.Cookies[2].PrefixValid {
		t.Errorf("expected third __Host- cookie with Domain to fail PrefixValid")
	}

	foundNoneSecure := false
	for _, n := range secCookie.Findings {
		if n.Title == `Cookie "tracker": SameSite=None without Secure` {
			foundNoneSecure = true
			break
		}
	}
	if !foundNoneSecure {
		t.Errorf("expected finding for SameSite=None without Secure, got: %+v", secCookie.Findings)
	}
}

func TestParseRawHeaders(t *testing.T) {
	raw := `HTTP/2 200 OK
content-type: text/html; charset=utf-8
cache-control: public, max-age=3600, s-maxage=7200
cdn-cache-control: max-age=86400
etag: "v1.2.3"
cross-origin-opener-policy: same-origin
cross-origin-embedder-policy: require-corp
x-content-type-options: nosniff`

	report, err := ParseRawHeaders(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.StatusCode != 200 {
		t.Errorf("status code: want 200, got %d", report.StatusCode)
	}
	if report.Proto != "HTTP/2" {
		t.Errorf("proto: want HTTP/2, got %s", report.Proto)
	}
	if report.Cache.TTL.BrowserTTLSeconds != 3600 {
		t.Errorf("browser ttl: want 3600, got %d", report.Cache.TTL.BrowserTTLSeconds)
	}
	if report.Cache.TTL.EdgeTTLSeconds != 86400 {
		t.Errorf("edge ttl: want 86400, got %d", report.Cache.TTL.EdgeTTLSeconds)
	}
	if !report.Security.Isolation.Isolated {
		t.Errorf("isolation: want true, got false")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestProbeHeadersLiveAndETag(t *testing.T) {
	guard := platform.NewEgressGuard(nil, nil)
	tracer := NewTracer(guard, 5*time.Second)

	tracer.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("If-None-Match") == `"test-etag-123"` {
			return &http.Response{
				StatusCode: http.StatusNotModified,
				Status:     "304 Not Modified",
				Proto:      "HTTP/1.1",
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    r,
			}, nil
		}
		h := make(http.Header)
		h.Set("ETag", `"test-etag-123"`)
		h.Set("Cache-Control", "public, max-age=300")
		h.Set("Content-Type", "text/plain")
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Proto:      "HTTP/1.1",
			Header:     h,
			Body:       io.NopCloser(strings.NewReader("Hello headers!")),
			Request:    r,
		}, nil
	})

	report, err := tracer.ProbeHeaders(context.Background(), "https://example.com/api", "browser")
	if err != nil {
		t.Fatalf("ProbeHeaders failed: %v", err)
	}

	if report.StatusCode != http.StatusOK {
		t.Errorf("status code: want 200, got %d", report.StatusCode)
	}
	if report.Cache.ETag != `"test-etag-123"` {
		t.Errorf("etag: want \"test-etag-123\", got %q", report.Cache.ETag)
	}
	if report.ETagSimulation == nil {
		t.Fatal("expected ETagSimulation to be present")
	}
	if !report.ETagSimulation.Revalidated {
		t.Errorf("ETag simulation revalidated: want true, got false (%+v)", report.ETagSimulation)
	}
	if report.ETagSimulation.StatusCode != http.StatusNotModified {
		t.Errorf("ETag simulation status: want 304, got %d", report.ETagSimulation.StatusCode)
	}
}
