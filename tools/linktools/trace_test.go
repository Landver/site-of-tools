package linktools

// White-box, and it has to be: the egress gate rejects loopback, which is
// exactly where httptest servers live, so these tests set the unexported
// allowLoopback seam. That seam is per-instance rather than a package-level var
// (dnstools' resolverOverride is a global behind a mutex) so parallel tests
// cannot see each other's. Rule #6's stated exception.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/platform"
)

// testTracer builds a tracer that may dial loopback. Never reachable from
// outside this package: allowLoopback is unexported and NewTracer never sets it.
func testTracer(t *testing.T) *Tracer {
	t.Helper()
	tr := NewTracer(platform.NewEgressGuard([]string{"80", "443"}, nil), 10*time.Second)
	if tr == nil {
		t.Fatal("NewTracer returned nil with a valid guard")
	}
	tr.allowLoopback = true
	return tr
}

func trace(t *testing.T, tr *Tracer, url string) *Chain {
	t.Helper()
	ch, err := tr.Trace(context.Background(), url, "")
	if err != nil {
		t.Fatalf("Trace(%s): %v", url, err)
	}
	return ch
}

func noteText(ch *Chain) string {
	var b strings.Builder
	for _, n := range ch.Notes {
		b.WriteString(n.Title + " " + n.Detail + "\n")
	}
	for _, h := range ch.Hops {
		for _, n := range h.Notes {
			b.WriteString(n.Title + " " + n.Detail + "\n")
		}
	}
	return b.String()
}

// TestTraceFollowsAChain is the happy path: each hop is its own request.
func TestTraceFollowsAChain(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "a=b")
		w.WriteHeader(200)
	}))
	defer final.Close()
	mid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	defer mid.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, mid.URL, http.StatusMovedPermanently)
	}))
	defer first.Close()

	ch := trace(t, testTracer(t), first.URL)
	if len(ch.Hops) != 3 {
		t.Fatalf("got %d hops, want 3", len(ch.Hops))
	}
	if ch.Final != final.URL {
		t.Errorf("final = %q, want %q", ch.Final, final.URL)
	}
	if !ch.Hops[2].SetCookie {
		t.Error("cookie-setting hop not marked")
	}
}

// TestNeverForwardsRefererOrAuthorization. A hand-rolled walk that copies
// headers forward would send the pasted URL — tokens and all — to every
// subsequent attacker-chosen host. That is a worse leak than the request log's.
func TestNeverForwardsRefererOrAuthorization(t *testing.T) {
	var got http.Header
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(200)
	}))
	defer final.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	defer first.Close()

	// userinfo present: net/http would otherwise derive a Basic auth header.
	u := strings.Replace(first.URL, "http://", "http://user:pass@", 1)
	trace(t, testTracer(t), u)

	if v := got.Get("Referer"); v != "" {
		t.Errorf("Referer forwarded to the second hop: %q", v)
	}
	if v := got.Get("Authorization"); v != "" {
		t.Errorf("Authorization sent: %q", v)
	}
	if v := got.Get("Cookie"); v != "" {
		t.Errorf("Cookie sent — there must be no jar: %q", v)
	}
}

// TestRefusesPrivateAddressMidChain. The obvious attack: a public first hop
// redirecting into the private network. Every hop must be re-gated, not just
// the first.
func TestRefusesPrivateAddressMidChain(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer first.Close()

	ch := trace(t, testTracer(t), first.URL)
	if ch.Final != "" {
		t.Errorf("final = %q; a refused chain has no destination", ch.Final)
	}
	if !strings.Contains(strings.ToLower(noteText(ch)), "routable") {
		t.Errorf("refusal not explained:\n%s", noteText(ch))
	}
	for _, h := range ch.Hops {
		if strings.Contains(h.URL, "169.254.169.254") && h.Status != 0 {
			t.Errorf("metadata endpoint returned status %d — it was actually dialled", h.Status)
		}
	}
}

// TestUngatedTracerRefusesLoopback proves the seam is the only thing letting
// these tests reach 127.0.0.1, i.e. that production is closed.
func TestUngatedTracerRefusesLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()

	tr := NewTracer(platform.NewEgressGuard([]string{"80", "443"}, nil), 5*time.Second)
	ch, err := tr.Trace(context.Background(), srv.URL, "")
	if err == nil && ch != nil && ch.Final != "" {
		t.Errorf("a production tracer reached loopback at %s", ch.Final)
	}
}

// TestNonHTTPSchemeEndsTheChain: a Location of intent:// or javascript: is
// named, never dialled.
func TestNonHTTPSchemeEndsTheChain(t *testing.T) {
	for _, loc := range []string{"javascript:alert(1)", "intent://x#Intent;scheme=http;end", "file:///etc/passwd"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", loc)
			w.WriteHeader(http.StatusFound)
		}))
		ch := trace(t, testTracer(t), srv.URL)
		if ch.Final != "" {
			t.Errorf("%s: final = %q, want empty — the chain continues somewhere we did not follow", loc, ch.Final)
		}
		srv.Close()
	}
}

// TestHopCapTrips and the chain does not claim a destination.
func TestHopCapTrips(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/next", http.StatusFound)
	}))
	defer srv.Close()

	ch := trace(t, testTracer(t), srv.URL)
	if len(ch.Hops) > 12 {
		t.Errorf("%d hops; the cap is 10", len(ch.Hops))
	}
	if ch.Final != "" {
		t.Errorf("final = %q after hitting the cap; the chain did not end, we stopped", ch.Final)
	}
}

// TestMetaRefreshAndRefreshHeaderAreNamed. Reporting "chain finished" on a 200
// that carries a refresh is a wrong answer in the security-relevant direction.
func TestMetaRefreshAndRefreshHeaderAreNamed(t *testing.T) {
	t.Run("meta", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><meta http-equiv="refresh" content="0;url=https://elsewhere.example/"></head></html>`))
		}))
		defer srv.Close()
		ch := trace(t, testTracer(t), srv.URL)
		if !strings.Contains(strings.ToLower(noteText(ch)), "refresh") {
			t.Errorf("meta refresh not named:\n%s", noteText(ch))
		}
	})
	t.Run("header", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Refresh", "0;url=https://elsewhere.example/")
			w.WriteHeader(200)
		}))
		defer srv.Close()
		ch := trace(t, testTracer(t), srv.URL)
		if !strings.Contains(strings.ToLower(noteText(ch)), "refresh") {
			t.Errorf("Refresh HTTP header not named:\n%s", noteText(ch))
		}
	})
}

// TestBotProtectionReadsAsRefusal, not as a dead link. They are different facts.
func TestBotProtectionReadsAsRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	ch := trace(t, testTracer(t), srv.URL)
	txt := strings.ToLower(noteText(ch))
	if !strings.Contains(txt, "refus") && !strings.Contains(txt, "automated") {
		t.Errorf("403 not reported as a refusal:\n%s", noteText(ch))
	}
}

// TestPersonaIsSent and reported, so "who was refused" is answerable (A17).
func TestPersonaIsSent(t *testing.T) {
	var ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.UserAgent()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	ch := trace(t, testTracer(t), srv.URL+"?x=1")
	browserUA := ua
	if browserUA == "" {
		t.Fatal("no User-Agent sent at all")
	}
	ch2, err := testTracer(t).Trace(context.Background(), srv.URL, "googlebot")
	if err != nil {
		t.Fatalf("googlebot persona: %v", err)
	}
	if !strings.Contains(strings.ToLower(ua), "googlebot") {
		t.Errorf("googlebot persona did not change the User-Agent: %q", ua)
	}
	if ch2.Persona == "" || ch.Persona == "" {
		t.Error("persona not reported back on the chain")
	}
}

// TestNilTracerIsDisabled, so the handler answers 503 rather than panicking.
func TestNilTracerIsDisabled(t *testing.T) {
	var tr *Tracer
	if _, err := tr.Trace(context.Background(), "https://example.com/", ""); err == nil {
		t.Error("nil tracer returned no error")
	}
	if NewTracer(nil, time.Second) != nil {
		t.Error("NewTracer with a nil guard must return nil, not an ungated tracer")
	}
}

// TestTransportStaysClosed guards the three settings that are silent bypasses if
// someone "tidies" them away later.
func TestTransportStaysClosed(t *testing.T) {
	tr := testTracer(t)
	c := tr.client
	transport, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, not *http.Transport — re-check the settings below", c.Transport)
	}
	if transport.Proxy != nil {
		t.Error("Proxy is set: HTTP_PROXY would receive the target hostname and the dialer gate would only validate the proxy")
	}
	if !transport.DisableKeepAlives {
		t.Error("DisableKeepAlives is false: a pooled connection answers a second authority without a dial, so the Control hook never runs for it")
	}
	if transport.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 is true: h2 coalesces authorities onto one connection, the same bypass by another route")
	}
	if transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify is set")
	}
	if c.Jar != nil {
		t.Error("a cookie jar is attached")
	}
	if transport.MaxResponseHeaderBytes == 0 || transport.MaxResponseHeaderBytes > 1<<20 {
		t.Errorf("MaxResponseHeaderBytes = %d; Go's default is 10 MB and must be lowered", transport.MaxResponseHeaderBytes)
	}
}
