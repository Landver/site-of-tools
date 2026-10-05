package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/shared"
	"github.com/Landver/site-of-tools/tools/linktools"
)

func limitsLinkApp(tracer *linktools.Tracer, lim *linktools.Limits) *echo.Echo {
	r := platform.NewRenderer(false, nil,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: linktools.Templates, DevDir: "tools/linktools/templates"},
	)
	e := platform.NewApp(r, fstest.MapFS{}, false, nil)
	linktools.Register(e, linktools.NewService(), tracer, nil, "https://link.example", lim)
	return e
}

func fromClient(e *echo.Echo, target, client string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("CF-Connecting-IP", client)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

const traceExample = "/trace?u=http%3A%2F%2Fexample.com%2F"

// The owner's key-gated /short routes and /trace keep separate 1/s budgets.
func TestTraceAndShortBudgetsAreSeparate(t *testing.T) {
	t.Parallel()
	e := limitsLinkApp(nil, nil)
	const client = "203.0.113.40"
	for range 5 {
		fromClient(e, "/short", client, asJSON)
	}
	if rec := fromClient(e, "/short", client, asJSON); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("sixth /short = %d, want 429", rec.Code)
	}
	for i := range 5 {
		if rec := fromClient(e, traceExample, client, asJSON); rec.Code == http.StatusTooManyRequests {
			t.Fatalf("trace %d was refused by the /short budget", i+1)
		}
	}
	if rec := fromClient(e, traceExample, client, asJSON); rec.Code != http.StatusTooManyRequests {
		t.Errorf("sixth trace = %d, want 429", rec.Code)
	}
}

// /s/:code spent through AllowKey (the MCP door) is spent for REST too: the
// per-client bucket across a /64, and the global breaker for everyone.
func TestResolveBudgetsAreSharedWithAllowKey(t *testing.T) {
	t.Parallel()
	lim := linktools.NewLimits()
	lim.Resolve = platform.NewLimiter(0.001, 1)
	lim.ResolveGlobal = platform.NewGlobalLimiter(0.001, 3)
	e := limitsLinkApp(nil, lim)

	if !platform.AllowKey(lim.Resolve, "2001:db8:9:9::1") || !platform.AllowKey(lim.ResolveGlobal, "2001:db8:9:9::1") {
		t.Fatal("first resolve refused")
	}
	if rec := fromClient(e, "/s/abc1234", "2001:db8:9:9::2", asJSON); rec.Code != http.StatusTooManyRequests {
		t.Errorf("same /64 over REST after AllowKey spent its bucket = %d, want 429", rec.Code)
	}
	if !platform.AllowKey(lim.ResolveGlobal, "198.51.100.9") {
		t.Fatal("second global token refused")
	}
	fromClient(e, "/s/abc1234", "203.0.113.42", asJSON)
	rec := fromClient(e, "/s/abc1234", "203.0.113.43", asJSON)
	if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != "busy, try again shortly" {
		t.Errorf("a fresh client after the global breaker emptied = %d %q, want the breaker's 503", rec.Code, rec.Body)
	}
}

func TestFullTraceCapAnswersBusy(t *testing.T) {
	t.Parallel()
	lim := linktools.NewLimits()
	if !lim.FetchCap.TryAcquire("198.51.100.250", 4) {
		t.Fatal("a fresh trace cap is not 4")
	}
	tracer := linktools.NewTracer(platform.NewEgressGuard([]string{"80", "443"}, nil), time.Second)
	e := limitsLinkApp(tracer, lim)

	for _, headers := range []map[string]string{asJSON, asHTML} {
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() { done <- fromClient(e, traceExample, "203.0.113.44", headers) }()
		select {
		case rec := <-done:
			if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), platform.BusyMessage) {
				t.Errorf("Accept %q with the trace cap full = %d %s, want 503 saying busy", headers["Accept"], rec.Code, rec.Body)
			}
			if headers["Accept"] == asJSON["Accept"] {
				var body map[string]string
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] != platform.BusyMessage {
					t.Errorf("JSON busy body = %s", rec.Body)
				}
			}
		case <-time.After(2 * time.Second):
			t.Fatal("the trace waited on a full cap instead of answering busy")
		}
	}
}
