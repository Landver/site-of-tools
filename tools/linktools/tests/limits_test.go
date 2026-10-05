package tests

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/linktools"
)

const traceExample = "/trace?u=http%3A%2F%2Fexample.com%2F"

func TestTraceAndShortBudgetsAreSeparate(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)
	for _, target := range []string{"/short", traceExample} {
		for range 5 {
			if rec := request(t, e, http.MethodGet, target, asJSON); rec.Code == http.StatusTooManyRequests {
				t.Fatalf("%s refused within its own burst", target)
			}
		}
		if rec := request(t, e, http.MethodGet, target, asJSON); rec.Code != http.StatusTooManyRequests {
			t.Errorf("sixth %s = %d, want 429", target, rec.Code)
		}
	}
}

func TestResolveBreakerAnswersBusy(t *testing.T) {
	t.Parallel()
	lim := linktools.NewLimits()
	lim.ResolveGlobal = platform.NewGlobalLimiter(0.001, 1)
	e := newLinkAppWith(t, nil, nil, lim)
	request(t, e, http.MethodGet, "/s/abc1234", asJSON)
	if rec := request(t, e, http.MethodGet, "/s/abc1234", asJSON); rec.Code != http.StatusServiceUnavailable || rec.Body.String() != "busy, try again shortly" {
		t.Errorf("/s/ with the breaker empty = %d %q, want the breaker's 503", rec.Code, rec.Body)
	}
}

func TestFullTraceCapAnswersBusy(t *testing.T) {
	t.Parallel()
	lim := linktools.NewLimits()
	if !lim.FetchCap.TryAcquire("198.51.100.250", 4) {
		t.Fatal("a fresh trace cap is not 4")
	}
	tracer := linktools.NewTracer(platform.NewEgressGuard([]string{"80", "443"}, nil), time.Second)
	e := newLinkAppWith(t, tracer, nil, lim)
	for _, tc := range []struct {
		headers map[string]string
		want    string
	}{
		{asJSON, `{"error":"` + platform.BusyMessage + `"}`},
		{asHTML, platform.BusyMessage},
	} {
		if rec := request(t, e, http.MethodGet, traceExample, tc.headers); rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("Accept %q with the trace cap full = %d %s, want 503 saying busy", tc.headers["Accept"], rec.Code, rec.Body)
		}
	}
}
