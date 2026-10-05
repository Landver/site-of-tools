package tests

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/dnstools"
)

// within fails the test if f waits: a full cap must refuse, never queue.
func within(t *testing.T, f func() *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- f() }()
	select {
	case rec := <-done:
		return rec
	case <-time.After(2 * time.Second):
		t.Fatal("the request waited on a full cap instead of answering busy")
		return nil
	}
}

func TestWalksHaveTheirOwnStricterBudget(t *testing.T) {
	t.Parallel()
	e := newAppWith(t, &goldenDNS{}, nil, nil, nil, nil)
	for i, target := range []string{"/consistency?name=example.com", "/trace?name=example.com", "/consistency?name=example.com"} {
		if rec := do(t, e, target, nil); rec.Code != http.StatusOK {
			t.Fatalf("walk %d (%s) = %d, want 200 inside the burst of 3", i+1, target, rec.Code)
		}
	}
	if rec := do(t, e, "/trace?name=example.com", nil); rec.Code != http.StatusTooManyRequests {
		t.Errorf("fourth walk = %d, want 429", rec.Code)
	}
	if rec := do(t, e, "/?name=example.com", nil); rec.Code != http.StatusOK {
		t.Errorf("a lookup after the walk budget ran out = %d, want 200", rec.Code)
	}
}

func TestRouteIsBusyOnlyWhenItsOwnCapIsFull(t *testing.T) {
	t.Parallel()
	dom := goldenUpstream(t, http.StatusOK, http.StatusOK)
	capOf := map[string]string{"/": "lookup", "/email": "lookup", "/consistency": "walk", "/trace": "walk", "/domain": "domain"}
	for _, full := range []string{"lookup", "walk", "domain"} {
		lim := dnstools.NewLimits()
		caps := map[string]**platform.Cap{"lookup": &lim.LookupCap, "walk": &lim.WalkCap, "domain": &lim.DomainCap}
		*caps[full] = platform.NewCap(0)
		e := newAppWith(t, &goldenDNS{}, nil, dom, nil, lim)
		for path, class := range capOf {
			rec := within(t, func() *httptest.ResponseRecorder {
				return do(t, e, path+"?name=example.com", map[string]string{"Accept": "text/html"})
			})
			want, busy := http.StatusOK, class == full
			if busy {
				want = http.StatusServiceUnavailable
			}
			if rec.Code != want || strings.Contains(rec.Body.String(), platform.BusyMessage) != busy {
				t.Errorf("%s with the %s cap full = %d, want %d (busy %v)", path, full, rec.Code, want, busy)
			}
		}
	}
}
