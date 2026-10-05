package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/shared"
	"github.com/Landver/site-of-tools/tools/botcheck"
)

func limitsApp(lim *botcheck.Limits) *echo.Echo {
	e := echo.New()
	e.Renderer = platform.NewRenderer(false, nil,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: botcheck.Templates, DevDir: "tools/botcheck/templates"},
	)
	botcheck.Register(e, fakeLooker{}, nil, nil, lim)
	return e
}

var (
	asAPI  = map[string]string{"Accept": "application/json"}
	asPage = map[string]string{"Accept": "text/html"}
)

// The JSON GET and POST /check are one class: both score, so both spend it.
func TestScoringRoutesShareOneBudget(t *testing.T) {
	lim := botcheck.NewLimits()
	a, b := limitsApp(lim), limitsApp(lim)
	for i := range 5 {
		if rec := get(a, "/", asAPI); rec.Code != http.StatusOK {
			t.Fatalf("GET / #%d = %d, want 200", i+1, rec.Code)
		}
		if rec := post(b, "/check", `{}`, asAPI); rec.Code != http.StatusOK {
			t.Fatalf("POST /check #%d = %d, want 200", i+1, rec.Code)
		}
	}
	rec := post(a, "/check", `{}`, asAPI)
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusTooManyRequests || body["error"] == "" {
		t.Errorf("11th score across both apps = %d %s, want a JSON 429", rec.Code, rec.Body)
	}
	page := post(b, "/check", `{}`, asPage)
	if page.Code != http.StatusTooManyRequests || !strings.Contains(page.Body.String(), "alert-error") ||
		!strings.Contains(page.Body.String(), "Too many checks") {
		t.Errorf("page's POST past the budget = %d, want the 429 error fragment:\n%s", page.Code, page.Body)
	}
}

func TestPageShellIsNotRateLimited(t *testing.T) {
	e := limitsApp(nil)
	for i := range 30 {
		if rec := get(e, "/", asPage); rec.Code != http.StatusOK {
			t.Fatalf("page load %d = %d, want 200: the shell scores nothing", i+1, rec.Code)
		}
	}
	if rec := post(e, "/check", `{}`, asAPI); rec.Code != http.StatusOK {
		t.Errorf("first check after 30 page loads = %d, want 200", rec.Code)
	}
}

func TestFullCheckCapAnswersBusy(t *testing.T) {
	lim := botcheck.NewLimits()
	if !lim.CheckCap.TryAcquire(8) {
		t.Fatal("a fresh check cap is not 8")
	}
	e := limitsApp(lim)
	for _, send := range []func() *httptest.ResponseRecorder{
		func() *httptest.ResponseRecorder { return get(e, "/", asAPI) },
		func() *httptest.ResponseRecorder { return post(e, "/check", `{}`, asAPI) },
		func() *httptest.ResponseRecorder { return post(e, "/check", `{}`, asPage) },
	} {
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() { done <- send() }()
		select {
		case rec := <-done:
			if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), platform.BusyMessage) {
				t.Errorf("full cap = %d %s, want 503 saying busy", rec.Code, rec.Body)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("a check waited on a full cap instead of answering busy")
		}
	}
	lim.CheckCap.Release(8)
	if rec := post(e, "/check", `{}`, asAPI); rec.Code != http.StatusOK {
		t.Errorf("check after the cap freed = %d, want 200", rec.Code)
	}
}
