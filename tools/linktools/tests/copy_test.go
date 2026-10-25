package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/linktools"
)

// data-copy and data-copy-auto (partials/copy.html) are the feature, so asserting them tests it.

// asOperator is the console's own htmx request shape: a page navigation cannot send the key header.
var asOperator = map[string]string{"Accept": "text/html", "HX-Request": "true", "X-Api-Key": testAPIKey}

// Each page includes partials/copy itself, and a button without it looks fine but does nothing.
func TestEveryCopyButtonHasTheScriptBehindIt(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	for _, target := range []string{
		"/?u=HTTPS%3A%2F%2FExample.com%2Fp%3Fa%3D1", // canonical form differs, so it has a card and a Copy
		"/clean?u=https%3A%2F%2Fexample.com%2Fp%3Futm_source%3Dx",
		"/utm?u=https%3A%2F%2Fexample.com%2Fp&utm_source=n&utm_medium=email",
		"/curl?u=https%3A%2F%2Fexample.com%2Fp",
		"/encode?v=a+b",
		"/extract?text=see+https%3A%2F%2Fexample.com%2F",
	} {
		body := request(t, e, http.MethodGet, target, asHTML).Body.String()
		if !strings.Contains(body, "data-copy=") {
			t.Errorf("%s renders no copy control", target)
		}
		if !strings.Contains(body, "navigator.clipboard") {
			t.Errorf("%s has copy buttons but not partials/copy; every one of them is decoration", target)
		}
	}

	// With no shortener /short renders no button, but the include sits outside {{if .Disabled}}
	// in a template a configured server shares, so the script must still ship.
	rec := request(t, e, http.MethodGet, "/short", asHTML)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /short with no shortener = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "navigator.clipboard") {
		t.Error("the console does not ship partials/copy when short links are off")
	}

	rec = request(t, e, http.MethodGet, "/trace", asHTML)
	if !strings.Contains(rec.Body.String(), "navigator.clipboard") {
		t.Error("the trace page does not ship partials/copy")
	}
}

// Live: the fresh link and the list both come from storage. A custom slug makes the expected URL exact.
func TestCopyOffersTheWholeShortURL(t *testing.T) {
	ctx := context.Background()
	short, store := liveShortener(t, ctx)
	e := newLinkApp(t, nil, short)

	req := httptest.NewRequest(http.MethodPost, "/short",
		strings.NewReader(`{"url":"https://example.com/made","slug":"copytest"}`))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range asOperator {
		req.Header.Set(k, v)
	}
	frag := httptest.NewRecorder()
	e.ServeHTTP(frag, req)
	if frag.Code != http.StatusCreated {
		t.Fatalf("POST /short (htmx) = %d, want 201 (body %s)", frag.Code, frag.Body)
	}
	want := `data-copy="` + short.ShortURL("copytest") + `"`
	if !strings.Contains(frag.Body.String(), want) {
		t.Errorf("created fragment does not offer %s to the clipboard:\n%s", want, frag.Body)
	}
	// And it copies with no click. Shorten is the only gesture anyone makes.
	if !strings.Contains(frag.Body.String(), "data-copy-auto") {
		t.Error("a created link does not copy on its own")
	}

	dead, err := short.Create(ctx, linktools.CreateRequest{URL: "https://example.com/dead"}, "")
	if err != nil {
		t.Fatalf("create link to revoke: %v", err)
	}
	if err := store.Revoke(ctx, dead.Code, time.Now()); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	rec := request(t, e, http.MethodGet, "/short", asOperator)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /short as operator = %d, want 200 (body %s)", rec.Code, rec.Body)
	}
	html := rec.Body.String()
	// The full URL, not the bare code the table prints: a code on the clipboard pastes as nonsense.
	if !strings.Contains(html, want) {
		t.Errorf("live alias row does not offer %s to the clipboard:\n%s", want, html)
	}
	if got := `data-copy="` + short.ShortURL(dead.Code) + `"`; strings.Contains(html, got) {
		t.Error("a revoked alias is still offered to the clipboard; a dead link fails silently in the paste")
	}
	// The list never auto-copies: ten rows cannot each claim the clipboard.
	if strings.Contains(html, "data-copy-auto") {
		t.Error("the alias list auto-copies a row; only a freshly created link may do that")
	}
}
