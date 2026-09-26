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

// The clipboard affordance is declarative: data-copy carries the text and
// data-copy-auto also copies it when htmx swaps the element in
// (shared/templates/partials/copy.html). Asserting the attributes is therefore
// asserting the feature.
//
// Two failure modes are worth a test. A button whose page forgot the partial is
// inert — it looks exactly like a working one and does nothing. And a button
// wired to the wrong value fails silently, in the paste, somewhere else
// entirely, which is why the short-link case is pinned to Shortener.ShortURL's
// output rather than to a prefix.

// asOperator is an htmx swap carrying the key: the only shape the console's own
// requests take, since a page navigation cannot send a header.
var asOperator = map[string]string{"Accept": "text/html", "HX-Request": "true", "X-Api-Key": testAPIKey}

// TestEveryCopyButtonHasTheScriptBehindIt is the guard that actually runs on a
// push: no Mongo, no key. Five pages render data-copy controls and each one has
// to include partials/copy separately, so the sixth page to grow a Copy button
// is the one that will forget — and nothing about the result looks broken.
func TestEveryCopyButtonHasTheScriptBehindIt(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	for _, target := range []string{
		"/clean?u=https%3A%2F%2Fexample.com%2Fp%3Futm_source%3Dx",
		"/utm?u=https%3A%2F%2Fexample.com%2Fp&utm_source=n&utm_medium=email",
		"/curl?u=https%3A%2F%2Fexample.com%2Fp",
		"/encode?v=a+b",
	} {
		body := request(t, e, http.MethodGet, target, asHTML).Body.String()
		if !strings.Contains(body, "data-copy=") {
			t.Errorf("%s renders no copy control", target)
		}
		if !strings.Contains(body, "navigator.clipboard") {
			t.Errorf("%s has copy buttons but not partials/copy; every one of them is decoration", target)
		}
	}

	// /short is the odd one: with no shortener wired it answers 503 and renders
	// no button at all, but it must still ship the script, because the include
	// sits outside {{if .Disabled}} and a configured server shares the template.
	rec := request(t, e, http.MethodGet, "/short", asHTML)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /short with no shortener = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "navigator.clipboard") {
		t.Error("the console does not ship partials/copy when short links are off")
	}
}

// TestCopyOffersTheWholeShortURL covers the value itself, at both places a short
// link is rendered — freshly created, and fetched back from the list a week
// later — plus the refusal that goes with the second. Live, because both come
// from storage.
//
// A custom slug, so the URL the markup must carry is known up front and the
// assertion is exact rather than a prefix match.
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

	dead, err := short.Create(ctx, "https://example.com/dead", linktools.CreateOptions{})
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
	// The full URL, not the bare code the table prints: a code on the clipboard
	// pastes as nonsense.
	if !strings.Contains(html, want) {
		t.Errorf("live alias row does not offer %s to the clipboard:\n%s", want, html)
	}
	if got := `data-copy="` + short.ShortURL(dead.Code) + `"`; strings.Contains(html, got) {
		t.Error("a revoked alias is still offered to the clipboard; a dead link fails silently in the paste")
	}
	// The list never auto-copies: ten rows cannot each claim the clipboard, and
	// nothing in it was just created.
	if strings.Contains(html, "data-copy-auto") {
		t.Error("the alias list auto-copies a row; only a freshly created link may do that")
	}
}
