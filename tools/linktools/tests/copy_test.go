package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/tools/linktools"
)

// A short link is worth nothing until it is pasted somewhere, so the console's
// job is not finished when it prints one. These tests pin the clipboard
// affordance to the ONE value that must reach it — Shortener.ShortURL's output,
// byte for byte. A copy button wired to a stale or half-built URL is worse than
// no button: it fails silently, in the paste, somewhere else entirely.
//
// The behaviour itself lives in shared/templates/partials/copy.html and is
// declarative: data-copy carries the text, data-copy-auto also copies on swap.
// Asserting the attributes is therefore asserting the feature, not the markup.

// postJSON drives a create through the real router. The existing `request`
// helper sends no body, and every interesting thing here is a response to one.
func postJSON(t *testing.T, e *echo.Echo, target, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

// asOperator is an htmx swap carrying the key — the only shape the console's
// own requests ever take, since a page navigation cannot send a header.
var asOperator = map[string]string{
	"Accept": "text/html", "HX-Request": "true", "X-Api-Key": testAPIKey,
}

// TestConsoleShipsTheCopyBehaviour: the partial is included by the page, not
// by the fragment. A fragment-level <script> would have to survive every
// reswap, and it would be absent from the very first paint. This also holds on
// a server with short links switched off, because the include sits outside the
// Disabled branch.
func TestConsoleShipsTheCopyBehaviour(t *testing.T) {
	t.Parallel()
	// 503, because this app has no shortener wired. That is the point: the
	// include has to sit outside {{if .Disabled}} or a server with the feature
	// off would serve a page whose copy buttons are inert decoration.
	rec := request(t, newLinkApp(t, nil, nil), http.MethodGet, "/short", asHTML)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /short with no shortener = %d, want 503", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"data-copy", "navigator.clipboard", "htmx:afterSwap"} {
		if !strings.Contains(body, want) {
			t.Errorf("console page is missing %q; partials/copy is not wired in", want)
		}
	}
}

// TestCreatedLinkIsOfferedToTheClipboard is the one the user hits: the fragment
// swapped in after Shorten must carry the finished URL, and must carry it
// AUTOMATICALLY. The assertion compares against the JSON representation of the
// same create, which is how a template that quietly rendered the code, the
// target or nothing at all gets caught.
func TestCreatedLinkIsOfferedToTheClipboard(t *testing.T) {
	ctx := context.Background()
	short, _ := liveShortener(t, ctx)
	e := newLinkApp(t, nil, short)

	// No "clean": the live harness deliberately leaves CleanTarget nil, and
	// stripping has nothing to do with what lands on the clipboard.
	const body = `{"url":"https://example.com/a/long/path?utm_source=x"}`

	api := postJSON(t, e, "/short", body, map[string]string{"Accept": "*/*", "X-Api-Key": testAPIKey})
	if api.Code != http.StatusCreated {
		t.Fatalf("POST /short (json) = %d, want 201 (body %s)", api.Code, api.Body)
	}
	var out struct {
		Short string `json:"short"`
	}
	if err := json.Unmarshal(api.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if out.Short == "" {
		t.Fatal("create returned no short URL")
	}

	frag := postJSON(t, e, "/short", body, asOperator)
	if frag.Code != http.StatusCreated {
		t.Fatalf("POST /short (htmx) = %d, want 201 (body %s)", frag.Code, frag.Body)
	}
	html := frag.Body.String()
	// Codes differ between the two creates, so the shape is what carries over.
	prefix := out.Short[:strings.LastIndex(out.Short, "/")+1]
	copied := copyValue.FindStringSubmatch(html)
	if copied == nil {
		t.Fatalf("created fragment has no data-copy at all:\n%s", html)
	}
	if !strings.HasPrefix(copied[1], prefix) {
		t.Errorf("data-copy = %q, want a %s… URL — the button is wired to the wrong value", copied[1], prefix)
	}
	if !strings.Contains(html, "data-copy-auto") {
		t.Error("created fragment does not copy on its own; the Shorten click is the only gesture anyone makes")
	}
	// What is copied is what is shown. An operator who declines the clipboard,
	// or whose browser refuses an unattended write, reads the URL off the page
	// instead — and would have no way to notice the two had diverged.
	shown := displayedURL.FindStringSubmatch(html)
	if shown == nil {
		t.Fatalf("created fragment does not display the URL:\n%s", html)
	}
	if shown[1] != copied[1] {
		t.Errorf("displayed %q but copied %q", shown[1], copied[1])
	}
}

var (
	copyValue    = regexp.MustCompile(`data-copy="([^"]+)"`)
	displayedURL = regexp.MustCompile(`<p[^>]*>(https?://[^<\s]+)</p>`)
)

// TestAliasRowsCopyTheWholeURLAndRevokedRowsCopyNothing covers the other half
// of the job — coming back for a link made last week — and the refusal that
// goes with it. The table renders bare codes, so the row's copy value is built
// server-side; handing out a revoked link would be worse than making somebody
// retype a live one.
func TestAliasRowsCopyTheWholeURLAndRevokedRowsCopyNothing(t *testing.T) {
	ctx := context.Background()
	short, store := liveShortener(t, ctx)
	e := newLinkApp(t, nil, short)

	live, err := short.Create(ctx, "https://example.com/live", linktools.CreateOptions{Note: "keep"})
	if err != nil {
		t.Fatalf("create live link: %v", err)
	}
	dead, err := short.Create(ctx, "https://example.com/dead", linktools.CreateOptions{Note: "gone"})
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

	// Full URL, not the bare code: a code on the clipboard pastes as nonsense.
	if want := `data-copy="` + short.ShortURL(live.Code) + `"`; !strings.Contains(html, want) {
		t.Errorf("alias row does not offer %s to the clipboard:\n%s", want, html)
	}
	if got := `data-copy="` + short.ShortURL(dead.Code) + `"`; strings.Contains(html, got) {
		t.Error("a revoked alias is still offered to the clipboard; copying a dead link fails silently in the paste")
	}
	// The list is never auto-copied — ten rows arriving cannot each claim the
	// clipboard, and nothing here was just created.
	if strings.Contains(html, "data-copy-auto") {
		t.Error("alias list auto-copies a row; only a freshly created link may do that")
	}
}
