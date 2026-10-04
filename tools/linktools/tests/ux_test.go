package tests

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/tools/linktools"
)

// The UX pass made promises a refactor could quietly break while every page
// still rendered: examples that load a result in one click, a removal table
// that names each reason once, a console list that reloads itself. Each test
// here pins one of them through the real router and templates.

// examplePages are the pages with "Try an example" chips. Trace has them too,
// but its examples dial out, so they are not followed here.
var examplePages = []string{"/", "/clean", "/diff", "/curl", "/utm", "/encode", "/extract"}

// exampleHref finds the chips' links: the hrefs after the "Try an example"
// label, which is all the empty state renders.
var exampleHref = regexp.MustCompile(`href="([^"]+)"`)

func examplesOn(t *testing.T, body string) []string {
	t.Helper()
	i := strings.Index(body, "Try an example")
	if i < 0 {
		return nil
	}
	block := body[i:]
	if end := strings.Index(block, "</div>"); end >= 0 {
		block = block[:end]
	}
	var out []string
	for _, m := range exampleHref.FindAllStringSubmatch(block, -1) {
		out = append(out, html.UnescapeString(m[1]))
	}
	return out
}

// TestHeadingIsThePageNameAlone: the suite name belongs on the <title>, where a
// tab strip needs it, and not on the <h1>, where it made every heading read
// "Clean a URL — Link Tools".
func TestHeadingIsThePageNameAlone(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	body := request(t, e, http.MethodGet, "/clean", asHTML).Body.String()
	if !strings.Contains(body, "<title>Clean a URL — Link Tools</title>") {
		t.Errorf("the <title> lost the suite name:\n%s", truncate(body))
	}
	h1 := regexp.MustCompile(`(?s)<h1[^>]*>(.*?)</h1>`).FindStringSubmatch(body)
	if h1 == nil {
		t.Fatal("no <h1> on /clean")
	}
	if got := strings.TrimSpace(h1[1]); got != "Clean a URL" {
		t.Errorf("<h1> = %q, want just the page name", got)
	}
}

// TestEveryExampleLoadsAResult follows every chip on every page and asserts it
// lands on a result, not on an error or another empty form. An example is the
// first thing a new visitor clicks; one that 400s is the whole first
// impression.
func TestEveryExampleLoadsAResult(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	for _, page := range examplePages {
		hrefs := examplesOn(t, request(t, e, http.MethodGet, page, asHTML).Body.String())
		if len(hrefs) == 0 {
			t.Errorf("%s: an empty page offers no examples", page)
			continue
		}
		for _, href := range hrefs {
			if !strings.HasPrefix(href, page) && !(page == "/" && strings.HasPrefix(href, "/?")) {
				t.Errorf("%s: example %q leaves the page it was offered on", page, href)
				continue
			}
			rec := request(t, e, http.MethodGet, href, asHTML)
			if rec.Code != http.StatusOK {
				t.Errorf("%s: example %q = %d, want 200", page, href, rec.Code)
				continue
			}
			body := rec.Body.String()
			if strings.Contains(body, "alert-error") {
				t.Errorf("%s: example %q renders an error:\n%s", page, href, truncate(body))
			}
			if examplesOn(t, body) != nil {
				t.Errorf("%s: example %q renders the empty state again, not a result", page, href)
			}
		}
	}
}

// TestClearingTheInputBringsTheExamplesBack: the pages are live, so emptying
// the box sends an htmx request with an empty value, and the answer has to be
// the empty state again rather than a blank area or an error.
func TestClearingTheInputBringsTheExamplesBack(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	for _, target := range []string{"/?u=", "/clean?u=", "/encode?v=", "/utm?u=", "/diff?a=&b="} {
		rec := request(t, e, http.MethodGet, target, asHTMX)
		if rec.Code != http.StatusOK {
			t.Errorf("%s as htmx = %d, want 200", target, rec.Code)
			continue
		}
		if !strings.Contains(rec.Body.String(), "Try an example") {
			t.Errorf("%s as htmx did not swap the examples back in:\n%s", target, truncate(rec.Body.String()))
		}
	}
}

// TestCleanNamesEachReasonOnce: three utm_ parameters are one rule's decision,
// and printing its paragraph three times read like three problems. The table
// still names every parameter it removed; only the reason is folded. The JSON
// keeps one entry per parameter.
func TestCleanNamesEachReasonOnce(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)
	target := "/clean?u=" + urlEscape("https://example.com/p?utm_source=a&utm_medium=b&utm_campaign=c&id=1")

	body := request(t, e, http.MethodGet, target, asHTML).Body.String()
	for _, key := range []string{"utm_source", "utm_medium", "utm_campaign"} {
		if !strings.Contains(body, ">"+key+"<") {
			t.Errorf("the removal table does not name %s", key)
		}
	}
	if n := strings.Count(body, ">utm_*<"); n != 1 {
		t.Errorf("the utm_* rule is printed %d times, want once for all three parameters", n)
	}

	rec := request(t, e, http.MethodGet, target, asJSON)
	if n := strings.Count(rec.Body.String(), `"rule":`); n != 3 {
		t.Errorf("the JSON carries %d removals, want 3: grouping is for the page only", n)
	}
}

// TestUTMFoldOpensForAValue: term and content are folded away because most
// links have neither, but a fold that hid a value the URL actually carries
// would hide what the page is building.
func TestUTMFoldOpensForAValue(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)
	open := regexp.MustCompile(`<details class="mt-3 text-sm" open>`)

	base := "/utm?u=" + urlEscape("https://example.com/") + "&utm_source=n"
	if body := request(t, e, http.MethodGet, base, asHTML).Body.String(); open.MatchString(body) {
		t.Error("the utm_term/utm_content fold is open with neither set")
	}
	if body := request(t, e, http.MethodGet, base+"&utm_term=shoes", asHTML).Body.String(); !open.MatchString(body) {
		t.Error("the fold stays closed over a utm_term value")
	}
}

// TestLiveFormsKeepTheHistoryClean: the parsing pages answer as you type, and
// every pause pushing a history entry would make the back button replay the
// typing one keystroke at a time. Trace, which waits for its button, pushes.
func TestLiveFormsKeepTheHistoryClean(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	for _, page := range []string{"/", "/clean", "/diff", "/utm", "/encode"} {
		body := request(t, e, http.MethodGet, page, asHTML).Body.String()
		if !strings.Contains(body, `hx-trigger="submit, input delay:`) {
			t.Errorf("%s: the form does not update as you type", page)
		}
		if strings.Contains(body, `hx-push-url="true"`) {
			t.Errorf("%s: a live form pushes history on every pause", page)
		}
		if !strings.Contains(body, `hx-replace-url="true"`) {
			t.Errorf("%s: the address bar does not follow the result", page)
		}
	}
}

// TestCreateAndRevokeReloadTheList: the list reloads on an htmx event the
// server sends, so a revoked link stops looking alive without a manual reload.
// JSON callers never see the header. Live, because both need storage.
func TestCreateAndRevokeReloadTheList(t *testing.T) {
	ctx := context.Background()
	short, _ := liveShortener(t, ctx)
	e := newLinkApp(t, nil, short)

	post := func(headers map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/short", strings.NewReader(`{"url":"https://example.com/reload"}`))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}

	rec := post(asOperator)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /short (htmx) = %d (body %s)", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("HX-Trigger"); got != "link-list-changed" {
		t.Errorf("create sent HX-Trigger %q, want link-list-changed", got)
	}

	api := post(map[string]string{"Accept": "application/json", "X-Api-Key": testAPIKey})
	if api.Code != http.StatusCreated {
		t.Fatalf("POST /short (JSON) = %d (body %s)", api.Code, api.Body)
	}
	if got := api.Header().Get("HX-Trigger"); got != "" {
		t.Errorf("a JSON create carries HX-Trigger %q; the event is for the console only", got)
	}

	link, err := short.Create(ctx, "https://example.com/revoke-me", linktools.CreateOptions{})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	rev := request(t, e, http.MethodDelete, "/short/"+link.Code, asOperator)
	if rev.Code != http.StatusOK {
		t.Fatalf("DELETE /short/%s = %d (body %s)", link.Code, rev.Code, rev.Body)
	}
	if got := rev.Header().Get("HX-Trigger"); got != "link-list-changed" {
		t.Errorf("revoke sent HX-Trigger %q, want link-list-changed", got)
	}
}

// TestWrongPasteIsSentToTheRightPage: a curl command or a block of text pasted
// where one URL goes gets a sentence saying what it looks like and a button to
// the page it belongs on, instead of "first path segment in URL cannot contain
// colon". The button is a POST form: the input may be a command with cookies
// in it, and a link would put them in a URL.
func TestWrongPasteIsSentToTheRightPage(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	for _, tc := range []struct{ page, input, action, field string }{
		{"/", "curl 'https://api.example.com/x' -H 'cookie: s=1'", "/curl", "curl"},
		{"/clean", `<a href="https://example.com/">x</a>`, "/extract", "text"},
		{"/utm", "see https://a.example and https://b.example", "/extract", "text"},
	} {
		target := tc.page + "?u=" + urlEscape(tc.input)
		rec := request(t, e, http.MethodGet, target, asHTMX)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", target, rec.Code)
			continue
		}
		body := rec.Body.String()
		if !strings.Contains(body, `<form method="post" action="`+tc.action+`"`) {
			t.Errorf("%s: no POST form to %s:\n%s", target, tc.action, truncate(body))
		}
		if !strings.Contains(body, `name="`+tc.field+`"`) {
			t.Errorf("%s: the form does not carry the input as %q", target, tc.field)
		}
	}
}

// TestCurlPasteNeverRidesInAURL: the paste form posts, and the route answers a
// POST with the full result, so a DevTools command's cookies stay out of the
// address bar, the history and the proxy logs. GET ?curl= still works for the
// API.
func TestCurlPasteNeverRidesInAURL(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	page := request(t, e, http.MethodGet, "/curl", asHTML).Body.String()
	form := regexp.MustCompile(`(?s)<form[^>]*>\s*<textarea name="curl"`).FindString(page)
	if form == "" {
		t.Fatal("no paste form found on /curl")
	}
	if !strings.Contains(page, `<form method="post" action="/curl" hx-post="/curl"`) {
		t.Error("the paste form does not POST")
	}

	req := httptest.NewRequest(http.MethodPost, "/curl",
		strings.NewReader("curl="+urlEscape("curl 'https://api.example.com/v1/x?id=1' -H 'cookie: s=1'")))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /curl = %d (body %s)", rec.Code, truncate(rec.Body.String()))
	}
	if !strings.Contains(rec.Body.String(), "https://api.example.com/v1/x?id=1") {
		t.Error("POST /curl did not take the command apart")
	}
}

// TestAlpineAttributesAreExpressions: Alpine evaluates x-init, x-data and
// @event values as JavaScript EXPRESSIONS, so a statement there (try/catch,
// var, a for loop) is a syntax error that logs once and disables the whole
// binding. It happened: the console's key was silently never read or saved,
// with every page still rendering perfectly. Statements belong in a script, as
// short.html's linkKey() does.
func TestAlpineAttributesAreExpressions(t *testing.T) {
	t.Parallel()
	files, _ := filepath.Glob("../templates/*.html")
	partials, _ := filepath.Glob("../../../shared/templates/partials/*.html")
	files = append(files, partials...)
	if len(files) == 0 {
		t.Fatal("no templates found; the test is looking in the wrong place")
	}
	attr := regexp.MustCompile(`\s(x-init|x-data|x-effect|@[\w.:-]+|x-on:[\w.:-]+)="\s*(try|var|let|const|for|while)\b`)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range attr.FindAllStringSubmatch(string(b), -1) {
			t.Errorf("%s: %s starts with the statement %q; Alpine needs an expression there", filepath.Base(f), m[1], m[2])
		}
	}
}
