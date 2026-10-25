package tests

import (
	"cmp"
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/tools/linktools"
)

// Each test pins one UX promise through the real router and templates.

// samplePages carry "Try sample" chips. A chip fills a field of its own form and submits it,
// as the handler in shared/templates/partials/head.html does.
var samplePages = []string{"/", "/clean", "/diff", "/curl", "/utm", "/encode", "/extract", "/headers"}

var (
	formBlock = regexp.MustCompile(`(?s)<form\b([^>]*)>(.*?)</form>`)
	formAttr  = regexp.MustCompile(`\b(method|action)="([^"]*)"`)
	fieldName = regexp.MustCompile(`<(?:input|textarea)\b[^>]*\bname="([^"]+)"`)
	chipTag   = regexp.MustCompile(`<button\b[^>]*\bdata-sample[^>]*>`)
	chipValue = regexp.MustCompile(`\bdata-sample(?:-([a-z]+))?="([^"]*)"`)
)

type sampleRequest struct{ method, target, body string }

// sampleRequests is the request each chip on a page submits; a data-sample without a field name fills the
// form's first field. The live headers fetch dials out, so its chips are left out.
func sampleRequests(body string) []sampleRequest {
	var out []sampleRequest
	for _, f := range formBlock.FindAllStringSubmatch(body, -1) {
		method, action := http.MethodGet, ""
		for _, a := range formAttr.FindAllStringSubmatch(f[1], -1) {
			if a[1] == "method" {
				method = strings.ToUpper(a[2])
			} else {
				action = a[2]
			}
		}
		first := fieldName.FindStringSubmatch(f[2])
		if first == nil || (action == "/headers" && method == http.MethodGet) {
			continue
		}
		for _, chip := range chipTag.FindAllString(f[2], -1) {
			v := url.Values{}
			for _, m := range chipValue.FindAllStringSubmatch(chip, -1) {
				v.Set(cmp.Or(m[1], first[1]), html.UnescapeString(m[2]))
			}
			if method == http.MethodPost {
				out = append(out, sampleRequest{method, action, v.Encode()})
			} else {
				out = append(out, sampleRequest{method, action + "?" + v.Encode(), ""})
			}
		}
	}
	return out
}

// TestHeadingIsThePageNameAlone: the suite name belongs on the <title>, not the <h1>.
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

// Every sample chip lands on a result, not an error.
func TestEverySampleLoadsAResult(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	for _, page := range samplePages {
		body := request(t, e, http.MethodGet, page, asHTML).Body.String()
		if !strings.Contains(body, "Try sample") {
			t.Errorf("%s: the page offers no samples", page)
		}
		for _, r := range sampleRequests(body) {
			req := httptest.NewRequest(r.method, r.target, strings.NewReader(r.body))
			req.Header.Set("Accept", "text/html")
			if r.body != "" {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `class="alert-error"`) {
				t.Errorf("%s: sample %s %.120s = %d, want a result:\n%s", page, r.method, r.target+r.body, rec.Code, truncate(rec.Body.String()))
			}
		}
	}
}

// An emptied live box swaps in an empty result, not an error.
func TestClearingTheInputClearsTheResult(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	for _, target := range []string{"/?u=", "/clean?u=", "/encode?v=", "/utm?u=", "/diff?a=&b="} {
		rec := request(t, e, http.MethodGet, target, asHTMX)
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `class="alert-error"`) {
			t.Errorf("%s as htmx = %d, want an empty result:\n%s", target, rec.Code, truncate(rec.Body.String()))
		}
	}
}

// One rule's reason prints once, every parameter is still named, and the JSON keeps one entry each.
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

// TestUTMFoldOpensForAValue: the fold never hides a value the URL carries.
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

// Live forms replace the URL rather than push one per pause; Trace, which waits for its button, pushes.
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

// Both send the list's reload event, to htmx only. Live, because both need storage.
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

	link, err := short.Create(ctx, linktools.CreateRequest{URL: "https://example.com/revoke-me"}, "")
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

// A curl command or text with links gets a POST button: a link would put a command's cookies in a URL.
func TestWrongPasteIsSentToTheRightPage(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	for _, tc := range []struct{ page, input, action, field string }{
		{"/?u=", "curl 'https://api.example.com/x' -H 'cookie: s=1'", "/curl", "curl"},
		{"/clean?u=", `<a href="https://example.com/">x</a>`, "/extract", "text"},
		{"/utm?u=", "see https://a.example and https://b.example", "/extract", "text"},
		{"/?u=", "https://a.example/\nhttps://b.example/", "/extract", "text"},
		{"/diff?b=https%3A%2F%2Fexample.com%2F&a=", "curl https://example.com/ -H 'cookie: s=1'", "/curl", "curl"},
		{"/curl?u=", "curl https://example.com/ -b 's=1'", "/curl", "curl"},
	} {
		target := tc.page + urlEscape(tc.input)
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

// The wrong-tool check never refuses one URL, even with a ?href=, a raw space or a URL in its query.
func TestOneURLIsNeverSentAway(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	for _, raw := range []string{
		"https://www.facebook.com/plugins/share_button.php?href=https%3A%2F%2Fexample.com%2F&layout=button",
		"https://click.example.com/track?href=https%3A%2F%2Fexample.com%2Fsale&utm_source=mail",
		"https://example.com/r?pagehref=1",
		"https://example.com/My Document.pdf",
		"https://example.com/login?next=https://other.example/x",
		"https://example.com/?q=red shoes&next=https://other.example/",
	} {
		if got := linktools.WrongTool(raw); got != "" {
			t.Errorf("WrongTool(%q) = %q, want \"\"", raw, got)
		}
		for _, page := range []string{"/", "/clean", "/utm"} {
			rec := request(t, e, http.MethodGet, page+"?u="+urlEscape(raw), asJSON)
			if rec.Code != http.StatusOK {
				t.Errorf("%s?u=%s = %d, want 200 (body %s)", page, raw, rec.Code, truncate(rec.Body.String()))
			}
		}
	}

	// The space is let through, and Inspect says what is wrong with it.
	var in linktools.Inspection
	rec := request(t, e, http.MethodGet, "/?u="+urlEscape("https://example.com/My Document.pdf"), asJSON)
	if err := json.Unmarshal(rec.Body.Bytes(), &in); err != nil {
		t.Fatalf("not an Inspection: %v (body %s)", err, rec.Body)
	}
	if !hasNote(in.Notes, linktools.SevWarn, "Unencoded spaces") {
		t.Errorf("no Unencoded spaces note: %+v", in.Notes)
	}
}

// TestCurlPasteNeverRidesInAURL: the paste form posts; GET ?curl= still works.
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
	if !strings.Contains(rec.Body.String(), `Scheme <span class="font-mono text-strong">https</span>`) {
		t.Error("POST /curl did not inspect the command's URL")
	}
}

// A statement in an Alpine attribute (try/catch, var, for) silently disables the binding.
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

// A default submit sends nothing for unwrap, so a shared Clean URL stays clean.
func TestCleanFormSendsUnwrapOnlyWhenTurnedOff(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	page := request(t, e, http.MethodGet, "/clean", asHTML).Body.String()
	if strings.Contains(page, `type="hidden" name="unwrap"`) {
		t.Error("the Clean form still carries a hidden unwrap companion")
	}
	if !strings.Contains(page, `name="unwrap" value="false"`) {
		t.Error("the unwrap control does not send unwrap=false when ticked")
	}
	off := request(t, e, http.MethodGet, "/clean?unwrap=false&u=https%3A%2F%2Fexample.com%2F", asHTML).Body.String()
	if !regexp.MustCompile(`name="unwrap" value="false"[^>]*checked`).MatchString(off) {
		t.Error("with unwrap=false the box does not show as ticked")
	}
}

// Vary and no-store keep Back from showing a bare cached fragment; an htmx error is never a history entry.
func TestFragmentsAreNeverCachedAsPages(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	page := request(t, e, http.MethodGet, inspectTarget, asHTML)
	vary := strings.Join(page.Header().Values("Vary"), ",")
	for _, want := range []string{"HX-Request", "Accept"} {
		if !strings.Contains(vary, want) {
			t.Errorf("Vary = %q, missing %s", vary, want)
		}
	}
	frag := request(t, e, http.MethodGet, inspectTarget, asHTMX)
	if got := frag.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("fragment Cache-Control = %q, want no-store", got)
	}
	bad := request(t, e, http.MethodGet, "/?u=http%3A%2F%2F%5B", asHTMX)
	if bad.Code != http.StatusBadRequest || bad.Header().Get("HX-Push-Url") != "false" {
		t.Errorf("htmx error = %d with HX-Push-Url %q; an error must not become a history entry", bad.Code, bad.Header().Get("HX-Push-Url"))
	}

	// The answers that return early, before the shared reply, vary the same.
	early := map[string]*httptest.ResponseRecorder{}
	for _, target := range []string{"/clean?u=", "/diff?a=x", "/encode?v=", "/extract"} {
		early[target] = request(t, e, http.MethodGet, target, asJSON)
	}
	early["/clean/rules (304)"] = request(t, e, http.MethodGet, "/clean/rules",
		map[string]string{"Accept": "application/json", "If-None-Match": `"` + linktools.RulesVersion + `"`})
	for target, rec := range early {
		if v := strings.Join(rec.Header().Values("Vary"), ","); !strings.Contains(v, "Accept") || !strings.Contains(v, "HX-Request") {
			t.Errorf("%s (%d): Vary = %q", target, rec.Code, v)
		}
	}
}

// TestEmptyTraceCostsNothing: a trace with no URL spends no trace budget.
func TestEmptyTraceCostsNothing(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)
	for i := 0; i < 12; i++ {
		if rec := request(t, e, http.MethodGet, "/trace?ua=googlebot", asHTMX); rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d with no URL was rate-limited", i+1)
		}
	}
}

// TestShortRefusesNonsenseTTLs: negative and sub-minute TTLs are refused.
func TestShortRefusesNonsenseTTLs(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, offlineShortener(t))
	for _, ttl := range []string{"-5h", "1ms", "30s"} {
		req := httptest.NewRequest(http.MethodPost, "/short",
			strings.NewReader(`{"url":"https://example.com/x","ttl":"`+ttl+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Api-Key", testAPIKey)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "at least 1m") {
			t.Errorf("ttl %s = %d %s, want 400 asking for at least 1m", ttl, rec.Code, rec.Body)
		}
	}
}

// TestEachStateSaysWhatItIs pins the state each page leaves a reader in.
func TestEachStateSaysWhatItIs(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)
	body := func(target string, headers map[string]string) string {
		t.Helper()
		return request(t, e, http.MethodGet, target, headers).Body.String()
	}

	// UTM with nothing to tag is a prompt, not a green "Tagged URL" card.
	if b := body("/utm?u="+urlEscape("https://example.com/pricing"), asHTMX); !strings.Contains(b, "No tags yet") || strings.Contains(b, "Tagged URL") {
		t.Errorf("untagged UTM:\n%s", truncate(b))
	}
	// A site-relative path is tagged as it stands, with a warning.
	rel := request(t, e, http.MethodGet, "/utm?u="+urlEscape("/landing?x=1")+"&utm_source=n", asJSON)
	var tagged struct{ URL string }
	if err := json.Unmarshal(rel.Body.Bytes(), &tagged); err != nil || rel.Code != http.StatusOK ||
		tagged.URL != "/landing?x=1&utm_source=n" || !strings.Contains(rel.Body.String(), "Not a whole link") {
		t.Errorf("relative UTM = %d %s", rel.Code, rel.Body)
	}

	// Clean never passes a javascript: URL with a green tick.
	if b := body("/clean?u="+urlEscape("javascript:alert(1)"), asHTMX); strings.Contains(b, "Nothing to remove") || !strings.Contains(b, "Scheme is javascript, not http(s)") {
		t.Errorf("javascript: on Clean:\n%s", truncate(b))
	}

	// The Go string to the API, a sentence on the page; curl keeps its case.
	if b := body("/curl?curl="+urlEscape("curl -H 'a: b'"), asJSON); !strings.Contains(b, `"error":"no URL in that command"`) {
		t.Errorf("JSON error = %s", b)
	}
	if b := body("/curl?curl="+urlEscape("curl -H 'a: b'"), asHTMX); !strings.Contains(b, "No URL in that command.") {
		t.Errorf("page error:\n%s", truncate(b))
	}
	if b := body("/curl?curl="+urlEscape("curl example"), asHTMX); strings.Contains(b, "Curl needs") {
		t.Errorf("curl capitalised at the start of a sentence:\n%s", truncate(b))
	}

	// A bare URL in the paste box says it is the other direction's input.
	if b := body("/curl?curl="+urlEscape("https://example.com/x"), asJSON); !strings.Contains(b, "Only a URL") {
		t.Errorf("bare URL pasted as a command: %s", truncate(b))
	}
	// Each curl panel offers its own direction's samples: commands to take apart, URLs to build from.
	for _, r := range sampleRequests(body("/curl", asHTML)) {
		if (r.method == http.MethodPost) != strings.Contains(r.target+"?"+r.body, "curl=curl") {
			t.Errorf("a curl sample sits in the other panel: %s %.120s", r.method, r.target+r.body)
		}
	}

	// An htmx POST resets the address bar to the bare path.
	for path, field := range map[string]string{"/curl": "curl", "/extract": "text"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(field+"="+urlEscape("curl https://example.com/ see https://example.org/")))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "text/html")
		req.Header.Set("HX-Request", "true")
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if got := rec.Header().Get("HX-Replace-Url"); got != path {
			t.Errorf("POST %s: HX-Replace-Url = %q, want %q", path, got, path)
		}
	}

	// Reworded rules ship a new version, or the extension keeps the cached text.
	if linktools.RulesVersion == "2026-09-25" {
		t.Error("the rules text changed, so RulesVersion must move off 2026-09-25")
	}
}

// A failed key check (429, 5xx, no answer) is said in the key card, since the list stays hidden.
func TestShortKeyCheckSaysWhenItFails(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("../templates/short.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(b)
	for _, want := range []string{
		"tell('error'",       // a swap without a data-key marker
		"htmx:responseError", // an answer htmx would not swap
		"htmx:sendError",     // no answer at all
		`x-text="message ||`, // the card shows the reason
		`@input="edited()"`,  // editing the key resets the console's last answer
	} {
		if !strings.Contains(page, want) {
			t.Errorf("short.html lacks %s", want)
		}
	}
}
