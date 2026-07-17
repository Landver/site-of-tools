package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/tools/botcheck"
	"github.com/Landver/site-of-tools/tools/iptools"
	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/shared"
)

// fakeLooker implements botcheck.Looker so the handler is tested without the real
// IP databases. It ignores the IP and returns a canned result.
type fakeLooker struct {
	res *iptools.Result
	err error
}

func (f fakeLooker) Lookup(string) (*iptools.Result, error) { return f.res, f.err }

// newTestApp builds a bare echo with the real (embedded) templates and the given
// Looker. Embedded FS is used so it works regardless of the test's cwd.
func newTestApp(svc botcheck.Looker) *echo.Echo {
	r := platform.NewRenderer(false, nil,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: botcheck.Templates, DevDir: "tools/botcheck/templates"},
	)
	e := echo.New()
	e.Renderer = r
	botcheck.Register(e, svc)
	return e
}

func post(app *echo.Echo, target, body string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	return rec
}

func get(app *echo.Echo, target string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	return rec
}

func TestCheckJSONFlagsWebdriver(t *testing.T) {
	rec := post(newTestApp(fakeLooker{}), "/check", `{"webdriver":true}`, map[string]string{"Accept": "application/json"})
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	var rep botcheck.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rep.Verdict != "bot" {
		t.Errorf("verdict = %q, want bot (score=%d)", rep.Verdict, rep.Score)
	}
	var found bool
	for _, c := range rep.Checks {
		if c.ID == "webdriver" {
			found = c.Triggered
		}
	}
	if !found {
		t.Errorf("webdriver check should be triggered in:\n%s", rec.Body.String())
	}
}

func TestCheckBrowserGetsFragment(t *testing.T) {
	rec := post(newTestApp(fakeLooker{}), "/check", `{}`, map[string]string{"Accept": "text/html"})
	body := rec.Body.String()
	if strings.Contains(body, "<html") {
		t.Errorf("POST /check should return a fragment, not a full page:\n%s", body)
	}
	if !strings.Contains(body, "/100") {
		t.Errorf("fragment should contain the score panel (/100):\n%s", body)
	}
}

func TestCheckPlainCurlGetsJSON(t *testing.T) {
	rec := post(newTestApp(fakeLooker{}), "/check", `{}`, map[string]string{"Accept": "*/*"})
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("plain curl content-type = %q, want application/json", ct)
	}
}

func TestCheckBadPayloadIs400(t *testing.T) {
	rec := post(newTestApp(fakeLooker{}), "/check", `{not json`, map[string]string{"Accept": "application/json"})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad payload code = %d, want 400", rec.Code)
	}
}

func TestIndexBrowserGetsFullPage(t *testing.T) {
	rec := get(newTestApp(fakeLooker{}), "/", map[string]string{"Accept": "text/html"})
	body := rec.Body.String()
	if !strings.Contains(body, "<html") {
		t.Errorf("browser GET / should be a full page:\n%s", body)
	}
	for _, want := range []string{"Bot check", "your request"} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
}

func TestIndexSetsAcceptCH(t *testing.T) {
	rec := get(newTestApp(fakeLooker{}), "/", map[string]string{"Accept": "text/html"})
	if ch := rec.Header().Get("Accept-CH"); !strings.Contains(ch, "Sec-CH-UA-Platform") {
		t.Errorf("Accept-CH = %q, want it to request Sec-CH-UA-Platform", ch)
	}
}

func TestIndexCurlGetsServerOnlyScore(t *testing.T) {
	// A datacenter IP should surface in the server-only score, even with no client
	// fingerprint. A normal browser UA avoids the empty-UA bot signal so we isolate
	// the datacenter check.
	looker := fakeLooker{res: &iptools.Result{
		CountryCode: "TR", Timezone: "Europe/Istanbul",
		Proxy: &iptools.Proxy{IsProxy: true, ProxyType: "DCH"},
	}}
	rec := get(newTestApp(looker), "/", map[string]string{"Accept": "application/json", "User-Agent": chromeMacUA})
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("content-type = %q, want application/json", ct)
	}
	var rep botcheck.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var dc botcheck.Check
	for _, c := range rep.Checks {
		if c.ID == "datacenter_ip" {
			dc = c
		}
	}
	if !dc.Triggered {
		t.Errorf("datacenter_ip should fire for a DCH proxy IP:\n%s", rec.Body.String())
	}
	// Client checks must be skipped on a server-only request.
	for _, c := range rep.Checks {
		if c.ID == "webdriver" && !c.Skipped {
			t.Errorf("webdriver should be skipped on server-only GET /")
		}
	}
}

func TestPlaceholderTimezoneCleanedThroughHandler(t *testing.T) {
	// A localhost/unknown IP yields IP2Location's "-" timezone; the handler must
	// clean it so a real browser timezone doesn't spuriously trip tz_mismatch.
	looker := fakeLooker{res: &iptools.Result{CountryCode: "-", Timezone: "-"}}
	body := `{"browserTZ":"Europe/Moscow","navMainUA":"` + chromeMacUA + `"}`
	rec := post(newTestApp(looker), "/check", body, map[string]string{"Accept": "application/json", "User-Agent": chromeMacUA})
	var rep botcheck.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, c := range rep.Checks {
		if c.ID == "tz_mismatch" && c.Triggered {
			t.Errorf("tz_mismatch fired against a '-' placeholder timezone:\n%s", rec.Body.String())
		}
	}
}

func TestCheckTimezoneMismatchFiresThroughHandler(t *testing.T) {
	// Positive end-to-end counterpart to TestPlaceholderTimezoneCleaned: proves the
	// handler actually wires res.Timezone -> sig.IPTimezone AND stamps sig.Now (a
	// zero Now would make ianaOffset return ok=false and silently suppress the check).
	// America/Los_Angeles is UTC-8/-7 year-round, never +03:00, so this is DST- and
	// wall-clock-independent despite addServerSignals using a live time.Now().
	looker := fakeLooker{res: &iptools.Result{Timezone: "+03:00"}}
	body := `{"browserTZ":"America/Los_Angeles"}`
	rec := post(newTestApp(looker), "/check", body, map[string]string{"Accept": "application/json", "User-Agent": chromeMacUA})
	var rep botcheck.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var tz botcheck.Check
	for _, c := range rep.Checks {
		if c.ID == "tz_mismatch" {
			tz = c
		}
	}
	if !tz.Triggered {
		t.Errorf("tz_mismatch should fire when browser TZ offset ≠ IP TZ offset:\n%s", rec.Body.String())
	}
}

func TestCheckSoftSignalsRenderAsFlagged(t *testing.T) {
	// Soft signals never dock points on their own, so each renders as "flagged"
	// (no misleading per-row "−8"), and the single cluster deduction line shows
	// only once enough of them fire. This body trips several soft signals but no
	// hard/consistency ones, so the fragment must carry both.
	body := `{"navMainUA":"` + chromeMacUA + `","plugins":0,"screenW":800,"screenH":600,"availW":800,"availH":600}`
	rec := post(newTestApp(fakeLooker{}), "/check", body, map[string]string{"Accept": "text/html", "User-Agent": chromeMacUA})
	frag := rec.Body.String()
	if !strings.Contains(frag, "flagged") {
		t.Errorf("a flagged soft signal should render as \"flagged\":\n%s", frag)
	}
	if !strings.Contains(frag, "weak signals counted together") {
		t.Errorf("3+ soft signals should show the single cluster line:\n%s", frag)
	}
}

func TestCheckDatacenterPlusHeadlessIsBot(t *testing.T) {
	// End-to-end: a headless fingerprint from a datacenter IP → bot, in JSON.
	looker := fakeLooker{res: &iptools.Result{Proxy: &iptools.Proxy{IsProxy: true, ProxyType: "DCH"}}}
	body := `{"webdriver":true,"cdpMainThread":true,"cdpWorker":true,"webglRenderer":"Google SwiftShader"}`
	rec := post(newTestApp(looker), "/check", body, map[string]string{"Accept": "application/json", "User-Agent": chromeMacUA})
	var rep botcheck.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rep.Verdict != "bot" || rep.Score != 0 {
		t.Errorf("headless+datacenter: score=%d verdict=%q, want 0/bot", rep.Score, rep.Verdict)
	}
}
