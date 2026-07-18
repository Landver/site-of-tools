package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/shared"
	"github.com/Landver/site-of-tools/tools/botcheck"
	"github.com/Landver/site-of-tools/tools/iptools"
)

// fakeLooker implements botcheck.Looker so the handler is tested without the real
// IP databases. It ignores the IP and returns a canned result.
type fakeLooker struct {
	res *iptools.Result
	err error
}

func (f fakeLooker) Lookup(string) (*iptools.Result, error) { return f.res, f.err }

// newTestApp builds a bare echo with the real (embedded) templates and the given
// Looker. Embedded FS is used so it works regardless of the test's cwd. The
// corpus is nil (Mongo off) — the corpus tests live in corpus_test.go.
func newTestApp(svc botcheck.Looker) *echo.Echo {
	r := platform.NewRenderer(false, nil,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: botcheck.Templates, DevDir: "tools/botcheck/templates"},
	)
	e := echo.New()
	e.Renderer = r
	botcheck.Register(e, svc, nil)
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

func TestIndexEnrichesConnCard(t *testing.T) {
	// G38/G44 wiring: the browser page's "your request" card picks up the ASN +
	// proxy attribution from the IP lookup (the shared conn partial renders those
	// rows only when enriched via WithNetwork).
	looker := fakeLooker{res: &iptools.Result{
		ASN: "14061", ASName: "DigitalOcean, LLC",
		Proxy: &iptools.Proxy{IsProxy: true, ProxyType: "VPN", Provider: "NordVPN"},
	}}
	rec := get(newTestApp(looker), "/", map[string]string{"Accept": "text/html"})
	body := rec.Body.String()
	for _, want := range []string{"AS14061 (DigitalOcean, LLC)", "VPN — NordVPN"} {
		if !strings.Contains(body, want) {
			t.Errorf("enriched conn card missing %q:\n%s", want, body)
		}
	}
	// A lookup without network data renders no ASN/proxy rows (unchanged card).
	rec = get(newTestApp(fakeLooker{}), "/", map[string]string{"Accept": "text/html"})
	if body := rec.Body.String(); strings.Contains(body, "<dt>ASN</dt>") || strings.Contains(body, "<dt>Proxy</dt>") {
		t.Errorf("an empty lookup must render no network rows:\n%s", body)
	}
}

func TestIndexRendersHistoryCard(t *testing.T) {
	// G46: the "your recent checks" card ships in the page shell — hidden until the
	// collector fills it from the visitor's own localStorage, with copy stating the
	// list never leaves the browser. The list itself is client-rendered JS (no JS
	// harness here); this pins the card's presence, its initial hidden state, and
	// the local-only disclosure.
	rec := get(newTestApp(fakeLooker{}), "/", map[string]string{"Accept": "text/html"})
	body := rec.Body.String()
	for _, want := range []string{
		`id="botcheck-history" hidden`, "your recent checks",
		"only in your browser's local storage", "never sent to",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("index page missing %q for the G46 history card:\n%s", want, body)
		}
	}
}

func TestIndexCurlGetsServerOnlyScore(t *testing.T) {
	// A datacenter IP should surface in the server-only score, even with no client
	// fingerprint. A normal browser UA avoids the empty-UA bot signal so we isolate
	// the datacenter check. The request carries the headers a real browser always
	// sends (Accept-Encoding, Accept-Language, Sec-Fetch-Mode) so the G06 presence
	// checks stay quiet too; Accept must stay application/json (the JSON path),
	// which accept_nav_mismatch still flags — a single soft signal, under the
	// cluster threshold, so it costs nothing.
	looker := fakeLooker{res: &iptools.Result{
		CountryCode: "TR", Timezone: "Europe/Istanbul",
		Proxy: &iptools.Proxy{IsProxy: true, ProxyType: "DCH"},
	}}
	rec := get(newTestApp(looker), "/", map[string]string{
		"Accept": "application/json", "User-Agent": chromeMacUA,
		"Accept-Encoding": "gzip, deflate, br", "Accept-Language": "en-US,en;q=0.9",
		"Sec-Fetch-Mode": "navigate",
	})
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

func TestCheckQuickWinSignalsThroughHandler(t *testing.T) {
	// A Chrome UA whose feature-detected engine is gecko, whose productSub is Gecko's
	// constant, and whose userAgentData Chromium version disagrees with the UA. Proves
	// the new client fields — including the nested uaData.fullVersionList array — bind
	// from JSON and their rules fire end-to-end through the real handler.
	body := `{"navMainUA":"` + chromeMacUA + `","engine":"gecko","productSub":"20100101",` +
		`"uaData":{"platform":"macOS","fullVersionList":[{"brand":"Chromium","version":"120.0.0.0"}]}}`
	rec := post(newTestApp(fakeLooker{}), "/check", body, map[string]string{"Accept": "application/json", "User-Agent": chromeMacUA})
	var rep botcheck.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, id := range []string{"engine_ua_mismatch", "productsub_mismatch", "ua_chrome_version_mismatch"} {
		var c botcheck.Check
		for _, got := range rep.Checks {
			if got.ID == id {
				c = got
			}
		}
		if !c.Triggered {
			t.Errorf("%s should fire through the handler:\n%s", id, rec.Body.String())
		}
	}
}

func TestCheckGoodBotThroughHandler(t *testing.T) {
	// G36 end-to-end: a verified crawler (Applebot from Apple's AS714) → "good-bot"
	// verdict + a Bot identity in the JSON. Proves addServerSignals wires res.ASN
	// through to the corroboration. GET / is the server-only path a real crawler hits.
	const applebot = "Mozilla/5.0 (Applebot/0.1; +http://www.apple.com/go/applebot)"
	looker := fakeLooker{res: &iptools.Result{ASN: "714", ASName: "Apple Inc."}}
	rec := get(newTestApp(looker), "/", map[string]string{"Accept": "application/json", "User-Agent": applebot})
	var rep botcheck.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rep.Verdict != "good-bot" {
		t.Errorf("verdict = %q, want good-bot (score %d):\n%s", rep.Verdict, rep.Score, rec.Body.String())
	}
	if rep.Bot == nil || rep.Bot.Name != "Applebot" || !rep.Bot.Verified {
		t.Errorf("Bot = %+v, want verified Applebot", rep.Bot)
	}
}

func TestCheckSpoofedGoodBotThroughHandler(t *testing.T) {
	// The same Applebot UA from a NON-Apple network is recognised but NOT verified, so
	// it stays a bot — the no-evasion property, proven end-to-end through the handler.
	const applebot = "Mozilla/5.0 (Applebot/0.1; +http://www.apple.com/go/applebot)"
	looker := fakeLooker{res: &iptools.Result{ASN: "14061", ASName: "DigitalOcean, LLC"}}
	rec := get(newTestApp(looker), "/", map[string]string{"Accept": "application/json", "User-Agent": applebot})
	var rep botcheck.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rep.Verdict == "good-bot" {
		t.Errorf("verdict = good-bot for an off-network Applebot claim — must not verify a spoof")
	}
	if rep.Bot == nil || rep.Bot.Verified {
		t.Errorf("Bot = %+v, want recognised-but-unverified Applebot", rep.Bot)
	}
}

func TestGoodBotResultTemplateRenders(t *testing.T) {
	// The good-bot verdict branch + the "expected" suppressed-row rendering must work.
	r := platform.NewRenderer(false, nil,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: botcheck.Templates, DevDir: "tools/botcheck/templates"},
	)
	rep := botcheck.Report{
		Score: 100, Verdict: "good-bot",
		Bot: &botcheck.BotIdentity{Name: "Applebot", Kind: "search-crawler", Verified: true},
		Checks: []botcheck.Check{{
			ID: "bot_user_agent", Label: "User-Agent is a known bot / HTTP client", Tier: "hard",
			Weight: 60, Triggered: true, Suppressed: true, Detail: "recognized Applebot",
		}},
	}
	var buf bytes.Buffer
	if err := r.Render(nil, &buf, "botcheck/result", rep); err != nil {
		t.Fatalf("render good-bot fragment: %v", err)
	}
	body := buf.String()
	for _, want := range []string{"Verified", "Applebot", "expected"} {
		if !strings.Contains(body, want) {
			t.Errorf("good-bot fragment missing %q:\n%s", want, body)
		}
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

func TestCheckGPUCoherenceThroughHandler(t *testing.T) {
	// G07/G08 end-to-end: an Apple GPU reported on a Windows Chrome UA. The
	// vendor/renderer pair is internally consistent (G07 stays silent) but the
	// GPU is impossible for the claimed OS (G08 fires) — and it proves the new
	// webglVendor field binds from JSON alongside webglRenderer through the real
	// handler.
	const winUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
	body := `{"navMainUA":"` + winUA + `","webglVendor":"Google Inc. (Apple)",` +
		`"webglRenderer":"ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)"}`
	rec := post(newTestApp(fakeLooker{}), "/check", body, map[string]string{"Accept": "application/json", "User-Agent": winUA})
	var rep botcheck.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var gpuOS, vendor botcheck.Check
	for _, c := range rep.Checks {
		switch c.ID {
		case "gpu_os_mismatch":
			gpuOS = c
		case "webgl_vendor_mismatch":
			vendor = c
		}
	}
	if !gpuOS.Triggered {
		t.Errorf("gpu_os_mismatch should fire for an Apple GPU on a Windows UA:\n%s", rec.Body.String())
	}
	if vendor.Triggered {
		t.Errorf("webgl_vendor_mismatch must not fire for a consistent Apple/Apple pair:\n%s", rec.Body.String())
	}
}

func TestServiceWorkerScriptServed(t *testing.T) {
	// G03+G14: the collector registers /botcheck-sw.js as a Service Worker, so the app
	// must serve it with a JavaScript MIME type (registration refuses anything
	// else), answering messages with its navigator values + webdriver + the CDP
	// trap, and — critically — with NO fetch handler, so it can never intercept a
	// request on the origin.
	rec := get(newTestApp(fakeLooker{}), "/botcheck-sw.js", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/javascript") {
		t.Errorf("content-type = %q, want application/javascript", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{"onmessage", "webdriver", "cdp"} {
		if !strings.Contains(body, want) {
			t.Errorf("SW script should report %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "onfetch") || strings.Contains(body, `"fetch"`) {
		t.Errorf("SW script must never install a fetch handler:\n%s", body)
	}
}

func TestCheckCrossContextSignalsThroughHandler(t *testing.T) {
	// G03 end-to-end: the new cross-context fields bind from the POSTed JSON and
	// their rules fire — here a Service Worker leaking a Linux UA, platform, and
	// core count while the top frame claims macOS (the Bright Data scenario).
	body := `{"navMainUA":"` + chromeMacUA + `","hardwareCores":8,"uaData":{"platform":"macOS"},` +
		`"swUA":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",` +
		`"swPlatform":"Linux","swCores":4}`
	rec := post(newTestApp(fakeLooker{}), "/check", body, map[string]string{"Accept": "application/json", "User-Agent": chromeMacUA})
	var rep botcheck.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, id := range []string{"context_ua_mismatch", "context_platform_mismatch", "context_cores_mismatch"} {
		var c botcheck.Check
		for _, got := range rep.Checks {
			if got.ID == id {
				c = got
			}
		}
		if !c.Triggered {
			t.Errorf("%s should fire through the handler:\n%s", id, rec.Body.String())
		}
	}
}

func TestCheckDeepTamperSignalsThroughHandler(t *testing.T) {
	// G04 end-to-end: the three deep-tamper fields bind from the POSTed JSON and
	// their rules fire through the real handler. nativeToStringProxied is inverted
	// (true = bad); nativeToStringOK stays true because a stealth proxy's purpose
	// is to keep the shallow check green.
	body := `{"v":2,"nativeToStringOK":true,"nativeDescriptorsOK":false,"nativeCallNewOK":false,"nativeToStringProxied":true}`
	rec := post(newTestApp(fakeLooker{}), "/check", body, map[string]string{"Accept": "application/json", "User-Agent": chromeMacUA})
	var rep botcheck.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, id := range []string{"tostring_proxy", "native_descriptor_tamper", "native_callnew_tamper"} {
		var c botcheck.Check
		for _, got := range rep.Checks {
			if got.ID == id {
				c = got
			}
		}
		if !c.Triggered {
			t.Errorf("%s should fire through the handler:\n%s", id, rec.Body.String())
		}
	}
	for _, c := range rep.Checks {
		if c.ID == "native_tamper" && c.Triggered {
			t.Errorf("native_tamper must not fire when nativeToStringOK binds true:\n%s", rec.Body.String())
		}
	}
}

// cleanClientBody is the JSON twin of cleanChrome (botcheck_test.go): a fully
// consistent client fingerprint, so the G06 handler tests isolate the server-side
// header rules — nothing in the body trips a client rule. Europe/Moscow is used
// because it keeps UTC+3 year-round (no DST), so tzOffset -180 stays consistent
// with the handler's live time.Now() stamp whatever the wall clock says.
var cleanClientBody = `{"v":3,"nativeToStringOK":true,"hasChromeObject":true,` +
	`"nativeDescriptorsOK":true,"nativeCallNewOK":true,"nativeToStringProxied":false,` +
	`"navMainUA":"` + chromeMacUA + `","navWorkerUA":"` + chromeMacUA + `","navIframeUA":"` + chromeMacUA + `",` +
	`"languages":["en-US","en"],"language":"en-US","vendor":"Google Inc.",` +
	`"appVersion":"` + strings.TrimPrefix(chromeMacUA, "Mozilla/") + `",` +
	`"webglRenderer":"ANGLE (Apple, Apple M1, OpenGL 4.1)","plugins":3,` +
	`"screenW":1920,"screenH":1080,"availW":1920,"availH":1040,"colorDepth":30,` +
	`"outerW":1680,"innerW":1400,"hardwareCores":8,"deviceMemory":8,` +
	`"browserTZ":"Europe/Moscow","tzOffset":-180,` +
	`"canvasSupported":true,"canvasStable":true,"canvasBlank":false,` +
	`"brands":["Chromium","Google Chrome","Not.A/Brand"],` +
	`"uaData":{"platform":"macOS","fullVersionList":[` +
	`{"brand":"Chromium","version":"125.0.6422.60"},` +
	`{"brand":"Google Chrome","version":"125.0.6422.60"},` +
	`{"brand":"Not.A/Brand","version":"24.0.0.0"}]},` +
	`"codecH264":true,"codecAAC":true,"fontCount":8,"productSub":"20030107","engine":"blink",` +
	`"iframeWebdriver":false,"iframeProxied":false,"swWebdriver":false,"swCDP":false,` +
	`"maxTouchPoints":0,"navProtoDescriptorsOK":true,"chromeRuntimeOK":true,` +
	`"chromeLateInjection":false,"jsEngine":"v8","webrtcIPs":[],"imageBroken":false,` +
	`"mimeTypes":2,"outerH":900,"innerH":800}`

// staleV2ClientBody is the same clean fingerprint as a stale cached v2 collector
// would POST it: no v3 keys at all. The v3-gated rules must skip rather than
// read the missing (damning-when-false/zero) fields as tampering.
var staleV2ClientBody = `{"v":2,"nativeToStringOK":true,"hasChromeObject":true,` +
	`"nativeDescriptorsOK":true,"nativeCallNewOK":true,"nativeToStringProxied":false,` +
	`"navMainUA":"` + chromeMacUA + `","navWorkerUA":"` + chromeMacUA + `","navIframeUA":"` + chromeMacUA + `",` +
	`"languages":["en-US","en"],"language":"en-US","vendor":"Google Inc.",` +
	`"appVersion":"` + strings.TrimPrefix(chromeMacUA, "Mozilla/") + `",` +
	`"webglRenderer":"ANGLE (Apple, Apple M1, OpenGL 4.1)","plugins":3,` +
	`"screenW":1920,"screenH":1080,"availW":1920,"availH":1040,"colorDepth":30,` +
	`"outerW":1680,"innerW":1400,"hardwareCores":8,"deviceMemory":8,` +
	`"browserTZ":"Europe/Moscow","tzOffset":-180,` +
	`"canvasSupported":true,"canvasStable":true,"canvasBlank":false,` +
	`"brands":["Chromium","Google Chrome","Not.A/Brand"],` +
	`"uaData":{"platform":"macOS","fullVersionList":[` +
	`{"brand":"Chromium","version":"125.0.6422.60"},` +
	`{"brand":"Google Chrome","version":"125.0.6422.60"},` +
	`{"brand":"Not.A/Brand","version":"24.0.0.0"}]},` +
	`"codecH264":true,"codecAAC":true,"fontCount":8,"productSub":"20030107","engine":"blink"}`

func TestCheckHeaderClusterThroughHandler(t *testing.T) {
	// G06 end-to-end: a browser-UA POST with no Accept-Encoding, no Accept-Language,
	// and a scripted-client Accept (*/*) trips exactly the three new soft header
	// checks — a full cluster, so the single -25 deduction applies (100 → 75).
	// Sec-Fetch-Mode is sent so sec_fetch_missing stays out of the count.
	rec := post(newTestApp(fakeLooker{}), "/check", cleanClientBody, map[string]string{
		"Accept": "*/*", "User-Agent": chromeMacUA, "Sec-Fetch-Mode": "cors",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	var rep botcheck.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, id := range []string{"accept_encoding_missing", "accept_language_missing", "accept_nav_mismatch"} {
		var c botcheck.Check
		for _, got := range rep.Checks {
			if got.ID == id {
				c = got
			}
		}
		if !c.Triggered {
			t.Errorf("%s should fire through the handler:\n%s", id, rec.Body.String())
		}
	}
	soft := 0
	for _, c := range rep.Checks {
		if c.Tier == "soft" && c.Triggered {
			soft++
		}
	}
	if soft != 3 {
		t.Errorf("triggered soft checks = %d, want exactly 3 (only the new header checks):\n%s", soft, rec.Body.String())
	}
	if rep.Score != 75 || rep.Verdict != "suspicious" {
		t.Errorf("header cluster: score=%d verdict=%q, want 75/suspicious (one soft-cluster deduction)", rep.Score, rep.Verdict)
	}
}

func TestCheckFullBrowserHeadersFlagNone(t *testing.T) {
	// The same clean fingerprint with the complete header set a real browser sends
	// (an Accept that includes text/html, Accept-Encoding, Accept-Language,
	// Sec-Fetch-Mode, Upgrade-Insecure-Requests) must flag NOTHING. Accept says
	// text/html, so the answer is the HTML fragment: a 100 score with no "flagged"
	// soft rows and no cluster deduction.
	rec := post(newTestApp(fakeLooker{}), "/check", cleanClientBody, map[string]string{
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"Accept-Encoding":           "gzip, deflate, br, zstd",
		"Accept-Language":           "en-US,en;q=0.9",
		"Sec-Fetch-Mode":            "cors",
		"Upgrade-Insecure-Requests": "1",
		"User-Agent":                chromeMacUA,
	})
	frag := rec.Body.String()
	if !strings.Contains(frag, "100<span") {
		t.Errorf("a full-header clean browser should score 100:\n%s", frag)
	}
	// A triggered soft row renders "flagged" as its status. The word also appears
	// once in the static explanatory copy ("Each flagged check subtracts…"), so a
	// fully clean fragment contains it exactly once — any triggered soft row adds
	// another.
	if n := strings.Count(frag, "flagged"); n != 1 {
		t.Errorf("a full-header clean browser should have no flagged soft rows (found %d extra):\n%s", n-1, frag)
	}
	if strings.Contains(frag, "weak signals counted together") {
		t.Errorf("no soft cluster should be active for a full-header clean browser:\n%s", frag)
	}
}

func TestCheckV3SignalsThroughHandler(t *testing.T) {
	// v3 end-to-end: the new client fields bind from the POSTed JSON and their
	// rules fire through the real handler — here a stealth browser whose iframe
	// and Service Worker leak webdriver, whose Navigator.prototype descriptors and
	// chrome.runtime fail integrity, whose chrome object was injected late, and
	// whose Error stack betrays SpiderMonkey under a Chrome UA.
	body := `{"v":3,"navMainUA":"` + chromeMacUA + `",` +
		`"iframeWebdriver":true,"swWebdriver":true,` +
		`"navProtoDescriptorsOK":false,"chromeRuntimeOK":false,` +
		`"chromeLateInjection":true,"jsEngine":"spidermonkey"}`
	rec := post(newTestApp(fakeLooker{}), "/check", body, map[string]string{"Accept": "application/json", "User-Agent": chromeMacUA})
	var rep botcheck.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, id := range []string{
		"iframe_webdriver", "webdriver_sw", "navigator_proto_tamper",
		"chrome_runtime_tamper", "chrome_late_injection", "jsengine_ua_mismatch",
	} {
		var c botcheck.Check
		for _, got := range rep.Checks {
			if got.ID == id {
				c = got
			}
		}
		if !c.Triggered {
			t.Errorf("%s should fire through the handler:\n%s", id, rec.Body.String())
		}
	}
}

func TestCheckWebRTCMismatchThroughHandler(t *testing.T) {
	// G09 end-to-end: httptest's RemoteAddr (192.0.2.1) is the egress the handler
	// wires into Signals.EgressIP; a PUBLIC WebRTC candidate that differs pierces
	// the proxy claim, while a private host candidate (normal NAT) must not.
	postIPs := func(ips string) botcheck.Report {
		body := `{"v":3,"navMainUA":"` + chromeMacUA + `","webrtcIPs":[` + ips + `]}`
		rec := post(newTestApp(fakeLooker{}), "/check", body, map[string]string{"Accept": "application/json", "User-Agent": chromeMacUA})
		var rep botcheck.Report
		if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return rep
	}
	fired := false
	for _, c := range postIPs(`"192.168.1.5","203.0.113.9"`).Checks {
		if c.ID == "webrtc_ip_mismatch" {
			fired = c.Triggered
		}
	}
	if !fired {
		t.Errorf("webrtc_ip_mismatch should fire when a public candidate ≠ the egress")
	}
	for _, c := range postIPs(`"192.168.1.5","10.0.0.2"`).Checks {
		if c.ID == "webrtc_ip_mismatch" && c.Triggered {
			t.Errorf("webrtc_ip_mismatch must not fire for private host candidates only")
		}
	}
}

func TestCheckStaleV2PayloadScores100ThroughHandler(t *testing.T) {
	// A returning visitor whose browser still runs the cached v2 collector POSTs a
	// payload with no v3 keys; the v3-gated rules must skip and the ungated ones
	// bind safe, so the score stays 100 with full browser headers — the
	// deploy-time cache-staleness contract, end to end.
	rec := post(newTestApp(fakeLooker{}), "/check", staleV2ClientBody, map[string]string{
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"Accept-Encoding":           "gzip, deflate, br, zstd",
		"Accept-Language":           "en-US,en;q=0.9",
		"Sec-Fetch-Mode":            "cors",
		"Upgrade-Insecure-Requests": "1",
		"User-Agent":                chromeMacUA,
	})
	frag := rec.Body.String()
	if !strings.Contains(frag, "100<span") {
		t.Errorf("a stale v2 payload from a clean browser should score 100:\n%s", frag)
	}
	// No v3 rule may read the missing fields as tampering — check the JSON view
	// for exact rule state rather than scraping the fragment. The request carries
	// the headers a real browser always sends so the header-presence soft checks
	// stay quiet; Accept: application/json still trips accept_nav_mismatch alone,
	// a single soft signal under the cluster threshold, so it costs nothing.
	rec = post(newTestApp(fakeLooker{}), "/check", staleV2ClientBody, map[string]string{
		"Accept": "application/json", "User-Agent": chromeMacUA,
		"Accept-Encoding": "gzip, deflate, br, zstd", "Accept-Language": "en-US,en;q=0.9",
		"Sec-Fetch-Mode": "cors",
	})
	var rep botcheck.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, c := range rep.Checks {
		switch c.ID {
		case "navigator_proto_tamper", "chrome_runtime_tamper", "mobile_no_touch", "plugins_mimetypes_incoherent":
			if c.Triggered {
				t.Errorf("%s must skip a pre-v3 payload, not read missing keys as tampering", c.ID)
			}
		case "iframe_webdriver", "webdriver_sw", "iframe_proxy", "cdp_sw_only", "chrome_late_injection",
			"jsengine_ua_mismatch", "webrtc_ip_mismatch", "image_broken", "zero_outer_height":
			if c.Triggered {
				t.Errorf("%s must bind safe on a pre-v3 payload", c.ID)
			}
		}
	}
	if rep.Score != 100 {
		t.Errorf("stale v2 payload: score=%d, want 100", rep.Score)
	}
}
