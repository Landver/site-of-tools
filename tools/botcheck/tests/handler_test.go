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

// fakeLooker implements botcheck.Looker → tests run w/o real IP databases.
// Ignores the IP, returns canned result.
type fakeLooker struct {
	res *iptools.Result
	err error
}

func (f fakeLooker) Lookup(string) (*iptools.Result, error) { return f.res, f.err }

// newTestApp builds bare echo w/ real (embedded) templates + given Looker.
// Embedded FS → works regardless of test's cwd. Corpus nil (Mongo off) —
// corpus tests live in corpus_test.go.
func newTestApp(svc botcheck.Looker) *echo.Echo {
	r := platform.NewRenderer(false, nil,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: botcheck.Templates, DevDir: "tools/botcheck/templates"},
	)
	e := echo.New()
	e.Renderer = r
	botcheck.Register(e, svc, nil, nil)
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
	for _, want := range []string{"Bot check", "Run again"} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
}

func TestIndexShowsIP2LocationCredit(t *testing.T) {
	// IP2Location LITE license requires exact acknowledgment on any page using
	// the data. botcheck's IP reputation checks do (via Looker) → full page
	// must carry it — see iptools' TestFullPageShowsIP2LocationCredit.
	rec := get(newTestApp(fakeLooker{}), "/", map[string]string{"Accept": "text/html"})
	body := rec.Body.String()
	if !strings.Contains(body, "uses the IP2Location LITE database") || !strings.Contains(body, "lite.ip2location.com") {
		t.Errorf("full botcheck page must carry the IP2Location LITE credit, got:\n%s", body)
	}
}

func TestIndexSetsAcceptCH(t *testing.T) {
	rec := get(newTestApp(fakeLooker{}), "/", map[string]string{"Accept": "text/html"})
	if ch := rec.Header().Get("Accept-CH"); !strings.Contains(ch, "Sec-CH-UA-Platform") {
		t.Errorf("Accept-CH = %q, want it to request Sec-CH-UA-Platform", ch)
	}
}

func TestCheckFragmentEnrichesConnCard(t *testing.T) {
	looker := fakeLooker{res: &iptools.Result{
		ASN: "14061", ASName: "DigitalOcean, LLC",
		Proxy: &iptools.Proxy{IsProxy: true, ProxyType: "VPN", Provider: "NordVPN"},
	}}
	body := `{"navMainUA":"` + chromeMacUA + `"}`
	rec := post(newTestApp(looker), "/check", body, map[string]string{"Accept": "text/html", "User-Agent": chromeMacUA})
	frag := rec.Body.String()
	for _, want := range []string{"AS14061 (DigitalOcean, LLC)", "VPN — NordVPN"} {
		if !strings.Contains(frag, want) {
			t.Errorf("enriched conn card missing %q:\n%s", want, frag)
		}
	}
	// Lookup w/ no network data → no ASN/proxy rows (unchanged card).
	rec = post(newTestApp(fakeLooker{}), "/check", `{}`, map[string]string{"Accept": "text/html"})
	if frag := rec.Body.String(); strings.Contains(frag, "<dt>ASN</dt>") || strings.Contains(frag, "<dt>Proxy</dt>") {
		t.Errorf("an empty lookup must render no network rows:\n%s", frag)
	}
}

func TestCheckFragmentRendersHistoryCard(t *testing.T) {
	rec := post(newTestApp(fakeLooker{}), "/check", `{}`, map[string]string{"Accept": "text/html"})
	frag := rec.Body.String()
	for _, want := range []string{
		`id="botcheck-history" hidden`, "your recent checks",
		"only in your browser's local storage", "never sent to",
	} {
		if !strings.Contains(frag, want) {
			t.Errorf("history card missing %q in fragment:\n%s", want, frag)
		}
	}
}

func TestIndexCurlGetsServerOnlyScore(t *testing.T) {
	// Datacenter IP should surface in server-only score, even w/ no client
	// fingerprint. Normal browser UA avoids empty-UA bot signal → isolates
	// datacenter check. Request carries headers a real browser always sends
	// (Accept-Encoding, Accept-Language, Sec-Fetch-Mode) → G06 presence
	// checks stay quiet too; Accept stays application/json (JSON path),
	// still flags accept_nav_mismatch — single soft signal, under cluster
	// threshold, costs nothing.
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
	// Client checks must skip on server-only request.
	for _, c := range rep.Checks {
		if c.ID == "webdriver" && !c.Skipped {
			t.Errorf("webdriver should be skipped on server-only GET /")
		}
	}
}

func TestPlaceholderTimezoneCleanedThroughHandler(t *testing.T) {
	// localhost/unknown IP yields IP2Location's "-" timezone; handler must
	// clean it → real browser timezone doesn't spuriously trip tz_mismatch.
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
	// Positive end-to-end counterpart to TestPlaceholderTimezoneCleaned: proves
	// handler wires res.Timezone -> sig.IPTimezone AND stamps sig.Now (zero Now →
	// ianaOffset returns ok=false → silently suppresses check). America/Los_Angeles
	// is UTC-8/-7 year-round, never +03:00 → DST- and wall-clock-independent
	// despite addServerSignals using live time.Now().
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
	// Soft signals never dock points alone → each renders as "flagged" (no
	// misleading per-row "−8"); single cluster deduction line shows only once
	// enough fire. Body trips several soft signals but no hard/consistency
	// ones → fragment must carry both.
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
	// Chrome UA whose feature-detected engine is gecko, whose productSub is
	// Gecko's constant, whose userAgentData Chromium version disagrees w/ UA.
	// Proves new client fields — incl. nested uaData.fullVersionList array —
	// bind from JSON, rules fire end-to-end through real handler.
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
	// G36 end-to-end: verified crawler (Applebot from Apple's AS714) → "good-bot"
	// verdict + Bot identity in JSON. Proves addServerSignals wires res.ASN
	// through to corroboration. GET / = server-only path a real crawler hits.
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
	// Same Applebot UA from NON-Apple network recognised but NOT verified →
	// stays bot — no-evasion property, proven end-to-end through handler.
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
	// good-bot verdict branch + "expected" suppressed-row rendering must work.
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
	if err := r.Render(nil, &buf, "botcheck/result", map[string]any{"Report": rep}); err != nil {
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
	// End-to-end: headless fingerprint from datacenter IP → bot, in JSON.
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
	// G07/G08 end-to-end: Apple GPU reported on Windows Chrome UA. Vendor/
	// renderer pair internally consistent (G07 stays silent) but GPU
	// impossible for claimed OS (G08 fires) — proves new webglVendor field
	// binds from JSON alongside webglRenderer through real handler.
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
	// G03+G14: collector registers /botcheck-sw.js as Service Worker → app must
	// serve it w/ JavaScript MIME type (registration refuses anything else),
	// answering messages w/ its navigator values + webdriver + CDP trap, and —
	// critically — w/ NO fetch handler, so it can never intercept a request on
	// the origin.
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
	// G03 end-to-end: new cross-context fields bind from POSTed JSON, rules
	// fire — here a Service Worker leaking Linux UA, platform, core count
	// while top frame claims macOS (the Bright Data scenario).
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
	// G04 end-to-end: three deep-tamper fields bind from POSTed JSON, rules
	// fire through real handler. nativeToStringProxied inverted (true = bad);
	// nativeToStringOK stays true — stealth proxy's purpose is keeping shallow
	// check green.
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

// cleanClientBody = JSON twin of cleanChrome (botcheck_test.go): fully
// consistent client fingerprint → G06 handler tests isolate server-side
// header rules — nothing in body trips client rule. Europe/Moscow used bc it
// keeps UTC+3 year-round (no DST) → tzOffset -180 stays consistent w/
// handler's live time.Now() stamp whatever wall clock says.
var cleanClientBody = `{"v":4,"nativeToStringOK":true,"hasChromeObject":true,` +
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
	`"mimeTypes":2,"outerH":900,"innerH":800` +
	cleanClientEnv

// cleanClientEnv = v4 collector's additive env section for clean
// desktop-Chrome fingerprint (leading comma, closes outer object). Chrome
// exposes no GPC property → key absent — fail-to-absent.
const cleanClientEnv = `,"env":{"matchMedia":true,"dpr":2,"colorScheme":"light","forcedColors":false,` +
	`"reducedMotion":false,"dynamicRange":"standard","gamut":"p3",` +
	`"connection":{"effectiveType":"4g","downlink":10,"rtt":50,"saveData":false},` +
	`"storageQuotaMB":285000,"permissions":{"notifications":"default","geolocation":"prompt"},` +
	`"emeClearKey":true}}`

// staleV3ClientBody = cleanClientBody as stale cached v3 collector would
// POST it: same clean fingerprint but v:3, no env section (v4 batch didn't
// exist for it). v4-gated rules must skip, not read absent env keys as
// evidence.
var staleV3ClientBody = strings.Replace(
	strings.TrimSuffix(cleanClientBody, cleanClientEnv)+"}",
	`"v":4`, `"v":3`, 1)

// staleV2ClientBody = same clean fingerprint as stale cached v2 collector
// would POST it: no v3 keys at all. v3-gated rules must skip, not read
// missing (damning-when-false/zero) fields as tampering.
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
	// G06 end-to-end: browser-UA POST w/ no Accept-Encoding, no Accept-Language,
	// scripted-client Accept (*/*) trips exactly the three new soft header
	// checks — full cluster → single -25 deduction applies (100 → 75).
	// Sec-Fetch-Mode sent so sec_fetch_missing stays out of count.
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
	// Same clean fingerprint w/ complete header set a real browser sends
	// (Accept incl. text/html, Accept-Encoding, Accept-Language,
	// Sec-Fetch-Mode, Upgrade-Insecure-Requests) must flag NOTHING. Accept
	// says text/html → answer is HTML fragment: 100 score, no "flagged" soft
	// rows, no cluster deduction.
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
	// Triggered soft row renders "flagged" as its status. Word also appears
	// once in static explanatory copy ("Each flagged check subtracts…") →
	// fully clean fragment contains it exactly once — any triggered soft row
	// adds another.
	if n := strings.Count(frag, "flagged"); n != 1 {
		t.Errorf("a full-header clean browser should have no flagged soft rows (found %d extra):\n%s", n-1, frag)
	}
	if strings.Contains(frag, "weak signals counted together") {
		t.Errorf("no soft cluster should be active for a full-header clean browser:\n%s", frag)
	}
}

func TestCheckV3SignalsThroughHandler(t *testing.T) {
	// v3 end-to-end: new client fields bind from POSTed JSON, rules fire
	// through real handler — here stealth browser whose iframe and Service
	// Worker leak webdriver, whose Navigator.prototype descriptors and
	// chrome.runtime fail integrity, whose chrome object injected late, whose
	// Error stack betrays SpiderMonkey under Chrome UA.
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
	// G09 end-to-end: httptest's RemoteAddr (192.0.2.1) = egress handler wires
	// into Signals.EgressIP; PUBLIC WebRTC candidate that differs pierces
	// proxy claim, private host candidate (normal NAT) must not.
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
	// Returning visitor whose browser still runs cached v2 collector POSTs
	// payload w/ no v3 keys; v3-gated rules must skip, ungated ones bind
	// safe → score stays 100 w/ full browser headers — deploy-time
	// cache-staleness contract, end to end.
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
	// No v3 rule may read missing fields as tampering — check JSON view for
	// exact rule state rather than scraping fragment. Request carries headers
	// a real browser always sends → header-presence soft checks stay quiet;
	// Accept: application/json still trips accept_nav_mismatch alone, single
	// soft signal under cluster threshold, costs nothing.
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

func TestCheckV4SignalsThroughHandler(t *testing.T) {
	// v4 end-to-end: nested env section binds from POSTed JSON, rules fire
	// through real handler — here spoofed browser whose environment lacks
	// window.matchMedia, whose connection claims '4g' while reporting 2000ms
	// rtt (implies at most 2g by spec's own table).
	body := `{"v":4,"navMainUA":"` + chromeMacUA + `",` +
		`"env":{"matchMedia":false,"dpr":2,"colorScheme":"dark",` +
		`"connection":{"effectiveType":"4g","downlink":10,"rtt":2000,"saveData":false},` +
		`"storageQuotaMB":285000,"gpc":true,` +
		`"permissions":{"notifications":"denied","geolocation":"prompt"},"emeClearKey":true}}`
	rec := post(newTestApp(fakeLooker{}), "/check", body, map[string]string{"Accept": "application/json", "User-Agent": chromeMacUA})
	var rep botcheck.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, id := range []string{"matchmedia_missing", "netinfo_incoherent"} {
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
	// Entropy half of env section echoes into raw-dump payload (G54) — never
	// scored, visible in report.
	if rep.ClientPayload == nil || rep.ClientPayload.Env.GPC == nil || !*rep.ClientPayload.Env.GPC ||
		rep.ClientPayload.Env.StorageQuotaMB != 285000 || rep.ClientPayload.Env.Permissions.Geolocation != "prompt" {
		t.Errorf("env entropy fields should bind into the echoed payload: %+v", rep.ClientPayload.Env)
	}
}

func TestCheckStaleV3PayloadSkipsV4Rules(t *testing.T) {
	// Returning visitor whose browser still runs cached v3 collector POSTs
	// payload w/ no env section at all; v4-gated rules must skip, not read
	// missing keys as evidence — deploy-time cache-staleness contract, one
	// version up from TestCheckStaleV2PayloadScores100ThroughHandler.
	rec := post(newTestApp(fakeLooker{}), "/check", staleV3ClientBody, map[string]string{
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
		case "matchmedia_missing", "netinfo_incoherent":
			if c.Triggered {
				t.Errorf("%s must skip a pre-v4 payload, not read missing env keys as evidence", c.ID)
			}
		}
	}
	// Only accept_nav_mismatch fires (JSON Accept) — single soft signal under
	// cluster threshold — score stays 100.
	if rep.Score != 100 {
		t.Errorf("stale v3 payload: score=%d, want 100", rep.Score)
	}
}
