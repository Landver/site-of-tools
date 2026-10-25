package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/shared"
	"github.com/Landver/site-of-tools/tools/botcheck"
	"github.com/Landver/site-of-tools/tools/iptools"
)

// fakeLooker returns a canned result for any IP, so tests need no IP databases.
type fakeLooker struct {
	res *iptools.Result
	err error
}

func (f fakeLooker) Lookup(context.Context, string) (*iptools.Result, error) { return f.res, f.err }

// newTestApp uses the embedded templates, so it works from any cwd; the corpus is nil (Mongo off).
func newTestApp(svc iptools.Looker) *echo.Echo {
	r := platform.NewRenderer(false, nil,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: botcheck.Templates, DevDir: "tools/botcheck/templates"},
	)
	e := echo.New()
	e.Renderer = r
	botcheck.Register(e, svc, nil, nil, nil)
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
	// The IP2Location LITE licence requires the credit on any page using its data, as botcheck does.
	rec := get(newTestApp(fakeLooker{}), "/", map[string]string{"Accept": "text/html"})
	body := rec.Body.String()
	if !strings.Contains(body, "uses the IP2Location LITE database") || !strings.Contains(body, "lite.ip2location.com") {
		t.Errorf("full botcheck page must carry the IP2Location LITE credit, got:\n%s", body)
	}
}

func TestIndexShowsSpamhausCredit(t *testing.T) {
	// ip_blocklisted (G37) can surface Spamhaus DROP data, so the page must credit them too.
	rec := get(newTestApp(fakeLooker{}), "/", map[string]string{"Accept": "text/html"})
	body := rec.Body.String()
	if !strings.Contains(body, "The Spamhaus Project") || !strings.Contains(body, "spamhaus.org/blocklists/do-not-route-or-peer") {
		t.Errorf("full botcheck page must carry the Spamhaus DROP credit, got:\n%s", body)
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
	// Lookup w/ no network data → no ASN/proxy rows (card unchanged).
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

// The four tabs don't fit a 320px screen on one line: the strip must wrap, not widen the page.
func TestResultTabsWrap(t *testing.T) {
	frag := post(newTestApp(fakeLooker{}), "/check", `{}`, map[string]string{"Accept": "text/html"}).Body.String()
	m := regexp.MustCompile(`<div class="([^"]*)">\s*<button type="button" @click="tab = `).FindStringSubmatch(frag)
	if m == nil {
		t.Fatalf("no tab strip in fragment:\n%s", frag)
	}
	if !strings.Contains(m[1], "flex-wrap") {
		t.Errorf("tab strip can't wrap: class=%q", m[1])
	}
}

func TestIndexCurlGetsServerOnlyScore(t *testing.T) {
	// A browser UA and the headers a browser always sends isolate datacenter_ip; the JSON Accept still
	// trips accept_nav_mismatch, a lone soft signal under the cluster threshold.
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
	// Client checks must skip on server-only req.
	for _, c := range rep.Checks {
		if c.ID == "webdriver" && !c.Skipped {
			t.Errorf("webdriver should be skipped on server-only GET /")
		}
	}
}

func TestUnknownTimezoneThroughHandler(t *testing.T) {
	// iptools reports IP2Location's "-" placeholder as "": unknown must not trip tz_mismatch on a real browser.
	looker := fakeLooker{res: &iptools.Result{}}
	body := `{"browserTZ":"Europe/Moscow","navMainUA":"` + chromeMacUA + `"}`
	rec := post(newTestApp(looker), "/check", body, map[string]string{"Accept": "application/json", "User-Agent": chromeMacUA})
	var rep botcheck.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, c := range rep.Checks {
		if c.ID == "tz_mismatch" && c.Triggered {
			t.Errorf("tz_mismatch fired against an unknown timezone:\n%s", rec.Body.String())
		}
	}
}

func TestCheckTimezoneMismatchFiresThroughHandler(t *testing.T) {
	// Also proves the handler stamps sig.Now (a zero Now silently suppresses the check). Los Angeles
	// is never +03:00, so this holds whatever the live time.Now() is.
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
	// Soft signals render "flagged" (no per-row "−8"); the single cluster line shows once enough fire.
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
	// A Chrome UA with Gecko's engine, productSub and a mismatched uaData version (nested JSON binds).
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
	// G36: Applebot from Apple's AS714 is a verified good bot; GET / is the path a real crawler hits.
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
	// The Applebot UA from a NON-Apple network is recognised but not verified, so it stays a bot.
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
	// End-to-end: headless fingerprint from datacenter IP → bot, JSON.
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
	// G07/G08: an Apple GPU pair is self-consistent (G07 silent) but impossible on Windows (G08 fires).
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
	// SW registration refuses a non-JavaScript MIME type; the SW must have NO fetch handler, so it can
	// never intercept a request on the origin.
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
	// G03: a Service Worker leaks Linux UA, platform and cores under a macOS top frame (Bright Data).
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
	// G04: nativeToStringOK stays true, since keeping the shallow check green is the proxy's purpose.
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

// cleanClientBody is cleanChrome as JSON, so header tests trip no client rule. Europe/Moscow is
// UTC+3 year-round, so tzOffset -180 holds whatever the wall clock says.
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

// cleanClientEnv is the v4 env section (leading comma, closes the object); Chrome exposes no GPC.
const cleanClientEnv = `,"env":{"matchMedia":true,"dpr":2,"colorScheme":"light","forcedColors":false,` +
	`"reducedMotion":false,"dynamicRange":"standard","gamut":"p3",` +
	`"connection":{"effectiveType":"4g","downlink":10,"rtt":50,"saveData":false},` +
	`"storageQuotaMB":285000,"permissions":{"notifications":"default","geolocation":"prompt"},` +
	`"emeClearKey":true}}`

// staleV3ClientBody is what a stale cached v3 collector POSTs: v:3 and no env section.
var staleV3ClientBody = strings.Replace(
	strings.TrimSuffix(cleanClientBody, cleanClientEnv)+"}",
	`"v":4`, `"v":3`, 1)

// staleV2ClientBody is what a stale cached v2 collector POSTs: no v3 keys at all.
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
	// G06: three soft header signals form the cluster (100 → 75); Sec-Fetch-Mode keeps a fourth out.
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
	// The full header set a real browser sends must flag NOTHING: 100, no flagged rows, no cluster.
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
	// "flagged" appears once in the static copy, so a clean fragment has it exactly once.
	if n := strings.Count(frag, "flagged"); n != 1 {
		t.Errorf("a full-header clean browser should have no flagged soft rows (found %d extra):\n%s", n-1, frag)
	}
	if strings.Contains(frag, "weak signals counted together") {
		t.Errorf("no soft cluster should be active for a full-header clean browser:\n%s", frag)
	}
}

func TestCheckV3SignalsThroughHandler(t *testing.T) {
	// v3: a stealth browser leaking through iframe, SW, descriptors, chrome.runtime and its stack.
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
	// G09: RemoteAddr 192.0.2.1 is the egress; a differing PUBLIC candidate fires, a private one doesn't.
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
	// A returning visitor's cached v2 collector must still score 100: the cache-staleness contract.
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
	// No v3 rule may read missing fields as tampering; the JSON Accept trips only accept_nav_mismatch.
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
	// v4: no matchMedia, and '4g' with a 2000ms rtt (at most 2g by the spec's own table).
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
	// The env's entropy half is never scored but echoes into the raw-dump payload (G54).
	if rep.ClientPayload == nil || rep.ClientPayload.Env.GPC == nil || !*rep.ClientPayload.Env.GPC ||
		rep.ClientPayload.Env.StorageQuotaMB != 285000 || rep.ClientPayload.Env.Permissions.Geolocation != "prompt" {
		t.Errorf("env entropy fields should bind into the echoed payload: %+v", rep.ClientPayload.Env)
	}
}

func TestCheckStaleV3PayloadSkipsV4Rules(t *testing.T) {
	// A cached v3 collector sends no env: v4-gated rules must skip, not read absent keys as evidence.
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
	// Only accept_nav_mismatch fires (JSON Accept), alone under the cluster threshold.
	if rep.Score != 100 {
		t.Errorf("stale v3 payload: score=%d, want 100", rep.Score)
	}
}

func TestIndexOGTags(t *testing.T) {
	body := get(newTestApp(fakeLooker{}), "/", map[string]string{"Accept": "text/html"}).Body.String()
	for _, want := range []string{
		`<meta property="og:type" content="website">`,
		`<meta property="og:title" content="Bot check">`,
		`<meta property="og:image" content="https://corpberry.com/static/img/og-cover.png">`,
		`<meta name="twitter:card" content="summary_large_image">`,
		`content="Open-source bot-detection self-test`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("botcheck index <head> missing %q", want)
		}
	}
}
