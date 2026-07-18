// Package botcheck is the botcheck.corpberry.com tool: it scores how much a
// visitor's browser looks like a human vs. an automated/bot browser, and shows a
// transparent per-signal breakdown.
//
// botcheck.go is the domain layer — pure Go, no HTTP and (deliberately) no
// iptools import. The handler collects client signals (from a vendored JS
// collector that POSTs a fingerprint) and server signals (HTTP headers + the
// existing iptools IP reputation lookup), flattens both into a Signals struct,
// and calls Evaluate. Keeping this package free of echo/iptools is what lets its
// tests construct Signals directly, with no databases and no HTTP.
//
// The one load-bearing idea (see docs/RESEARCH.md / docs/ROADMAP.md): every client signal is
// spoofable, so the strongest checks are the cross-layer/cross-context
// consistency ones — what the browser *claims* (JS) vs. what the connection
// *shows* (headers, IP) vs. what a second JS context reports (Worker/iframe).
package botcheck

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	// Embed the IANA timezone database so time.LoadLocation works regardless of
	// the (distroless) runtime image — needed for the browser-TZ vs IP-TZ offset
	// comparison below.
	_ "time/tzdata"
)

// UAData is the subset of navigator.userAgentData the collector reports. It exists
// so Go can cross-check the JS-reported platform + browser version against the
// Sec-CH-UA-Platform request header and the legacy User-Agent string. FullVersionList
// is the G01 catch: a UA-string spoof that edits "Chrome/NNN" but leaves
// userAgentData intact disagrees with the "Chromium" brand entry here (see
// ua_chrome_version_mismatch / chVersionMajor).
type UAData struct {
	Platform        string         `json:"platform"`
	FullVersionList []BrandVersion `json:"fullVersionList"`
}

// BrandVersion is one entry of navigator.userAgentData.fullVersionList
// (e.g. {"Chromium", "125.0.6422.60"}); the GREASE decoy brand is ignored when
// reading it (see chVersionMajor / realBrandSet).
type BrandVersion struct {
	Brand   string `json:"brand"`
	Version string `json:"version"`
}

// Signals is everything the scorer needs: client-collected values (bound
// straight from the POSTed fingerprint JSON via the json tags) and
// server-observed values (headers + IP lookup, filled by the handler and hidden
// from the wire with json:"-"), all flattened to plain fields so this package
// imports nothing but stdlib. A zero value means "not supplied"; ClientCollected
// distinguishes "a real browser reported false/empty" from "no client
// fingerprint was posted at all" (e.g. a plain curl), so client checks are
// skipped rather than treated as passing.
type Signals struct {
	ClientCollected bool `json:"-"`

	// CollectorV is the fingerprint-payload version the collector stamps (the
	// "v" key). Rules whose fields are damning when false (the G04 deep-tamper
	// probes: a missing key binds false) must not evaluate payloads too old to
	// carry them — a stale cached botcheck.js would otherwise read as tampered.
	// 0 = an unversioned/pre-G04 payload. See collectorVDeepTamper.
	CollectorV int `json:"v"`

	// ── client-collected (bound from the POSTed JSON) ────────────────────────
	Webdriver        bool     `json:"webdriver"`
	FrameworkGlobals []string `json:"frameworkGlobals"`
	CDPMainThread    bool     `json:"cdpMainThread"`
	CDPWorker        bool     `json:"cdpWorker"`
	NativeToStringOK bool     `json:"nativeToStringOK"`
	NavMainUA        string   `json:"navMainUA"`
	NavWorkerUA      string   `json:"navWorkerUA"`
	NavIframeUA      string   `json:"navIframeUA"`
	Languages        []string `json:"languages"`
	PermissionState  string   `json:"permissionState"`
	NotificationPerm string   `json:"notificationPermission"`
	HasChromeObject  bool     `json:"hasChromeObject"`
	WebGLRenderer    string   `json:"webglRenderer"`
	WebGLVendor      string   `json:"webglVendor"` // UNMASKED_VENDOR_WEBGL (e.g. "Google Inc. (Apple)"); cross-checked against the renderer (G07) and the UA-claimed OS (G08)
	Plugins          int      `json:"plugins"`
	ScreenW          int      `json:"screenW"`
	ScreenH          int      `json:"screenH"`
	OuterW           int      `json:"outerW"`
	InnerW           int      `json:"innerW"`
	HardwareCores    int      `json:"hardwareCores"`
	DeviceMemory     float64  `json:"deviceMemory"`
	BrowserTZ        string   `json:"browserTZ"`
	UAData           UAData   `json:"uaData"`
	NavLanguage      string   `json:"language"`   // navigator.language (should equal Languages[0])
	Vendor           string   `json:"vendor"`     // navigator.vendor
	AppVersion       string   `json:"appVersion"` // navigator.appVersion
	AvailW           int      `json:"availW"`     // screen.availWidth
	AvailH           int      `json:"availH"`     // screen.availHeight
	ColorDepth       int      `json:"colorDepth"` // screen.colorDepth

	// ── Layer-2 (medium) client signals ──────────────────────────────────────
	TZOffset        int      `json:"tzOffset"`        // Date().getTimezoneOffset() minutes (west of UTC)
	CanvasSupported bool     `json:"canvasSupported"` // a 2D canvas context is available
	CanvasStable    bool     `json:"canvasStable"`    // two identical draws hash the same (else: randomised)
	CanvasBlank     bool     `json:"canvasBlank"`     // the drawn canvas has no non-transparent pixels
	Brands          []string `json:"brands"`          // navigator.userAgentData.brands names
	CodecH264       bool     `json:"codecH264"`       // <video> can play H.264
	CodecAAC        bool     `json:"codecAAC"`        // <audio> can play AAC
	FontCount       int      `json:"fontCount"`       // probe fonts detected (-1 = couldn't measure)

	// ── quick-win client signals (G01/G02/G05) ───────────────────────────────
	ProductSub string `json:"productSub"` // navigator.productSub — engine constant ("20030107" WebKit/Blink, "20100101" Gecko)
	Engine     string `json:"engine"`     // feature-detected engine family: "blink" | "gecko" | "webkit"

	// ── cross-context client signals (G03) ───────────────────────────────────
	// The same navigator values re-read inside a Web Worker, a display:none
	// iframe, and a Service Worker — three extra JS contexts. Anti-detect tools
	// overwhelmingly spoof only the top frame's navigator, so a context that
	// confidently reports something different is a strong consistency tell (the
	// Bright Data catch: a worker claiming Linux while the top UA says macOS).
	// Every rule comparing these requires BOTH sides present: "" / 0 / nil means
	// the context didn't answer (unsupported API, probe timeout), which is never
	// evidence — the comparison skips instead of firing.
	SWUA                string   `json:"swUA"`                // Service Worker's navigator.userAgent
	WorkerLanguages     []string `json:"workerLanguages"`     // worker's navigator.languages
	IframeLanguages     []string `json:"iframeLanguages"`     // iframe's navigator.languages
	SWLanguages         []string `json:"swLanguages"`         // Service Worker's navigator.languages
	WorkerCores         int      `json:"workerCores"`         // worker's navigator.hardwareConcurrency
	IframeCores         int      `json:"iframeCores"`         // iframe's navigator.hardwareConcurrency
	SWCores             int      `json:"swCores"`             // Service Worker's navigator.hardwareConcurrency
	WorkerPlatform      string   `json:"workerPlatform"`      // worker's navigator.userAgentData.platform
	IframePlatform      string   `json:"iframePlatform"`      // iframe's navigator.userAgentData.platform
	SWPlatform          string   `json:"swPlatform"`          // Service Worker's navigator.userAgentData.platform
	WorkerWebGLRenderer string   `json:"workerWebGLRenderer"` // worker's WebGL unmasked renderer via OffscreenCanvas ("" if unsupported)

	// ── G04 deep native-tamper probes (CreepJS queryLies-style) ──────────────
	// Same contract as NativeToStringOK: an OK field is false ONLY on a confirmed
	// tamper — a probe that can't run yields the pass value — so on a posted
	// fingerprint false reads as damning, never as "absent data".
	NativeDescriptorsOK bool `json:"nativeDescriptorsOK"` // descriptor/own-property sanity on the natives
	NativeCallNewOK     bool `json:"nativeCallNewOK"`     // call/new TypeError traps behave
	// NativeToStringProxied is INVERTED: true is the bad value. It means
	// Function.prototype.toString carries Proxy artifacts — the stealth-plugin
	// hallmark that exists to defeat the shallow NativeToStringOK check.
	NativeToStringProxied bool `json:"nativeToStringProxied"`

	// ── server-observed (filled by the handler; never read off the wire) ─────
	HTTPUserAgent   string `json:"-"`
	SecCHUAPlatform string `json:"-"`
	SecCHUA         string `json:"-"` // full Sec-CH-UA header (brand list)
	SecFetchMode    string `json:"-"` // Sec-Fetch-Mode header (real browsers always send it)
	AcceptLanguage  string `json:"-"`
	// G06 header-consistency signals, all server-observed.
	HTTPAccept         string `json:"-"` // Accept header; a browser's navigation/fetch Accept includes text/html
	HTTPAcceptEncoding string `json:"-"` // Accept-Encoding header; every real browser sends one on every request
	// Upgrade-Insecure-Requests is captured for completeness but deliberately UNUSED
	// by any rule: Safari never sends it, so a rule keyed on its presence or absence
	// would false-positive every real Safari user.
	HTTPUpgradeInsecureRequests string `json:"-"`
	IPTimezone                  string `json:"-"`
	ASN                         string `json:"-"` // egress ASN number (IP2Location), for good-bot corroboration
	IsDatacenter                bool   `json:"-"`
	IsProxy                     bool   `json:"-"`
	IsVPN                       bool   `json:"-"`
	IsTor                       bool   `json:"-"`

	// Now is the request time, stamped by the handler. It's an input (not a call
	// to the clock) so Evaluate stays pure and testable; used to resolve the
	// browser timezone's current UTC offset (DST-aware).
	Now time.Time `json:"-"`
}

// Tier classifies a check by how damning it is; it also drives the soft-signal
// combination rule (see Evaluate) and the colour in the HTML table.
const (
	TierHard        = "hard"        // near-standalone bot proof
	TierConsistency = "consistency" // a combination that should not co-occur
	TierSoft        = "soft"        // weak on its own; only counts in a cluster
)

// Check is one row in the transparent breakdown table. Triggered means the
// anomaly fired (bad); Skipped means it could not be evaluated (e.g. a
// client-only signal on a server-only request) and so neither counts nor reads
// as a pass.
type Check struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Tier      string `json:"tier"`
	Weight    int    `json:"weight"`
	Triggered bool   `json:"triggered"`
	Skipped   bool   `json:"skipped,omitempty"`
	// Suppressed marks a rule that fired but did not dock the score because it is
	// expected of a verified good bot (bot-shaped, from a datacenter). The row still
	// shows in the breakdown, as "expected" rather than a deduction.
	Suppressed bool   `json:"suppressed,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

// Report is the content-negotiated result the transport layer renders as HTML or
// JSON. Score is an authenticity score: 100 = looks fully human, 0 = looks fully
// automated. Bot is set when the User-Agent is a recognised crawler / AI agent
// (verified or not); a verified one also overrides Verdict to "good-bot".
type Report struct {
	Score   int          `json:"score"`
	Verdict string       `json:"verdict"` // "human" | "suspicious" | "bot" | "good-bot"
	Bot     *BotIdentity `json:"bot,omitempty"`
	Checks  []Check      `json:"checks"`
}

// Scoring constants. The soft rule (borrowed from deviceandbrowserinfo) is that
// no single weak signal may ever produce a false positive: a soft hit is ignored
// until at least softComboThreshold soft signals fire together, at which point
// the whole cluster promotes to one softComboWeight deduction.
const (
	humanFloor         = 80 // score ≥ this ⇒ "human"
	suspiciousFloor    = 50 // score ≥ this ⇒ "suspicious"; below ⇒ "bot"
	softComboThreshold = 3
	softComboWeight    = 25
	// collectorVDeepTamper is the payload version that introduced the G04
	// deep-tamper fields (nativeDescriptorsOK / nativeCallNewOK /
	// nativeToStringProxied). Those fields are damning when false and a missing
	// JSON key binds false, so the G04 rules skip payloads older than this —
	// a returning visitor with a stale cached collector must not read as tampered.
	collectorVDeepTamper = 2
)

// Evaluate runs every rule against the signals and returns the scored report. It
// is a pure function of its input — no DB, no globals, no clock — so it is
// trivially testable and race-free. Score starts at 100 and each triggered
// hard/consistency rule subtracts its weight; soft rules are summed separately
// and only bite as a cluster.
func Evaluate(s Signals) Report {
	// Identify a recognised crawler / AI agent up front (nil for anything else). A
	// *verified* one (operator corroborated by the egress ASN) is expected to look
	// bot-shaped, so its expected deductions are suppressed below and its verdict is
	// overridden — but only verified: an unverified UA claim is labelled, not excused.
	bot := classifyGoodBot(clientUA(s), s.ASN)
	suppress := bot != nil && bot.Verified

	checks := make([]Check, 0, len(rules))
	deduction := 0

	for _, r := range rules {
		skipped := r.needsClient && !s.ClientCollected
		triggered, detail := false, ""
		if !skipped {
			triggered, detail = r.eval(s)
		}
		c := Check{
			ID: r.id, Label: r.label, Tier: r.tier, Weight: r.weight,
			Triggered: triggered, Skipped: skipped, Detail: detail,
		}
		// Hard/consistency rules dock their weight immediately; soft rules never bite
		// individually — they cost one softComboWeight only as a cluster, applied once
		// below. For a verified good bot, the expected-crawler deductions are recorded
		// but not counted (they'd wrongly tank a legitimate crawler's score).
		if triggered && r.tier != TierSoft {
			if suppress && suppressedForGoodBot[r.id] {
				c.Suppressed = true
			} else {
				deduction += r.weight
			}
		}
		checks = append(checks, c)
	}

	// SoftClusterActive (SoftFired ≥ softComboThreshold) is the single source of
	// truth for the soft-cluster rule, shared by scoring here and the display helpers.
	report := Report{Checks: checks, Bot: bot}
	if report.SoftClusterActive() {
		deduction += softComboWeight
	}

	report.Score = max(0, 100-deduction)
	report.Verdict = verdictFor(report.Score)
	if suppress {
		report.Verdict = "good-bot" // classification override, independent of the score
	}
	return report
}

// suppressedForGoodBot are the deductions a genuine verified crawler is expected to
// trip — being a bot, from a datacenter/hosting network. They are recorded but not
// counted for a corroborated good bot, so its score reads coherently. Every other
// rule (webdriver, CDP, native tamper, …) still counts, so a compromised host inside
// the operator's own network would still surface in the breakdown.
var suppressedForGoodBot = map[string]bool{
	"bot_user_agent": true,
	"datacenter_ip":  true,
	"proxy_ip":       true,
}

func verdictFor(score int) string {
	switch {
	case score >= humanFloor:
		return "human"
	case score >= suspiciousFloor:
		return "suspicious"
	default:
		return "bot"
	}
}

// --- shared signal helpers (used by the rule predicates in scoring.go) --------

// osFromUA normalises the OS named in a User-Agent string to the vocabulary
// navigator.userAgentData.platform uses ("Windows", "macOS", "Linux",
// "Android", "iOS", "Chrome OS"). "" means "couldn't tell" — callers treat that
// as "no mismatch" rather than a trigger. Order matters: Android and CrOS UAs
// also contain "Linux", and iOS UAs contain "like Mac OS X".
func osFromUA(ua string) string {
	switch {
	case strings.Contains(ua, "Windows"):
		return "Windows"
	case strings.Contains(ua, "Android"):
		return "Android"
	case strings.Contains(ua, "iPhone"), strings.Contains(ua, "iPad"):
		return "iOS"
	case strings.Contains(ua, "CrOS"):
		return "Chrome OS"
	case strings.Contains(ua, "Mac OS X"), strings.Contains(ua, "Macintosh"):
		return "macOS"
	case strings.Contains(ua, "Linux"), strings.Contains(ua, "X11"):
		return "Linux"
	default:
		return ""
	}
}

// normPlatform folds userAgentData/Sec-CH-UA-Platform values into the same
// vocabulary osFromUA returns (Chromium reports "macOS" but quotes the CH header
// value, and older/edge cases vary), so the two are comparable.
func normPlatform(p string) string {
	p = strings.Trim(strings.TrimSpace(p), `"`)
	switch strings.ToLower(p) {
	case "windows":
		return "Windows"
	case "macos", "mac os x", "macintosh":
		return "macOS"
	case "linux":
		return "Linux"
	case "android":
		return "Android"
	case "ios", "iphone", "ipados":
		return "iOS"
	case "chrome os", "chromeos", "cros":
		return "Chrome OS"
	default:
		return p
	}
}

// isSoftwareRenderer reports whether a WebGL renderer string is a software
// rasteriser — a strong "headless / no GPU" tell on a desktop browser.
func isSoftwareRenderer(r string) bool {
	r = strings.ToLower(r)
	for _, m := range []string{"swiftshader", "llvmpipe", "mesa offscreen", "software", "microsoft basic render"} {
		if strings.Contains(r, m) {
			return true
		}
	}
	return false
}

// gpuVendorFamily normalises a WebGL unmasked vendor and/or renderer string to a
// GPU vendor family: "apple", "nvidia", "amd", "intel", "adreno" or "mali". It
// copes with every real reporting style — Chrome's ANGLE pair ("Google Inc.
// (NVIDIA)" + "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 ...)"),
// Safari's generalised "Apple Inc." / "Apple GPU", Firefox's plain
// "NVIDIA Corporation" / "GeForce ..." — because the ANGLE wrapper and the
// "Google Inc. (...)" shim always carry the true vendor inside them, so a
// substring search over the lowercased concatenation suffices. "" means
// "couldn't tell" (VM passthrough strings, software rasterisers, masked
// values); callers treat that as "no signal", never as a mismatch — that is
// what keeps llvmpipe-on-Linux and VMware guests from tripping the GPU rules.
func gpuVendorFamily(vendor, renderer string) string {
	s := strings.ToLower(vendor + " " + renderer)
	switch {
	case strings.Contains(s, "apple"):
		return "apple"
	case strings.Contains(s, "nvidia"), strings.Contains(s, "geforce"), strings.Contains(s, "quadro"):
		return "nvidia"
	case strings.Contains(s, "amd"), strings.Contains(s, "radeon"), strings.Contains(s, "ati technologies"):
		return "amd"
	case strings.Contains(s, "intel"):
		return "intel"
	case strings.Contains(s, "adreno"), strings.Contains(s, "qualcomm"):
		return "adreno"
	case strings.Contains(s, "mali"):
		return "mali"
	default:
		return ""
	}
}

// botUATokens are headless browsers, scripting HTTP clients, and self-declared
// bots — definitive non-browser tells (unlike Electron, handled separately).
var botUATokens = []string{
	"headlesschrome", "headless", "phantomjs", "slimerjs",
	"python-requests", "go-http-client", "curl/", "wget", "scrapy",
	"okhttp", "java/", "libwww", "node-fetch", "axios", "httpclient",
	"bot", "spider", "crawler",
}

// embeddedRuntimeTokens are browser engines embedded in a desktop app — real
// Chromium/WebKit engines, legitimate for an app but unusual for browsing
// arbitrary sites, so a suspicious (not definitive) signal.
var embeddedRuntimeTokens = []string{"electron", "cef ", "cefsharp", "qtwebengine", "nw.js", "nwjs"}

// botUAToken returns the first botUATokens match in a User-Agent (or "" for
// none). An empty UA counts as a token: real browsers always send one.
func botUAToken(ua string) string {
	if strings.TrimSpace(ua) == "" {
		return "(empty user-agent)"
	}
	return firstToken(ua, botUATokens)
}

func embeddedRuntimeToken(ua string) string { return firstToken(ua, embeddedRuntimeTokens) }

// looksLikeBrowser reports whether a User-Agent claims to be a mainstream
// interactive browser — the precondition for "a real browser would have sent
// header X" checks. It excludes UAs already caught as bots/HTTP clients.
func looksLikeBrowser(ua string) bool {
	if ua == "" || !strings.HasPrefix(ua, "Mozilla/") || botUAToken(ua) != "" {
		return false
	}
	for _, m := range []string{"Chrome", "Firefox", "Safari", "Edg", "OPR"} {
		if strings.Contains(ua, m) {
			return true
		}
	}
	return false
}

// clientUA returns the browser's own reported User-Agent (navigator.userAgent),
// falling back to the HTTP header when the client half wasn't collected.
func clientUA(s Signals) string {
	if s.NavMainUA != "" {
		return s.NavMainUA
	}
	return s.HTTPUserAgent
}

// engineFromUA maps a User-Agent to the rendering engine a genuine browser with
// that UA must run: "blink" (Chrome/Edge/Opera/Chromium), "gecko" (Firefox),
// "webkit" (Safari and every iOS browser — Apple mandates WebKit there). "" means
// "can't tell", so a mismatch rule treats it as no signal. iOS is checked first
// because CriOS/FxiOS UAs carry a brand token but still run WebKit. It is the
// single source of truth for UA→engine inference (see expectedProductSub).
func engineFromUA(ua string) string {
	switch {
	case ua == "":
		return ""
	case osFromUA(ua) == "iOS":
		return "webkit"
	case strings.Contains(ua, "Firefox"):
		return "gecko"
	case strings.Contains(ua, "Edg"), strings.Contains(ua, "OPR"),
		strings.Contains(ua, "Chrome"), strings.Contains(ua, "Chromium"):
		return "blink"
	case strings.Contains(ua, "Safari"):
		return "webkit"
	default:
		return ""
	}
}

// expectedProductSub returns the navigator.productSub constant every mainstream
// browser on this engine reports: Gecko always "20100101", WebKit/Blink always
// "20030107". It derives the engine from engineFromUA (single source of truth), so
// iOS browsers — WebKit whatever their FxiOS/CriOS brand token — are classified
// correctly. "" ⇒ can't tell (don't fire).
func expectedProductSub(ua string) string {
	switch engineFromUA(ua) {
	case "gecko":
		return "20100101"
	case "blink", "webkit":
		return "20030107"
	default:
		return ""
	}
}

// majorOf parses the leading integer of a dotted version ("125.0.6422.60" ⇒ 125).
// 0 ⇒ no leading digits.
func majorOf(v string) int {
	v = strings.TrimSpace(v)
	i := 0
	for i < len(v) && v[i] >= '0' && v[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0
	}
	n, _ := strconv.Atoi(v[:i])
	return n
}

// uaChromeMajor parses the Chromium major version from a UA's "Chrome/125.0.0.0"
// token — the version Chrome/Edge/Opera all track. 0 ⇒ not a Chromium UA.
func uaChromeMajor(ua string) int {
	const tok = "Chrome/"
	if i := strings.Index(ua, tok); i >= 0 {
		return majorOf(ua[i+len(tok):])
	}
	return 0
}

// chVersionMajor returns the Chromium engine major userAgentData reports — the
// "Chromium" brand entry of fullVersionList (falling back to "Google Chrome"). That
// is exactly the value the UA's "Chrome/NNN" token carries, so comparing the two is
// valid for every Chromium browser: forks whose branded version diverges (Opera
// 111, Vivaldi 7, Samsung 24 — all on Chromium ~125) still expose the true Chromium
// major here and so don't false-positive. uaFullVersion is deliberately NOT read —
// it carries the fork's branded version, not the engine's. 0 ⇒ not reported.
func chVersionMajor(u UAData) int {
	var googleChrome int
	for _, bv := range u.FullVersionList {
		switch strings.ToLower(strings.TrimSpace(bv.Brand)) {
		case "chromium":
			if m := majorOf(bv.Version); m > 0 {
				return m
			}
		case "google chrome":
			if googleChrome == 0 {
				googleChrome = majorOf(bv.Version)
			}
		}
	}
	return googleChrome
}

// firstToken returns the first token that appears (case-insensitively) in ua.
func firstToken(ua string, tokens []string) string {
	l := strings.ToLower(ua)
	for _, t := range tokens {
		if strings.Contains(l, t) {
			return strings.TrimSpace(t)
		}
	}
	return ""
}

// offsetFormat reports whether s is a UTC offset like "+03:00" / "-08:00" — the
// shape IP2Location returns for a timezone (as opposed to an IANA name).
func offsetFormat(s string) bool {
	return len(s) > 0 && (s[0] == '+' || s[0] == '-')
}

// zoneOffsetSeconds resolves an IANA timezone name (e.g. "Europe/Moscow") to its
// UTC offset in seconds east of UTC at time at (DST-aware). Returns false if the
// zone can't be loaded or at is the zero time (can't tell).
func zoneOffsetSeconds(zone string, at time.Time) (int, bool) {
	if at.IsZero() {
		return 0, false
	}
	loc, err := time.LoadLocation(zone)
	if err != nil {
		return 0, false
	}
	_, secs := at.In(loc).Zone()
	return secs, true
}

// ianaOffset formats a zone's current offset like IP2Location's "+03:00".
func ianaOffset(zone string, at time.Time) (string, bool) {
	secs, ok := zoneOffsetSeconds(zone, at)
	if !ok {
		return "", false
	}
	sign := "+"
	if secs < 0 {
		sign, secs = "-", -secs
	}
	return fmt.Sprintf("%s%02d:%02d", sign, secs/3600, (secs%3600)/60), true
}

// chBrandNames extracts the brand names from a Sec-CH-UA structured header like
// `"Chromium";v="125", "Google Chrome";v="125", "Not.A/Brand";v="24"` — the
// first quoted token in each comma-separated entry.
func chBrandNames(header string) []string {
	var out []string
	for _, part := range strings.Split(header, ",") {
		if i := strings.IndexByte(part, '"'); i >= 0 {
			if j := strings.IndexByte(part[i+1:], '"'); j >= 0 {
				out = append(out, part[i+1:][:j])
			}
		}
	}
	return out
}

// realBrandSet lowercases brand names and drops the GREASE entry (the decoy brand
// always contains "Brand", e.g. "Not.A/Brand"), leaving only genuine brands.
func realBrandSet(names []string) map[string]bool {
	set := map[string]bool{}
	for _, n := range names {
		if strings.Contains(strings.ToLower(n), "brand") {
			continue
		}
		set[strings.ToLower(strings.TrimSpace(n))] = true
	}
	return set
}

func sameStringSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// Group returns the checks in one tier, in rule order — used by the template to
// render the breakdown in labelled groups.
func (r Report) Group(tier string) []Check {
	out := make([]Check, 0, len(r.Checks))
	for _, c := range r.Checks {
		if c.Tier == tier {
			out = append(out, c)
		}
	}
	return out
}

// SoftFired reports how many soft-tier signals triggered. Soft signals never dock
// points individually — they only cost the score once softComboThreshold of them
// fire together (see Evaluate) — so the template shows each as "flagged" rather
// than a per-row deduction and, when the cluster is active, adds a single line for
// the real penalty. Keeps the displayed numbers matching what actually moved the score.
func (r Report) SoftFired() int {
	n := 0
	for _, c := range r.Checks {
		if c.Tier == TierSoft && c.Triggered {
			n++
		}
	}
	return n
}

// SoftClusterActive reports whether enough soft signals fired to apply the cluster
// penalty — the only case where soft signals move the score.
func (r Report) SoftClusterActive() bool { return r.SoftFired() >= softComboThreshold }

// SoftClusterPenalty is the score cost of an active soft cluster.
func (r Report) SoftClusterPenalty() int { return softComboWeight }

// primaryLang extracts the base language subtag from a languages list or an
// Accept-Language header (e.g. "en-US,ru;q=0.9" → "en"). "" if none.
func primaryLang(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if i := strings.IndexAny(s, ",;"); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(strings.TrimSpace(s))
}
