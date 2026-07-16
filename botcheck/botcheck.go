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
// The one load-bearing idea (see docs/tools/botornot/): every client signal is
// spoofable, so the strongest checks are the cross-layer/cross-context
// consistency ones — what the browser *claims* (JS) vs. what the connection
// *shows* (headers, IP) vs. what a second JS context reports (Worker/iframe).
package botcheck

import "strings"

// UAData is the subset of navigator.userAgentData.getHighEntropyValues() the
// collector reports. It exists so Go can cross-check the JS-reported platform
// against the Sec-CH-UA* request headers and the legacy User-Agent string.
type UAData struct {
	Platform        string `json:"platform"`
	PlatformVersion string `json:"platform_version"`
	Architecture    string `json:"architecture"`
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

	// ── server-observed (filled by the handler; never read off the wire) ─────
	HTTPUserAgent   string `json:"-"`
	SecCHUAPlatform string `json:"-"`
	SecFetchMode    string `json:"-"` // Sec-Fetch-Mode header (real browsers always send it)
	AcceptLanguage  string `json:"-"`
	IPCountry       string `json:"-"`
	IPTimezone      string `json:"-"`
	IsDatacenter    bool   `json:"-"`
	IsProxy         bool   `json:"-"`
	IsVPN           bool   `json:"-"`
	IsTor           bool   `json:"-"`
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
	Detail    string `json:"detail,omitempty"`
}

// Report is the content-negotiated result the transport layer renders as HTML or
// JSON. Score is an authenticity score: 100 = looks fully human, 0 = looks fully
// automated.
type Report struct {
	Score   int     `json:"score"`
	Verdict string  `json:"verdict"` // "human" | "suspicious" | "bot"
	Checks  []Check `json:"checks"`
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
)

// Evaluate runs every rule against the signals and returns the scored report. It
// is a pure function of its input — no DB, no globals, no clock — so it is
// trivially testable and race-free. Score starts at 100 and each triggered
// hard/consistency rule subtracts its weight; soft rules are summed separately
// and only bite as a cluster.
func Evaluate(s Signals) Report {
	checks := make([]Check, 0, len(rules))
	deduction, softTriggered := 0, 0

	for _, r := range rules {
		skipped := r.needsClient && !s.ClientCollected
		triggered, detail := false, ""
		if !skipped {
			triggered, detail = r.eval(s)
		}
		checks = append(checks, Check{
			ID: r.id, Label: r.label, Tier: r.tier, Weight: r.weight,
			Triggered: triggered, Skipped: skipped, Detail: detail,
		})
		if !triggered {
			continue
		}
		if r.tier == TierSoft {
			softTriggered++
		} else {
			deduction += r.weight
		}
	}

	if softTriggered >= softComboThreshold {
		deduction += softComboWeight
	}

	score := max(0, 100-deduction)
	return Report{Score: score, Verdict: verdictFor(score), Checks: checks}
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

// cleanPlaceholder maps IP2Location/IP2Proxy's "-" (unknown) placeholder to an
// empty string, so an unknown IP timezone/country is treated as "no signal"
// rather than a real value the cross-checks could spuriously trip on.
func cleanPlaceholder(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

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
