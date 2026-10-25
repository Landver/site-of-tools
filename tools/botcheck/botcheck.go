// Package botcheck scores how human a browser looks by cross-checking its claims against what it shows.
package botcheck

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	// Embeds the IANA tz DB so time.LoadLocation works on the distroless image.
	_ "time/tzdata"
)

// UAData.FullVersionList catches a UA spoof that edits "Chrome/NNN" but leaves userAgentData intact.
type UAData struct {
	Platform        string         `json:"platform"`
	FullVersionList []BrandVersion `json:"fullVersionList"`
}

// BrandVersion is one fullVersionList entry; the GREASE decoy brand is ignored on read.
type BrandVersion struct {
	Brand   string `json:"brand"`
	Version string `json:"version"`
}

// ConnectionInfo is navigator.connection, absent on most Firefox/Safari; zero values are never a signal.
type ConnectionInfo struct {
	EffectiveType string  `json:"effectiveType"` // "slow-2g" | "2g" | "3g" | "4g"
	Downlink      float64 `json:"downlink"`      // Mbps estimate (0 = not supplied)
	RTT           int     `json:"rtt"`           // ms estimate (0 = not supplied)
	SaveData      bool    `json:"saveData"`      // user asked for reduced data usage
}

// PermissionSample is entropy only: no rule scores its values, which are user preferences.
type PermissionSample struct {
	Notifications string `json:"notifications"`
	Geolocation   string `json:"geolocation"`
}

// EnvInfo is raw-dump entropy except matchMedia and connection, which v4-gated rules score.
type EnvInfo struct {
	MatchMedia     bool             `json:"matchMedia"`     // window.matchMedia is a function — always sent by v4 collector
	DPR            float64          `json:"dpr"`            // devicePixelRatio (0 = not supplied)
	ColorScheme    string           `json:"colorScheme"`    // prefers-color-scheme: "light" | "dark"
	ForcedColors   bool             `json:"forcedColors"`   // forced-colors: active (Windows High Contrast)
	ReducedMotion  bool             `json:"reducedMotion"`  // prefers-reduced-motion: reduce
	DynamicRange   string           `json:"dynamicRange"`   // "high" | "standard"
	Gamut          string           `json:"gamut"`          // widest supported color-gamut: "rec2020" | "p3" | "srgb"
	Connection     ConnectionInfo   `json:"connection"`     // navigator.connection (zero = API absent)
	StorageQuotaMB int              `json:"storageQuotaMB"` // navigator.storage.estimate().quota, MB (0 = not supplied)
	GPC            *bool            `json:"gpc"`            // navigator.globalPrivacyControl (nil = browser doesn't expose it)
	Permissions    PermissionSample `json:"permissions"`    // tiny Permissions API sample
	EMEClearKey    *bool            `json:"emeClearKey"`    // ClearKey EME available (nil = probe couldn't run)
}

// Signals: zero = not supplied; ClientCollected separates a browser reporting false from no fingerprint.
type Signals struct {
	ClientCollected bool `json:"-"`
	HeadersSupplied bool `json:"-"`
	IPSupplied      bool `json:"-"`

	// CollectorV lets rules on false-when-missing fields skip payloads from a stale cached botcheck.js.
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
	WebGLVendor      string   `json:"webglVendor"` // UNMASKED_VENDOR_WEBGL, e.g. "Google Inc. (Apple)"
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
	CanvasBlank     bool     `json:"canvasBlank"`     // drawn canvas has no non-transparent pixels
	Brands          []string `json:"brands"`          // navigator.userAgentData.brands names
	CodecH264       bool     `json:"codecH264"`       // <video> can play H.264
	CodecAAC        bool     `json:"codecAAC"`        // <audio> can play AAC
	FontCount       int      `json:"fontCount"`       // probe fonts detected (-1 = couldn't measure)

	// ── quick-win client signals (G01/G02/G05) ───────────────────────────────
	ProductSub string `json:"productSub"` // navigator.productSub — engine constant ("20030107" WebKit/Blink, "20100101" Gecko)
	Engine     string `json:"engine"`     // feature-detected engine family: "blink" | "gecko" | "webkit"

	// ── cross-context client signals (G03) ───────────────────────────────────
	// Spoofs mostly patch only the top frame; an empty value means that context was silent, never evidence.
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
	// Fail-to-pass like NativeToStringOK: false only on a confirmed tamper, so false is damning.
	NativeDescriptorsOK bool `json:"nativeDescriptorsOK"` // descriptor/own-property sanity on natives
	NativeCallNewOK     bool `json:"nativeCallNewOK"`     // call/new TypeError traps behave
	// NativeToStringProxied is inverted, true = bad: a proxied toString is a stealth-plugin hallmark.
	NativeToStringProxied bool `json:"nativeToStringProxied"`

	// ── v3 batch signals (G09–G14, G17, G22, G23 + Layer-1 backlog) ───────────
	// The two OK bools fail-to-pass, so their rules are v3-gated; true-is-bad and value fields need no gate.
	IframeWebdriver       bool     `json:"iframeWebdriver"`       // navigator.webdriver re-read inside the iframe (G11)
	IframeProxied         bool     `json:"iframeProxied"`         // iframe contentWindow Proxy detected — true = bad (G11)
	MaxTouchPoints        int      `json:"maxTouchPoints"`        // navigator.maxTouchPoints (G12)
	SWWebdriver           bool     `json:"swWebdriver"`           // navigator.webdriver read in the Service Worker (G14)
	SWCDP                 bool     `json:"swCDP"`                 // the CDP Error.stack trap fired in the Service Worker (G14)
	NavProtoDescriptorsOK bool     `json:"navProtoDescriptorsOK"` // fail-to-pass OK bool: WebIDL accessor-descriptor walk (G17)
	ChromeRuntimeOK       bool     `json:"chromeRuntimeOK"`       // fail-to-pass OK bool: chrome.runtime integrity (G22)
	ChromeLateInjection   bool     `json:"chromeLateInjection"`   // window.chrome injected late — true = bad (G22)
	JSEngine              string   `json:"jsEngine"`              // feature-detected JS engine: "v8" | "spidermonkey" | "jsc" (G23)
	WebRTCIPs             []string `json:"webrtcIPs"`             // deduped ICE candidate IPs, mDNS .local skipped (G09)
	ImageBroken           bool     `json:"imageBroken"`           // a guaranteed-loadable 1×1 image failed — true = bad (G10)
	MimeTypes             int      `json:"mimeTypes"`             // navigator.mimeTypes.length (Layer-1 backlog)
	OuterH                int      `json:"outerH"`                // window.outerHeight (Layer-1 backlog)
	InnerH                int      `json:"innerH"`                // window.innerHeight (Layer-1 backlog)

	// ── v4 batch signals (G15/G21) ───────────────────────────────────────────
	// v4-gated (collectorVTamperV4): a stale v3 collector never sends env, and its zeros aren't evidence.
	Env EnvInfo `json:"env"`

	// ── server-observed (filled by the handler; never read off the wire) ─────
	HTTPUserAgent      string `json:"-"`
	SecCHUAPlatform    string `json:"-"`
	SecCHUA            string `json:"-"` // full Sec-CH-UA header (brand list)
	SecFetchMode       string `json:"-"` // Sec-Fetch-Mode header (real browsers always send it)
	AcceptLanguage     string `json:"-"`
	HTTPAccept         string `json:"-"` // Accept header; browser nav/fetch Accept includes text/html
	HTTPAcceptEncoding string `json:"-"` // Accept-Encoding header; every real browser sends one, every request
	IPTimezone         string `json:"-"`
	EgressIP           string `json:"-"` // connection IP server observed (c.RealIP()), for WebRTC cross-check (G09)
	ASN                string `json:"-"` // egress ASN number (IP2Location), for good-bot corroboration
	IsDatacenter       bool   `json:"-"`
	IsProxy            bool   `json:"-"`
	IsVPN              bool   `json:"-"`
	IsTor              bool   `json:"-"`
	// FingerprintIPs: distinct IPs with this fingerprint in the 30-day corpus; 0 = no data, never evidence.
	FingerprintIPs int `json:"-"`
	// FingerprintChurn: distinct fingerprints from this IP within churnWindow; 0 = no data, never evidence.
	FingerprintChurn int `json:"-"`
	// CorpusConsulted: the corpus counts above were read; without it the corpus rules skip.
	CorpusConsulted bool `json:"-"`
	// IPBlocklist* are handler-computed (it owns iptools' source names); Count = ipsum feeds listing the IP,
	// Deliberate = a non-ipsum ban, trusted regardless of Count.
	IPBlocklistSources    []string `json:"-"`
	IPBlocklistCount      int      `json:"-"`
	IPBlocklistDeliberate bool     `json:"-"`

	// Now is stamped by the handler so Evaluate stays pure; it resolves the browser tz's DST-aware offset.
	Now time.Time `json:"-"`
}

// Tier: how damning a check is; drives the soft-cluster rule and the table colour.
const (
	TierHard        = "hard"        // near-standalone bot proof
	TierConsistency = "consistency" // combination that shouldn't co-occur
	TierSoft        = "soft"        // weak alone; only counts in cluster
)

// Consistency-tier subgroups: display only, no scoring effect.
const (
	subgroupNetwork   = "network"
	subgroupUA        = "ua"
	subgroupContext   = "context"
	subgroupInternals = "internals"
)

// Check: Skipped = couldn't evaluate (e.g. a client rule on a server-only request), neither pass nor hit.
type Check struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Tier      string `json:"tier"`
	Subgroup  string `json:"-"`
	Weight    int    `json:"weight"`
	Triggered bool   `json:"triggered"`
	Skipped   bool   `json:"skipped,omitempty"`
	// Suppressed: fired but not counted, as expected of a verified good bot.
	Suppressed bool   `json:"suppressed,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

// Report.Score is authenticity: 100 = human, 0 = automated. ClientPayload is nil on the server-only GET.
type Report struct {
	Score         int          `json:"score"`
	Verdict       string       `json:"verdict"` // "human" | "suspicious" | "bot" | "good-bot"
	Bot           *BotIdentity `json:"bot,omitempty"`
	Coverage      Coverage     `json:"coverage"`
	Checks        []Check      `json:"checks"`
	ClientPayload *Signals     `json:"clientPayload,omitempty"`
	// Corpus count behind fingerprint_reuse; 0 (corpus off, first sighting) stays hidden.
	FingerprintIPs int `json:"fingerprintIPs,omitempty"`
	// Corpus count behind ip_fingerprint_churn; 0 stays hidden the same way.
	FingerprintChurn int `json:"fingerprintChurn,omitempty"`
}

type Coverage struct {
	Hard        TierCoverage `json:"hard"`
	Consistency TierCoverage `json:"consistency"`
	Soft        TierCoverage `json:"soft"`
}

// TierCoverage: Evaluated + Skipped = the tier's checks; Fired counts suppressed good-bot hits too.
type TierCoverage struct {
	Evaluated int `json:"evaluated"`
	Skipped   int `json:"skipped"`
	Fired     int `json:"fired"`
}

func (c *Coverage) add(ch Check) {
	var t *TierCoverage
	switch ch.Tier {
	case TierHard:
		t = &c.Hard
	case TierConsistency:
		t = &c.Consistency
	case TierSoft:
		t = &c.Soft
	default:
		return
	}
	if ch.Skipped {
		t.Skipped++
		return
	}
	t.Evaluated++
	if ch.Triggered {
		t.Fired++
	}
}

// RawJSON is exactly what the browser POSTed: every server-observed Signals field must stay json:"-".
func (s Signals) RawJSON() string {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}

// FingerprintHash covers only stable fields a farm locks when cloning a profile (no window geometry, canvas
// or server fields), so one browser keeps one hash across visits.
func (s Signals) FingerprintHash() string {
	fields := []string{
		s.NavMainUA,
		strings.Join(s.Languages, ","),
		s.UAData.Platform,
		strconv.Itoa(s.HardwareCores),
		strconv.FormatFloat(s.DeviceMemory, 'f', -1, 64),
		strconv.Itoa(s.ScreenW),
		strconv.Itoa(s.ScreenH),
		strconv.Itoa(s.ColorDepth),
		s.BrowserTZ,
		s.WebGLVendor,
		s.WebGLRenderer,
		s.ProductSub,
		s.Engine,
		strconv.Itoa(s.FontCount),
	}
	sum := sha256.Sum256([]byte(strings.Join(fields, "\x1f")))
	return hex.EncodeToString(sum[:])
}

// Soft rule (from deviceandbrowserinfo): soft hits count only once softComboThreshold fire together.
const (
	humanFloor         = 80 // score ≥ this ⇒ "human"
	suspiciousFloor    = 50 // score ≥ this ⇒ "suspicious"; below ⇒ "bot"
	softComboThreshold = 3
	softComboWeight    = 25
	// collectorVDeepTamper: first payload with the G04 fields; older ones skip those rules.
	collectorVDeepTamper = 2
	// collectorVTamperV3: first payload with the v3 fields that are damning when false or zero.
	collectorVTamperV3 = 3
	// collectorVTamperV4: first payload with the "env" section; a v3 collector's zeros aren't evidence.
	collectorVTamperV4 = 4
	// Below 5 IPs: one person roaming home, work and mobile networks; at 5: a proxy pool.
	fingerprintReuseMinIPs = 5
	// Below 8 fingerprints: a household's devices, or someone re-checking after a browser tweak.
	fingerprintChurnMinHashes = 8
	// churnWindow: short enough that a normal address's few devices never reach the floor.
	churnWindow = 10 * time.Minute
	// 3 = ipsum README's auto-ban advice ("at least 3 (black)lists"); one feed alone could dock a human on a
	// recycled residential IP. A deliberate ban from any other source bypasses this floor.
	ipsumBlocklistFloor = 3
)

// Evaluate is pure (no DB, globals or clock): score starts at 100, hard/consistency hits subtract weight.
func Evaluate(s Signals) Report {
	// Only an ASN-verified bot gets suppression; an unverified UA claim is labelled, not excused.
	bot := classifyGoodBot(clientUA(s), s.ASN)
	suppress := bot != nil && bot.Verified

	checks := make([]Check, 0, len(rules))
	var coverage Coverage
	deduction := 0

	for _, r := range rules {
		skipped := r.needsClient && !s.ClientCollected ||
			r.needsHeaders && !s.HeadersSupplied ||
			r.needsIP && !s.IPSupplied ||
			r.needsCorpus && !s.CorpusConsulted
		triggered, detail := false, ""
		if !skipped {
			triggered, detail = r.eval(s)
		}
		c := Check{
			ID: r.id, Label: r.label, Tier: r.tier, Subgroup: r.subgroup, Weight: r.weight,
			Triggered: triggered, Skipped: skipped, Detail: detail,
		}
		// Soft hits cost one cluster charge below; a verified bot's expected hits are recorded, not counted.
		if triggered && r.tier != TierSoft {
			if suppress && suppressedForGoodBot[r.id] {
				c.Suppressed = true
			} else {
				deduction += r.weight
			}
		}
		checks = append(checks, c)
		coverage.add(c)
	}

	// SoftClusterActive is the single source of truth for the soft cluster, shared with display helpers.
	report := Report{Checks: checks, Coverage: coverage, Bot: bot, FingerprintIPs: s.FingerprintIPs, FingerprintChurn: s.FingerprintChurn}
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

// suppressedForGoodBot: hits a verified crawler is expected to trip. Every other rule still counts, so a
// compromised host inside the operator's network still surfaces.
var suppressedForGoodBot = map[string]bool{
	"bot_user_agent":    true,
	"datacenter_ip":     true,
	"proxy_ip":          true,
	"fingerprint_reuse": true,
	// Crawler egress can land on abuse lists (shared cloud ranges, recycled IPs).
	"ip_blocklisted": true,
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

// --- shared signal helpers (used by rule predicates in scoring.go) ---

// osFromUA: order matters, as Android/CrOS UAs also contain "Linux" and iOS "like Mac OS X". "" = can't tell.
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

// normPlatform folds userAgentData and the quoted Sec-CH-UA-Platform into osFromUA's vocabulary.
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

func isSoftwareRenderer(r string) bool {
	r = strings.ToLower(r)
	for _, m := range []string{
		"swiftshader", "llvmpipe", "lavapipe", "swrast", "softpipe", "virgl",
		"mesa offscreen", "software", "microsoft basic render",
		"svga3d", "vmware", "virtualbox", "vbox", "qemu",
	} {
		if strings.Contains(r, m) {
			return true
		}
	}
	return false
}

// gpuVendorFamily: ANGLE and "Google Inc. (...)" carry the true vendor, so substring search suffices.
// "" (VMs, software rasterisers, masked values) is never a mismatch, so llvmpipe and VMware stay silent.
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

// botUATokens: definitive non-browser tells; embedded runtimes like Electron are only suspicious.
var botUATokens = []string{
	"headlesschrome", "headless", "phantomjs", "slimerjs",
	"python-requests", "go-http-client", "curl/", "wget", "scrapy",
	"okhttp", "java/", "libwww", "node-fetch", "axios", "httpclient",
	"bot", "spider", "crawler",
}

var embeddedRuntimeTokens = []string{"electron", "cef ", "cefsharp", "qtwebengine", "nw.js", "nwjs"}

// botUAToken treats an empty UA as a bot token: real browsers always send one.
func botUAToken(ua string) string {
	if strings.TrimSpace(ua) == "" {
		return "(empty user-agent)"
	}
	return firstToken(ua, botUATokens)
}

func embeddedRuntimeToken(ua string) string { return firstToken(ua, embeddedRuntimeTokens) }

// looksLikeBrowser gates the "a real browser would have sent header X" checks.
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

// clientUA falls back to the HTTP header when the client half wasn't collected.
func clientUA(s Signals) string {
	if s.NavMainUA != "" {
		return s.NavMainUA
	}
	return s.HTTPUserAgent
}

// engineFromUA checks iOS first: CriOS/FxiOS still run WebKit, which Apple mandates. "" = can't tell.
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

func jsEngineFromUA(ua string) string {
	switch engineFromUA(ua) {
	case "blink":
		return "v8"
	case "gecko":
		return "spidermonkey"
	case "webkit":
		return "jsc"
	default:
		return ""
	}
}

// ectRank orders effectiveType slowest to fastest; 0 = unknown, never a mismatch.
func ectRank(ect string) int {
	switch ect {
	case "slow-2g":
		return 1
	case "2g":
		return 2
	case "3g":
		return 3
	case "4g":
		return 4
	default:
		return 0
	}
}

func ectName(rank int) string {
	switch rank {
	case 1:
		return "slow-2g"
	case 2:
		return "2g"
	case 3:
		return "3g"
	default:
		return "4g"
	}
}

// ectFromRTT graces the spec thresholds: the page sees rtt rounded to 50ms, while the browser derived
// effectiveType from the raw estimate.
func ectFromRTT(rtt int) int {
	switch {
	case rtt >= 2050: // spec: ≥ 2000 ⇒ slow-2g
		return 1
	case rtt >= 1450: // spec: ≥ 1400 ⇒ 2g
		return 2
	case rtt >= 320: // spec: ≥ 270 ⇒ 3g
		return 3
	default:
		return 4
	}
}

// ectFromDownlink: same rounding grace as ectFromRTT (downlink rounds to 0.05 Mbps).
func ectFromDownlink(downlink float64) int {
	switch {
	case downlink < 0.10: // spec: < 0.05 ⇒ slow-2g
		return 1
	case downlink < 0.12: // spec: < 0.07 ⇒ 2g
		return 2
	case downlink < 0.75: // spec: < 0.7 ⇒ 3g
		return 3
	default:
		return 4
	}
}

// RFC 6598 carrier-grade NAT: a host candidate here is normal on mobile networks, not a proxy tell.
var cgnatRange = netip.MustParsePrefix("100.64.0.0/10")

// publicIP unmaps IPv4-mapped IPv6 so families compare like for like; NAT'd candidates are never a tell.
func publicIP(s string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
		addr.IsPrivate() || addr.IsMulticast() || addr.IsUnspecified() || cgnatRange.Contains(addr) {
		return netip.Addr{}, false
	}
	return addr, true
}

// majorOf: "125.0.6422.60" ⇒ 125; 0 when there are no leading digits.
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

// uaChromeMajor: the "Chrome/" major, which Chrome, Edge and Opera all track; 0 = not Chromium.
func uaChromeMajor(ua string) int {
	const tok = "Chrome/"
	if i := strings.Index(ua, tok); i >= 0 {
		return majorOf(ua[i+len(tok):])
	}
	return 0
}

// chVersionMajor reads the "Chromium" brand, not uaFullVersion: forks (Opera 111, Vivaldi 7) brand their
// own version but expose the true engine major there. 0 = not reported.
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

func firstToken(ua string, tokens []string) string {
	l := strings.ToLower(ua)
	for _, t := range tokens {
		if strings.Contains(l, t) {
			return strings.TrimSpace(t)
		}
	}
	return ""
}

// offsetFormat: IP2Location gives a UTC offset like "+03:00" rather than an IANA name.
func offsetFormat(s string) bool {
	return len(s) > 0 && (s[0] == '+' || s[0] == '-')
}

// zoneOffsetSeconds is DST-aware; false if the zone won't load or at is zero.
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

// ianaOffset: formats a zone's current offset like IP2Location's "+03:00".
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

// chBrandNames takes the first quoted token per entry: `"Chromium";v="125", "Not.A/Brand";v="24"`.
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

// realBrandSet drops the GREASE decoy, which always contains "Brand" (e.g. "Not.A/Brand").
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

// Group returns one tier's checks in rule order.
func (r Report) Group(tier string) []Check {
	out := make([]Check, 0, len(r.Checks))
	for _, c := range r.Checks {
		if c.Tier == tier {
			out = append(out, c)
		}
	}
	return out
}

// Subgroup: only the consistency tier is split for display.
func (r Report) Subgroup(tier, subgroup string) []Check {
	out := make([]Check, 0, len(r.Checks))
	for _, c := range r.Checks {
		if c.Tier == tier && c.Subgroup == subgroup {
			out = append(out, c)
		}
	}
	return out
}

// SoftFired: soft hits show as "flagged", not as per-row deductions, so shown numbers match the score.
func (r Report) SoftFired() int {
	n := 0
	for _, c := range r.Checks {
		if c.Tier == TierSoft && c.Triggered {
			n++
		}
	}
	return n
}

// SoftClusterActive is the only case where soft signals move the score.
func (r Report) SoftClusterActive() bool { return r.SoftFired() >= softComboThreshold }

// SoftClusterPenalty: score cost of an active soft cluster.
func (r Report) SoftClusterPenalty() int { return softComboWeight }

// primaryLang: "en-US,ru;q=0.9" → "en"; "" if none.
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
