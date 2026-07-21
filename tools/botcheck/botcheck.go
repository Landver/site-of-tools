// Package botcheck: scores human vs bot look of a visitor's browser, w/
// transparent per-signal breakdown, for botcheck.corpberry.com.
//
// botcheck.go = domain layer: pure Go, no HTTP, no iptools import. Handler
// gathers client signals (JS collector POSTs fingerprint) + server signals
// (headers + iptools IP lookup) → flattens into Signals → Evaluate. No
// echo/iptools here → tests build Signals directly, no DB/HTTP.
//
// Core idea (docs/RESEARCH.md, docs/roadmap/): every client signal spoofable
// → strongest checks = cross-layer/cross-context consistency — browser
// *claims* (JS) vs connection *shows* (headers, IP) vs 2nd JS context
// (Worker/iframe).
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

	// Embeds IANA tz DB → time.LoadLocation works on distroless image —
	// needed for browser-TZ vs IP-TZ offset compare below.
	_ "time/tzdata"
)

// UAData: navigator.userAgentData subset collector reports. Lets Go
// cross-check JS platform+version vs Sec-CH-UA-Platform header + legacy UA.
// FullVersionList = G01 catch: UA spoof editing "Chrome/NNN" but leaving
// userAgentData intact disagrees w/ "Chromium" brand entry (see
// ua_chrome_version_mismatch / chVersionMajor).
type UAData struct {
	Platform        string         `json:"platform"`
	FullVersionList []BrandVersion `json:"fullVersionList"`
}

// BrandVersion: one fullVersionList entry (e.g. {"Chromium",
// "125.0.6422.60"}). GREASE decoy brand ignored on read (see chVersionMajor
// / realBrandSet).
type BrandVersion struct {
	Brand   string `json:"brand"`
	Version string `json:"version"`
}

// ConnectionInfo: v4 navigator.connection sample (G21) — browser's own
// net-quality estimate. API absent on most Firefox/Safari → zero struct;
// EffectiveType "" = not supplied, never a signal. netinfo_incoherent
// cross-checks effectiveType vs rtt/downlink, SAME object (browser derives
// type from those estimates → spoofed override self-contradicts).
type ConnectionInfo struct {
	EffectiveType string  `json:"effectiveType"` // "slow-2g" | "2g" | "3g" | "4g"
	Downlink      float64 `json:"downlink"`      // Mbps estimate (0 = not supplied)
	RTT           int     `json:"rtt"`           // ms estimate (0 = not supplied)
	SaveData      bool    `json:"saveData"`      // user asked for reduced data usage
}

// PermissionSample: v4 two-name Permissions API sample (G21). States:
// granted/denied/prompt; "" = query failed or name unsupported (old Safari
// rejects 'geolocation') — never evidence. Entropy only, no rule scores
// VALUES (user prefs).
type PermissionSample struct {
	Notifications string `json:"notifications"`
	Geolocation   string `json:"geolocation"`
}

// EnvInfo: v4 collector's additive "env" section (G15/G21) — CSS
// media-query/display-capability + net/storage API surface. Every field
// fails-to-absent, zero = not supplied, never evidence. matchmedia_missing +
// netinfo_incoherent are v4-gated (collectorVTamperV4) → stale v3 collector
// skips them; rest = entropy in raw dump, never scored — user prefs (colour
// scheme, forced colours, GPC) + hw caps (gamut, EME) ≠ bot tells.
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

// Signals: everything scorer needs. Client-collected (bound from POSTed
// fingerprint JSON via json tags) + server-observed (headers + IP lookup,
// handler-filled, json:"-"), flattened → package imports only stdlib. Zero =
// not supplied; ClientCollected splits "browser reported false/empty" from
// "no fingerprint posted" (plain curl) → client checks skip, not pass.
type Signals struct {
	ClientCollected bool `json:"-"`

	// CollectorV = payload version collector stamps ("v" key). Rules
	// damning-when-false (G04 deep-tamper: missing key → false) must skip
	// payloads too old to carry them, else stale cached botcheck.js reads as
	// tampered. 0 = unversioned/pre-G04. See collectorVDeepTamper.
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
	WebGLVendor      string   `json:"webglVendor"` // UNMASKED_VENDOR_WEBGL (e.g. "Google Inc. (Apple)"); cross-checked vs renderer (G07) + UA-claimed OS (G08)
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
	// Navigator values re-read in Web Worker, display:none iframe, Service
	// Worker — 3 extra JS contexts. Anti-detect tools mostly spoof only top
	// frame's navigator → context reporting something different = strong
	// consistency tell (Bright Data catch: worker says Linux, top UA says
	// macOS). Rules need BOTH sides present: ""/0/nil = context silent
	// (unsupported API, probe timeout), never evidence → skip, don't fire.
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
	// Same contract as NativeToStringOK: OK field false ONLY on confirmed
	// tamper — probe that can't run → pass value. On posted fingerprint,
	// false = damning, never "absent data".
	NativeDescriptorsOK bool `json:"nativeDescriptorsOK"` // descriptor/own-property sanity on natives
	NativeCallNewOK     bool `json:"nativeCallNewOK"`     // call/new TypeError traps behave
	// NativeToStringProxied INVERTED: true = bad. Function.prototype.toString
	// carries Proxy artifacts — stealth-plugin hallmark meant to defeat
	// shallow NativeToStringOK check.
	NativeToStringProxied bool `json:"nativeToStringProxied"`

	// ── v3 batch signals (G09–G14, G17, G22, G23 + Layer-1 backlog) ───────────
	// Added w/ payload v3. Two OK bools fail-to-pass like G04 (false only on
	// confirmed anomaly) → v3-gated (collectorVTamperV3); TRUE=BAD booleans +
	// value fields bind safe on stale payload, no gate needed.
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
	// Added w/ payload v4 as one additive "env" section. Same contract as v3:
	// fails-to-absent, zero = not supplied, never evidence; v4-gated
	// (collectorVTamperV4) → stale v3 collector skips.
	Env EnvInfo `json:"env"`

	// ── server-observed (filled by the handler; never read off the wire) ─────
	HTTPUserAgent   string `json:"-"`
	SecCHUAPlatform string `json:"-"`
	SecCHUA         string `json:"-"` // full Sec-CH-UA header (brand list)
	SecFetchMode    string `json:"-"` // Sec-Fetch-Mode header (real browsers always send it)
	AcceptLanguage  string `json:"-"`
	// G06 header-consistency signals, all server-observed.
	HTTPAccept         string `json:"-"` // Accept header; browser nav/fetch Accept includes text/html
	HTTPAcceptEncoding string `json:"-"` // Accept-Encoding header; every real browser sends one, every request
	// Upgrade-Insecure-Requests captured for completeness, deliberately
	// UNUSED: Safari never sends it → keying a rule on it false-positives
	// every real Safari user.
	HTTPUpgradeInsecureRequests string `json:"-"`
	IPTimezone                  string `json:"-"`
	EgressIP                    string `json:"-"` // connection IP server observed (c.RealIP()), for WebRTC cross-check (G09)
	ASN                         string `json:"-"` // egress ASN number (IP2Location), for good-bot corroboration
	IsDatacenter                bool   `json:"-"`
	IsProxy                     bool   `json:"-"`
	IsVPN                       bool   `json:"-"`
	IsTor                       bool   `json:"-"`
	// FingerprintIPs: distinct IPs presenting this exact fingerprint, rolling
	// 30-day corpus (G41/G42). Handler-filled from Mongo on POST /check only;
	// 0 = no corpus data (store off, count failed, first sighting) →
	// fingerprint_reuse treats as no signal, never evidence.
	FingerprintIPs int `json:"-"`
	// FingerprintChurn: DISTINCT fingerprints this egress IP presented,
	// rolling churn window (G43) — rotation tell, temporal inverse of
	// FingerprintIPs. Handler-filled from Mongo on POST /check only; 0 = no
	// corpus data → ip_fingerprint_churn treats as no signal, never evidence.
	FingerprintChurn int `json:"-"`

	// Now = request time, handler-stamped. Input not a clock call → Evaluate
	// stays pure/testable; resolves browser tz's current UTC offset
	// (DST-aware).
	Now time.Time `json:"-"`
}

// Tier: how damning a check is; drives soft-signal combo rule (see
// Evaluate) + HTML table colour.
const (
	TierHard        = "hard"        // near-standalone bot proof
	TierConsistency = "consistency" // combination that shouldn't co-occur
	TierSoft        = "soft"        // weak alone; only counts in cluster
)

// Subgroup: splits consistency tier into presentation groups. No scoring
// effect, display only.
const (
	subgroupNetwork   = "network"
	subgroupUA        = "ua"
	subgroupContext   = "context"
	subgroupInternals = "internals"
)

// Check: one row in breakdown table. Triggered = anomaly fired (bad);
// Skipped = couldn't evaluate (e.g. client-only signal, server-only
// request) — neither pass nor hit.
type Check struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Tier      string `json:"tier"`
	Subgroup  string `json:"-"`
	Weight    int    `json:"weight"`
	Triggered bool   `json:"triggered"`
	Skipped   bool   `json:"skipped,omitempty"`
	// Suppressed: rule fired but didn't dock score — expected of verified
	// good bot (bot-shaped, datacenter). Row still shows, as "expected" not a
	// deduction.
	Suppressed bool   `json:"suppressed,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

// Report: content-negotiated result, HTML/JSON. Score = authenticity: 100
// fully human, 0 fully automated. Bot set when UA = recognised crawler/AI
// agent (verified or not); verified → Verdict overrides to "good-bot".
// ClientPayload echoes POSTed fingerprint (POST /check only, nil on
// server-only GET) → report shows raw values behind verdict, G54 raw-dump
// for debugging. Server-observed fields never leak: json:"-" on Signals,
// HTML renders via RawJSON.
type Report struct {
	Score         int          `json:"score"`
	Verdict       string       `json:"verdict"` // "human" | "suspicious" | "bot" | "good-bot"
	Bot           *BotIdentity `json:"bot,omitempty"`
	Checks        []Check      `json:"checks"`
	ClientPayload *Signals     `json:"clientPayload,omitempty"`
	// FingerprintIPs: corpus count behind fingerprint_reuse (G41/G42) —
	// distinct IPs, this fingerprint, rolling 30-day window. 0 = corpus off
	// or first sighting → HTML hides line, omitempty keeps out of JSON.
	FingerprintIPs int `json:"fingerprintIPs,omitempty"`
	// FingerprintChurn: corpus count behind ip_fingerprint_churn (G43) —
	// distinct fingerprints, this IP, rolling churn window. 0 = corpus off or
	// no rotation → omitempty/HTML hide it.
	FingerprintChurn int `json:"fingerprintChurn,omitempty"`
}

// RawJSON: client-collected fingerprint half as indented JSON, raw-dump
// section (G54). Every server-observed field json:"-" → plain Marshal =
// exactly what browser POSTed, headers/IP can't leak. Can't fail here (plain
// scalars); failure would degrade to empty dump, never error page.
func (s Signals) RawJSON() string {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}

// FingerprintHash: G41/G42 stable identity of fingerprint's client half —
// sha256 over canonical stable-field subset: UA, languages,
// userAgentData.platform, cores, memory, screen+colour depth, timezone,
// WebGL vendor+renderer, productSub, engine, font count. Subset = what a
// scraping farm locks cloning one profile: volatile surfaces (window
// geometry, canvas/audio probes) + server-observed fields excluded → one
// browser = one hash across visits, two different browsers ≠ collide.
// Pure/deterministic — same Signals in, same hash out — corpus counts
// distinct IPs/hash. Fields joined w/ unit separator none can contain → no
// collision by concat.
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

// Scoring constants. Soft rule (from deviceandbrowserinfo): no single weak
// signal ever false-positives → soft hit ignored until softComboThreshold
// fire together, then cluster promotes to one softComboWeight deduction.
const (
	humanFloor         = 80 // score ≥ this ⇒ "human"
	suspiciousFloor    = 50 // score ≥ this ⇒ "suspicious"; below ⇒ "bot"
	softComboThreshold = 3
	softComboWeight    = 25
	// collectorVDeepTamper: payload version adding G04 deep-tamper fields
	// (nativeDescriptorsOK/nativeCallNewOK/nativeToStringProxied). Damning
	// when false, missing key → false → G04 rules skip older payloads, else
	// stale-collector returning visitor reads as tampered.
	collectorVDeepTamper = 2
	// collectorVTamperV3: payload version adding v3 fields damning when
	// false/zero (navProtoDescriptorsOK, chromeRuntimeOK, maxTouchPoints,
	// mimeTypes). Keyed rules skip older payloads, same contract as above.
	collectorVTamperV3 = 3
	// collectorVTamperV4: payload version adding v4 "env" section (G15/G21).
	// Keyed rules (matchmedia_missing, netinfo_incoherent) skip older
	// payloads — stale v3 collector never sent section → zeros mustn't read
	// as evidence.
	collectorVTamperV4 = 4
	// fingerprintReuseMinIPs: distinct-IP floor, fingerprint_reuse (G41/G42).
	// Below → person roaming networks (home+work+mobile), silent. At/above →
	// infra reusing one locked fingerprint across a proxy pool.
	fingerprintReuseMinIPs = 5
	// fingerprintChurnMinHashes: distinct-fingerprint floor,
	// ip_fingerprint_churn (G43). Below → IP w/ a handful of browsers
	// (household devices, browser-tweak re-check), silent. At/above → one
	// address cycling enough fingerprints in churn window to look like
	// randomising automation or busy shared egress. Soft-tier → only bites
	// as cluster even above floor.
	fingerprintChurnMinHashes = 8
	// churnWindow: rolling look-back handler passes to corpus, counting
	// distinct fingerprints/IP for ip_fingerprint_churn. Short enough normal
	// address's few devices never hit floor, long enough to catch a rotation
	// burst.
	churnWindow = 10 * time.Minute
)

// Evaluate: runs every rule against signals → scored report. Pure fn — no
// DB, no globals, no clock — trivially testable, race-free. Score starts
// 100; each triggered hard/consistency rule subtracts weight; soft rules
// summed separately, bite only as cluster.
func Evaluate(s Signals) Report {
	// ID recognised crawler/AI agent up front (nil otherwise). *Verified*
	// one (ASN-corroborated) expected bot-shaped → its deductions suppress
	// below + verdict overrides — unverified UA claim labelled, not excused.
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
			ID: r.id, Label: r.label, Tier: r.tier, Subgroup: r.subgroup, Weight: r.weight,
			Triggered: triggered, Skipped: skipped, Detail: detail,
		}
		// Hard/consistency rules dock weight immediately; soft rules never
		// bite alone — cost one softComboWeight only as cluster, applied once
		// below. Verified good bot: expected-crawler deductions recorded, not
		// counted (else wrongly tanks a legit crawler's score).
		if triggered && r.tier != TierSoft {
			if suppress && suppressedForGoodBot[r.id] {
				c.Suppressed = true
			} else {
				deduction += r.weight
			}
		}
		checks = append(checks, c)
	}

	// SoftClusterActive (SoftFired ≥ softComboThreshold) = single source of
	// truth for soft-cluster rule, shared w/ display helpers. FingerprintIPs
	// carries corpus count straight to report — input like any Signals field
	// → Evaluate stays pure.
	report := Report{Checks: checks, Bot: bot, FingerprintIPs: s.FingerprintIPs, FingerprintChurn: s.FingerprintChurn}
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

// suppressedForGoodBot: deductions a verified crawler is expected to trip —
// being a bot, datacenter/hosting network, sharing one fingerprint across
// fleet IPs. Recorded, not counted, for corroborated good bot → score reads
// coherent. Every other rule (webdriver, CDP, native tamper, …) still counts
// → compromised host inside operator's own network still surfaces.
var suppressedForGoodBot = map[string]bool{
	"bot_user_agent":    true,
	"datacenter_ip":     true,
	"proxy_ip":          true,
	"fingerprint_reuse": true,
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

// osFromUA: normalises UA's OS name → navigator.userAgentData.platform
// vocabulary ("Windows","macOS","Linux","Android","iOS","Chrome OS"). "" =
// can't tell → callers = no mismatch, not a trigger. Order matters:
// Android/CrOS UAs also contain "Linux", iOS contains "like Mac OS X".
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

// normPlatform: folds userAgentData/Sec-CH-UA-Platform values → same
// vocabulary as osFromUA (Chromium reports "macOS" but quotes CH header;
// edge cases vary) → the two comparable.
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

// isSoftwareRenderer: WebGL renderer string = software rasteriser? Strong
// "headless/no GPU" tell on desktop browser.
func isSoftwareRenderer(r string) bool {
	r = strings.ToLower(r)
	for _, m := range []string{"swiftshader", "llvmpipe", "mesa offscreen", "software", "microsoft basic render"} {
		if strings.Contains(r, m) {
			return true
		}
	}
	return false
}

// gpuVendorFamily: normalises WebGL unmasked vendor/renderer → GPU vendor
// family: apple/nvidia/amd/intel/adreno/mali. Copes w/ every real style —
// Chrome's ANGLE pair ("Google Inc. (NVIDIA)" + "ANGLE (NVIDIA, NVIDIA
// GeForce RTX 3080 Direct3D11 ...)"), Safari's "Apple Inc."/"Apple GPU",
// Firefox's plain "NVIDIA Corporation"/"GeForce ..." — ANGLE wrapper +
// "Google Inc. (...)" shim always carry true vendor inside → substring
// search over lowercased concat suffices. "" = can't tell (VM passthrough,
// software rasterisers, masked values) → callers = no signal, never
// mismatch — keeps llvmpipe-on-Linux + VMware guests from tripping GPU
// rules.
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

// botUATokens: headless browsers, scripting HTTP clients, self-declared
// bots — definitive non-browser tells (unlike Electron, handled separately).
var botUATokens = []string{
	"headlesschrome", "headless", "phantomjs", "slimerjs",
	"python-requests", "go-http-client", "curl/", "wget", "scrapy",
	"okhttp", "java/", "libwww", "node-fetch", "axios", "httpclient",
	"bot", "spider", "crawler",
}

// embeddedRuntimeTokens: browser engines embedded in desktop apps — real
// Chromium/WebKit, legit for an app but unusual for arbitrary sites →
// suspicious, not definitive.
var embeddedRuntimeTokens = []string{"electron", "cef ", "cefsharp", "qtwebengine", "nw.js", "nwjs"}

// botUAToken: first botUATokens match in UA (or "" for none). Empty UA
// counts as a token: real browsers always send one.
func botUAToken(ua string) string {
	if strings.TrimSpace(ua) == "" {
		return "(empty user-agent)"
	}
	return firstToken(ua, botUATokens)
}

func embeddedRuntimeToken(ua string) string { return firstToken(ua, embeddedRuntimeTokens) }

// looksLikeBrowser: UA claims mainstream interactive browser? Precondition
// for "real browser would've sent header X" checks. Excludes UAs already
// caught as bots/HTTP clients.
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

// clientUA: browser's own reported UA (navigator.userAgent), falls back to
// HTTP header if client half uncollected.
func clientUA(s Signals) string {
	if s.NavMainUA != "" {
		return s.NavMainUA
	}
	return s.HTTPUserAgent
}

// engineFromUA: maps UA → rendering engine a genuine browser w/ that UA must
// run: "blink" (Chrome/Edge/Opera/Chromium), "gecko" (Firefox), "webkit"
// (Safari + every iOS browser — Apple mandates WebKit). "" = can't tell →
// mismatch rule = no signal. iOS checked first: CriOS/FxiOS UAs carry a
// brand token but still run WebKit. Single source of truth for UA→engine
// (see expectedProductSub).
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

// expectedProductSub: navigator.productSub constant every mainstream
// browser on this engine reports — Gecko always "20100101", WebKit/Blink
// always "20030107". Derives engine via engineFromUA (single source of
// truth) → iOS browsers (WebKit under any FxiOS/CriOS token) classify right.
// "" ⇒ can't tell, don't fire.
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

// jsEngineFromUA: maps UA → JS engine a genuine browser must run: Blink=V8,
// Gecko=SpiderMonkey, WebKit (Safari + every iOS browser)=JavaScriptCore
// ("jsc"). Derives rendering engine via engineFromUA (single source of
// truth) → iOS under any FxiOS/CriOS token maps to JSC right. "" ⇒ can't
// tell, don't fire.
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

// ectRank: orders Network Information effectiveType slowest→fastest
// (slow-2g<2g<3g<4g). 0 = unknown/unsupplied → callers treat as can't tell,
// never mismatch.
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

// ectName: rank → effectiveType string, for rule detail lines.
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

// ectFromRTT: maps connection.rtt (ms) → effectiveType per Network
// Information spec threshold table. Each threshold graced by API's own
// rounding (rtt rounds to 50ms before page sees it, browser computes
// effectiveType from raw estimate) → real browser's rounded report landing
// one step across a boundary never self-contradicts.
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

// ectFromDownlink: maps connection.downlink (Mbps) → implied effectiveType,
// same rounding grace as ectFromRTT (downlink rounds to 0.05 Mbps).
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

// cgnatRange: carrier-grade NAT shared space (RFC 6598). Host candidate in
// it differing from egress IP = normal carrier NAT on mobile networks, not a
// proxy tell — same exclusion class as RFC1918.
var cgnatRange = netip.MustParsePrefix("100.64.0.0/10")

// publicIP: parses s as IP, normalises, reports public (globally routable)?
// webrtc_ip_mismatch compares only public candidates: NAT'd host candidate
// (RFC1918/ULA/loopback/link-local/CGNAT) differing from egress IP = normal,
// never a tell. IPv4-mapped IPv6 unmapped → family compare apples-to-apples.
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

// majorOf: leading integer of a dotted version ("125.0.6422.60" ⇒ 125). 0 ⇒
// no leading digits.
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

// uaChromeMajor: parses Chromium major from UA's "Chrome/125.0.0.0" token —
// version Chrome/Edge/Opera all track. 0 ⇒ not Chromium.
func uaChromeMajor(ua string) int {
	const tok = "Chrome/"
	if i := strings.Index(ua, tok); i >= 0 {
		return majorOf(ua[i+len(tok):])
	}
	return 0
}

// chVersionMajor: Chromium engine major userAgentData reports — "Chromium"
// brand entry of fullVersionList (falls back to "Google Chrome"). Exactly
// what UA's "Chrome/NNN" token carries → comparable for every Chromium
// browser: forks w/ diverging branded version (Opera 111, Vivaldi 7, Samsung
// 24 — all Chromium ~125) still expose true Chromium major here, no
// false-positive. uaFullVersion deliberately NOT read — carries fork's
// branded version, not engine's. 0 ⇒ not reported.
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

// firstToken: first token appearing (case-insensitive) in ua.
func firstToken(ua string, tokens []string) string {
	l := strings.ToLower(ua)
	for _, t := range tokens {
		if strings.Contains(l, t) {
			return strings.TrimSpace(t)
		}
	}
	return ""
}

// offsetFormat: s a UTC offset like "+03:00"/"-08:00"? Shape IP2Location
// returns for a tz (vs IANA name).
func offsetFormat(s string) bool {
	return len(s) > 0 && (s[0] == '+' || s[0] == '-')
}

// zoneOffsetSeconds: resolves IANA tz name (e.g. "Europe/Moscow") → UTC
// offset in seconds east, at time `at` (DST-aware). False if zone won't load
// or `at` = zero time.
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

// chBrandNames: extracts brand names from Sec-CH-UA header like
// `"Chromium";v="125", "Google Chrome";v="125", "Not.A/Brand";v="24"` —
// first quoted token per comma-separated entry.
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

// realBrandSet: lowercases brand names, drops GREASE entry (decoy always
// contains "Brand", e.g. "Not.A/Brand") → genuine brands only.
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

// Group: checks in one tier, rule order — template renders breakdown in
// labelled groups.
func (r Report) Group(tier string) []Check {
	out := make([]Check, 0, len(r.Checks))
	for _, c := range r.Checks {
		if c.Tier == tier {
			out = append(out, c)
		}
	}
	return out
}

// Subgroup: checks in one tier+subgroup. Empty subgroup = nothing; only
// consistency tier uses this, split for display.
func (r Report) Subgroup(tier, subgroup string) []Check {
	out := make([]Check, 0, len(r.Checks))
	for _, c := range r.Checks {
		if c.Tier == tier && c.Subgroup == subgroup {
			out = append(out, c)
		}
	}
	return out
}

// SoftFired: count of triggered soft-tier signals. Soft signals never dock
// points alone — cost score once, only when softComboThreshold fire
// together (see Evaluate) → template shows each as "flagged" not a per-row
// deduction, adds one line for real penalty when cluster active. Keeps
// displayed numbers matching what actually moved the score.
func (r Report) SoftFired() int {
	n := 0
	for _, c := range r.Checks {
		if c.Tier == TierSoft && c.Triggered {
			n++
		}
	}
	return n
}

// SoftClusterActive: enough soft signals fired for cluster penalty? Only
// case soft signals move the score.
func (r Report) SoftClusterActive() bool { return r.SoftFired() >= softComboThreshold }

// SoftClusterPenalty: score cost of an active soft cluster.
func (r Report) SoftClusterPenalty() int { return softComboWeight }

// primaryLang: base language subtag from a languages list or Accept-Language
// header (e.g. "en-US,ru;q=0.9" → "en"). "" if none.
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
