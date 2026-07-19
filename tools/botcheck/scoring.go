package botcheck

import (
	"fmt"
	"strings"
)

// rule is one detection signal. eval reports whether the anomaly fired and a
// short human detail for the table. needsClient marks rules that read a
// client-collected field, so Evaluate can skip (not fail) them on a server-only
// request. Weights are a starting proposal, tuned against botcheck/tests — not
// gospel; adjust there, with fixtures, rather than by feel.
type rule struct {
	id          string
	label       string
	tier        string
	subgroup    string
	weight      int
	needsClient bool
	eval        func(Signals) (bool, string)
}

// gpuOSImpossible is the exhaustive list of GPU-family/OS pairs gpu_os_mismatch
// may ever fire on — combinations no shipping hardware produces: an Apple GPU
// off macOS/iOS, a desktop discrete GPU (NVIDIA GeForce / AMD Radeon) on a phone
// OS, a mobile Adreno/Mali on an Apple desktop OS. Everything not listed here is
// deliberately silent, because real machines exist: AMD Radeon + macOS (Intel
// Macs), NVIDIA + macOS (pre-2014 Macs), Adreno + Windows (Snapdragon ARM
// laptops), Intel + Android (old Atom phones), anything + Chrome OS.
var gpuOSImpossible = map[string]map[string]bool{
	"apple":  {"Windows": true, "Linux": true, "Android": true},
	"nvidia": {"iOS": true, "Android": true},
	"amd":    {"iOS": true, "Android": true},
	"adreno": {"macOS": true, "iOS": true},
	"mali":   {"macOS": true, "iOS": true},
}

// rules is the full ordered signal set. Hard tells first (each near-standalone),
// then cross-layer/cross-context consistency checks (the load-bearing ones),
// then soft heuristics (only counted as a cluster — see Evaluate). The score is
// the sum of triggered weights subtracted from 100.
var rules = []rule{
	// ── Hard tells ────────────────────────────────────────────────────────────
	{
		id: "webdriver", label: "navigator.webdriver is true", tier: TierHard, weight: 60, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.Webdriver, "" },
	},
	{
		id: "framework_globals", label: "Automation framework globals present", tier: TierHard, weight: 60, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if len(s.FrameworkGlobals) == 0 {
				return false, ""
			}
			return true, strings.Join(s.FrameworkGlobals, ", ")
		},
	},
	{
		id: "bot_user_agent", label: "User-Agent is a known bot / HTTP client", tier: TierHard, weight: 60,
		eval: func(s Signals) (bool, string) {
			if tok := botUAToken(s.HTTPUserAgent); tok != "" {
				return true, "matched " + tok
			}
			// Recognise every good-bot/AI-agent token too: several (Meta-ExternalAgent,
			// Claude-User, ChatGPT-User, …) carry no generic bot/spider/crawler substring
			// and would otherwise escape this penalty. Check both the header and any
			// posted navigator UA. A *verified* good bot has this deduction suppressed in
			// Evaluate; an unverified one keeps it — recognition is not leniency.
			if b := matchGoodBot(s.HTTPUserAgent); b != nil {
				return true, "recognized " + b.name
			}
			if b := matchGoodBot(s.NavMainUA); b != nil {
				return true, "recognized " + b.name
			}
			return false, ""
		},
	},
	{
		id: "native_tamper", label: "A native function was monkey-patched (toString)", tier: TierHard, weight: 45, needsClient: true,
		eval: func(s Signals) (bool, string) { return !s.NativeToStringOK, "" },
	},
	{
		// Proxying Function.prototype.toString is the puppeteer-extra-stealth hallmark:
		// it exists precisely to defeat the shallow native_tamper check, and no
		// legitimate software does it — privacy extensions patch the DOM leak-surface
		// APIs (canvas/WebGL), never toString itself. That is why this one is hard
		// while the G04 descriptor/call-new probes below stay consistency-tier.
		id: "tostring_proxy", label: "Function.prototype.toString is proxied or replaced (stealth hallmark)", tier: TierHard, weight: 45, needsClient: true,
		eval: func(s Signals) (bool, string) {
			// Skip pre-v2 payloads: the key didn't exist, false would be a lie.
			if s.CollectorV < collectorVDeepTamper {
				return false, ""
			}
			return s.NativeToStringProxied, ""
		},
	},
	{
		id: "software_renderer", label: "WebGL uses a software renderer (headless tell)", tier: TierHard, weight: 40, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.WebGLRenderer != "" && isSoftwareRenderer(s.WebGLRenderer) {
				return true, s.WebGLRenderer
			}
			return false, ""
		},
	},
	{
		// G11: navigator.webdriver re-read inside the iframe's fresh JS context.
		// Stealth toolkits patch the top frame's navigator (even its prototype);
		// the iframe realm has its own Navigator.prototype and leaks the truth.
		id: "iframe_webdriver", label: "navigator.webdriver is true inside the iframe", tier: TierHard, weight: 60, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.IframeWebdriver, "" },
	},
	{
		// G14: navigator.webdriver read inside the Service Worker — a third
		// context a top-frame-only webdriver patch forgets (the incolumitas
		// inconsistentServiceWorkerNavigatorPropery catch).
		id: "webdriver_sw", label: "navigator.webdriver is true in the Service Worker", tier: TierHard, weight: 60, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.SWWebdriver, "" },
	},

	// ── Consistency (client claim vs. server / second context) ─────────────────
	{
		id: "ua_header_mismatch", label: "JS User-Agent ≠ HTTP User-Agent", tier: TierConsistency, subgroup: subgroupUA, weight: 35, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.NavMainUA == "" || s.HTTPUserAgent == "" || s.NavMainUA == s.HTTPUserAgent {
				return false, ""
			}
			return true, "navigator vs header differ"
		},
	},
	{
		id: "context_ua_mismatch", label: "Worker/iframe/Service-Worker User-Agent ≠ main-thread User-Agent", tier: TierConsistency, subgroup: subgroupContext, weight: 35, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.NavMainUA == "" {
				return false, ""
			}
			if s.NavWorkerUA != "" && s.NavWorkerUA != s.NavMainUA {
				return true, "worker differs"
			}
			if s.NavIframeUA != "" && s.NavIframeUA != s.NavMainUA {
				return true, "iframe differs"
			}
			if s.SWUA != "" && s.SWUA != s.NavMainUA {
				return true, "service worker differs"
			}
			return false, ""
		},
	},
	{
		// G03: navigator.languages re-read in each secondary context. Anti-detect
		// tools patch the top frame's navigator only, so a worker/iframe/SW still
		// shows the real list. Compare primary subtags only (en-US vs en is the
		// same language), and only when both sides answered — an empty context
		// list means the API is unsupported there, not a mismatch.
		id: "context_language_mismatch", label: "Worker/iframe/Service-Worker language ≠ main-thread language", tier: TierConsistency, subgroup: subgroupContext, weight: 20, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if len(s.Languages) == 0 {
				return false, ""
			}
			main := primaryLang(s.Languages[0])
			first := func(l []string) string {
				if len(l) == 0 {
					return ""
				}
				return primaryLang(l[0])
			}
			for _, c := range []struct{ name, lang string }{
				{"worker", first(s.WorkerLanguages)},
				{"iframe", first(s.IframeLanguages)},
				{"service worker", first(s.SWLanguages)},
			} {
				if c.lang != "" && c.lang != main {
					return true, fmt.Sprintf("%s primary language %s vs main %s", c.name, c.lang, main)
				}
			}
			return false, ""
		},
	},
	{
		// G03: hardwareConcurrency re-read in each secondary context. Assumption
		// (false-positive guard): anti-fingerprint throttling caps the value
		// GLOBALLY, not per-context — Firefox resistFingerprinting and Brave's
		// farbling report the same capped number in every context of the origin,
		// so a real privacy browser still agrees with itself. Only a spoof that
		// patched one context and forgot the others disagrees.
		id: "context_cores_mismatch", label: "Worker/iframe/Service-Worker hardwareConcurrency ≠ main thread", tier: TierConsistency, subgroup: subgroupContext, weight: 20, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.HardwareCores == 0 {
				return false, ""
			}
			for _, c := range []struct {
				name  string
				cores int
			}{
				{"worker", s.WorkerCores},
				{"iframe", s.IframeCores},
				{"service worker", s.SWCores},
			} {
				if c.cores > 0 && c.cores != s.HardwareCores {
					return true, fmt.Sprintf("%s reports %d cores vs main %d", c.name, c.cores, s.HardwareCores)
				}
			}
			return false, ""
		},
	},
	{
		// G03: userAgentData.platform re-read in each secondary context (empty on
		// Safari/Firefox, which simply skip). normPlatform on both sides so
		// "macOS" vs "Mac OS X" style spelling variants can't false-fire.
		id: "context_platform_mismatch", label: "Worker/iframe/Service-Worker platform ≠ main-thread platform", tier: TierConsistency, subgroup: subgroupContext, weight: 25, needsClient: true,
		eval: func(s Signals) (bool, string) {
			main := normPlatform(s.UAData.Platform)
			if main == "" {
				return false, ""
			}
			for _, c := range []struct{ name, platform string }{
				{"worker", s.WorkerPlatform},
				{"iframe", s.IframePlatform},
				{"service worker", s.SWPlatform},
			} {
				if p := normPlatform(c.platform); p != "" && p != main {
					return true, fmt.Sprintf("%s platform %s vs main %s", c.name, p, main)
				}
			}
			return false, ""
		},
	},
	{
		// G03: the worker's WebGL unmasked renderer (read via OffscreenCanvas) vs
		// the main thread's — the CreepJS hasBadWebGL diff. Same browser, same
		// GPU ⇒ same renderer string; a spoofed top-frame WebGL read disagrees.
		// Fires only when both reads succeeded (OffscreenCanvas WebGL is often
		// unsupported, which just leaves the worker side empty).
		id: "context_webgl_mismatch", label: "Worker WebGL renderer ≠ main-thread WebGL renderer", tier: TierConsistency, subgroup: subgroupContext, weight: 20, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.WebGLRenderer == "" || s.WorkerWebGLRenderer == "" || s.WebGLRenderer == s.WorkerWebGLRenderer {
				return false, ""
			}
			return true, "worker renderer differs from main thread"
		},
	},
	{
		id: "ch_platform_mismatch", label: "Sec-CH-UA-Platform ≠ navigator.userAgentData.platform", tier: TierConsistency, subgroup: subgroupUA, weight: 30, needsClient: true,
		eval: func(s Signals) (bool, string) {
			h, j := normPlatform(s.SecCHUAPlatform), normPlatform(s.UAData.Platform)
			if h == "" || j == "" || h == j {
				return false, ""
			}
			return true, fmt.Sprintf("header %s vs JS %s", h, j)
		},
	},
	{
		id: "ua_os_mismatch", label: "OS in User-Agent ≠ userAgentData.platform", tier: TierConsistency, subgroup: subgroupUA, weight: 30, needsClient: true,
		eval: func(s Signals) (bool, string) {
			ua := osFromUA(s.NavMainUA)
			if ua == "" {
				ua = osFromUA(s.HTTPUserAgent)
			}
			j := normPlatform(s.UAData.Platform)
			if ua == "" || j == "" || ua == j {
				return false, ""
			}
			return true, fmt.Sprintf("UA %s vs platform %s", ua, j)
		},
	},
	{
		// Feature-detect the real rendering engine (Blink/Gecko/WebKit) client-side
		// and compare to the engine the UA claims. Robust against a spoofed UA string:
		// the engine probes read capabilities the UA can't fake. Only fires on a
		// confident disagreement (both sides known and different).
		id: "engine_ua_mismatch", label: "Feature-detected engine ≠ engine the User-Agent claims", tier: TierConsistency, subgroup: subgroupUA, weight: 30, needsClient: true,
		eval: func(s Signals) (bool, string) {
			want := engineFromUA(clientUA(s))
			if want == "" || s.Engine == "" || s.Engine == want {
				return false, ""
			}
			return true, fmt.Sprintf("engine %s vs UA implies %s", s.Engine, want)
		},
	},
	{
		// A UA-string spoof that edits "Chrome/NNN" but leaves userAgentData intact
		// disagrees here: the UA's Chromium major must equal the "Chromium" brand entry
		// of fullVersionList (see chVersionMajor). The CreepJS/Electron frozen-UA catch.
		id: "ua_chrome_version_mismatch", label: "User-Agent Chrome version ≠ userAgentData version", tier: TierConsistency, subgroup: subgroupUA, weight: 25, needsClient: true,
		eval: func(s Signals) (bool, string) {
			uaM, chM := uaChromeMajor(clientUA(s)), chVersionMajor(s.UAData)
			if uaM == 0 || chM == 0 || uaM == chM {
				return false, ""
			}
			return true, fmt.Sprintf("UA Chrome %d vs userAgentData %d", uaM, chM)
		},
	},
	{
		id: "embedded_runtime", label: "User-Agent is an embedded app runtime (Electron/CEF)", tier: TierConsistency, subgroup: subgroupUA, weight: 25,
		eval: func(s Signals) (bool, string) {
			ua := s.HTTPUserAgent
			if ua == "" {
				ua = s.NavMainUA
			}
			if tok := embeddedRuntimeToken(ua); tok != "" {
				return true, "matched " + tok
			}
			return false, ""
		},
	},
	{
		id: "tz_mismatch", label: "Browser timezone ≠ IP timezone", tier: TierConsistency, subgroup: subgroupNetwork, weight: 25, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.BrowserTZ == "" || s.IPTimezone == "" {
				return false, ""
			}
			// IP2Location gives a UTC offset ("+03:00"); the browser gives an IANA
			// name ("Europe/Moscow"). Compare offset-to-offset — a plain string
			// compare would fire for every real visitor (formats never match).
			if offsetFormat(s.IPTimezone) {
				bo, ok := ianaOffset(s.BrowserTZ, s.Now)
				if !ok || bo == s.IPTimezone {
					return false, "" // unknown/unstampable zone ⇒ can't verify, don't fire
				}
				return true, fmt.Sprintf("browser %s (%s) vs IP %s", s.BrowserTZ, bo, s.IPTimezone)
			}
			// Both look like IANA names (other IP DB formats) — name compare.
			if strings.EqualFold(s.BrowserTZ, s.IPTimezone) {
				return false, ""
			}
			return true, fmt.Sprintf("browser %s vs IP %s", s.BrowserTZ, s.IPTimezone)
		},
	},
	{
		id: "datacenter_ip", label: "Egress IP is a datacenter / Tor address", tier: TierConsistency, subgroup: subgroupNetwork, weight: 30,
		eval: func(s Signals) (bool, string) {
			if s.IsDatacenter {
				return true, "datacenter / hosting"
			}
			if s.IsTor {
				return true, "Tor exit node"
			}
			return false, ""
		},
	},
	{
		// Mutually exclusive with datacenter_ip: IP2Proxy marks datacenters/Tor as
		// proxies too, so only fire here for a VPN or an otherwise-uncategorised
		// proxy — never double-count an address the datacenter rule already caught.
		id: "proxy_ip", label: "Egress IP is a proxy / VPN", tier: TierConsistency, subgroup: subgroupNetwork, weight: 20,
		eval: func(s Signals) (bool, string) {
			if s.IsVPN {
				return true, "VPN"
			}
			if s.IsProxy && !s.IsDatacenter && !s.IsTor {
				return true, "public/other proxy"
			}
			return false, ""
		},
	},
	{
		id: "permission_impossible", label: "Impossible permission state (prompt while denied)", tier: TierConsistency, subgroup: subgroupInternals, weight: 25, needsClient: true,
		eval: func(s Signals) (bool, string) {
			return s.PermissionState == "prompt" && s.NotificationPerm == "denied", ""
		},
	},
	{
		id: "lang_mismatch", label: "navigator.languages ≠ Accept-Language", tier: TierConsistency, subgroup: subgroupUA, weight: 15, needsClient: true,
		eval: func(s Signals) (bool, string) {
			var nav string
			if len(s.Languages) > 0 {
				nav = primaryLang(s.Languages[0])
			}
			hdr := primaryLang(s.AcceptLanguage)
			if nav == "" || hdr == "" || nav == hdr {
				return false, ""
			}
			return true, fmt.Sprintf("JS %s vs header %s", nav, hdr)
		},
	},
	{
		// Self-consistency (no IP needed): the browser's own IANA timezone must
		// agree with its own Date().getTimezoneOffset(). Spoofers commonly change
		// one and forget the other.
		id: "tz_self_inconsistent", label: "Timezone name disagrees with getTimezoneOffset()", tier: TierConsistency, subgroup: subgroupInternals, weight: 25, needsClient: true,
		eval: func(s Signals) (bool, string) {
			secs, ok := zoneOffsetSeconds(s.BrowserTZ, s.Now)
			if s.BrowserTZ == "" || !ok {
				return false, ""
			}
			expected := -secs / 60 // getTimezoneOffset is minutes west of UTC
			if expected == s.TZOffset {
				return false, ""
			}
			return true, fmt.Sprintf("%s implies %d min but reported %d", s.BrowserTZ, expected, s.TZOffset)
		},
	},
	{
		// Randomised canvas output (two identical draws hashing differently) is a
		// noise-injecting anti-fingerprint / stealth tool.
		id: "canvas_unstable", label: "Canvas output is randomised between draws", tier: TierConsistency, subgroup: subgroupInternals, weight: 15, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.CanvasSupported && !s.CanvasStable, "" },
	},
	{
		// Parse the Sec-CH-UA header brand list (server) and compare to the JS
		// userAgentData.brands (client); a spoofed User-Agent that forgets to keep
		// the two in sync is caught here. GREASE decoy brand is ignored.
		id: "ch_brands_mismatch", label: "Sec-CH-UA header brands ≠ userAgentData.brands", tier: TierConsistency, subgroup: subgroupUA, weight: 20, needsClient: true,
		eval: func(s Signals) (bool, string) {
			hdr, js := realBrandSet(chBrandNames(s.SecCHUA)), realBrandSet(s.Brands)
			if len(hdr) == 0 || len(js) == 0 || sameStringSet(hdr, js) {
				return false, "" // can't compare (stripped / non-Chromium) or they match
			}
			return true, "header and JS brand lists differ"
		},
	},
	{
		id: "vendor_mismatch", label: "Chromium User-Agent but navigator.vendor ≠ \"Google Inc.\"", tier: TierConsistency, subgroup: subgroupUA, weight: 20, needsClient: true,
		eval: func(s Signals) (bool, string) {
			ua := clientUA(s)
			if strings.Contains(ua, "Chrome") && s.Vendor != "" && s.Vendor != "Google Inc." {
				return true, "vendor=" + s.Vendor
			}
			return false, ""
		},
	},
	{
		id: "app_version_mismatch", label: "navigator.appVersion inconsistent with User-Agent", tier: TierConsistency, subgroup: subgroupUA, weight: 15, needsClient: true,
		eval: func(s Signals) (bool, string) {
			// Every mainstream browser reports appVersion as the UA minus "Mozilla/".
			if s.NavMainUA == "" || s.AppVersion == "" || !strings.HasPrefix(s.NavMainUA, "Mozilla/") {
				return false, ""
			}
			return s.AppVersion != strings.TrimPrefix(s.NavMainUA, "Mozilla/"), ""
		},
	},
	{
		// navigator.productSub is a fixed per-engine constant ("20030107" on every
		// WebKit/Blink browser, "20100101" on Gecko). A value that doesn't match the
		// engine the UA claims is a classic spoof/patched-runtime tell.
		id: "productsub_mismatch", label: "navigator.productSub not the engine's constant", tier: TierConsistency, subgroup: subgroupUA, weight: 20, needsClient: true,
		eval: func(s Signals) (bool, string) {
			want := expectedProductSub(clientUA(s))
			if want == "" || s.ProductSub == "" || s.ProductSub == want {
				return false, ""
			}
			return true, fmt.Sprintf("productSub %s, expected %s", s.ProductSub, want)
		},
	},
	{
		id: "language_primary_mismatch", label: "navigator.language ≠ navigator.languages[0]", tier: TierConsistency, subgroup: subgroupUA, weight: 15, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.NavLanguage == "" || len(s.Languages) == 0 || s.Languages[0] == "" {
				return false, ""
			}
			if strings.EqualFold(s.NavLanguage, s.Languages[0]) {
				return false, ""
			}
			return true, fmt.Sprintf("language %s vs languages[0] %s", s.NavLanguage, s.Languages[0])
		},
	},
	{
		// G07: the unmasked WebGL VENDOR and RENDERER both come from the same GPU
		// driver, so a real browser never reports them in different vendor families —
		// Chrome's ANGLE pair is internally consistent ("Google Inc. (NVIDIA)" /
		// "ANGLE (NVIDIA, ...)") and modern Safari generalises both to "Apple Inc." /
		// "Apple GPU". A cross-family pair (vendor says Apple, renderer says NVIDIA)
		// is a hand-edited spoof. Fires only when BOTH sides parse to a confident
		// family AND differ: an empty or unparseable string (VM, software rasteriser,
		// masked) is no signal, so e.g. an "ARM" vendor beside a "Mali" renderer
		// (normal on Android) stays silent.
		id: "webgl_vendor_mismatch", label: "WebGL vendor and renderer disagree", tier: TierConsistency, subgroup: subgroupInternals, weight: 20, needsClient: true,
		eval: func(s Signals) (bool, string) {
			vf, rf := gpuVendorFamily(s.WebGLVendor, ""), gpuVendorFamily("", s.WebGLRenderer)
			if vf == "" || rf == "" || vf == rf {
				return false, ""
			}
			return true, fmt.Sprintf("vendor %q (%s) vs renderer %q (%s)", s.WebGLVendor, vf, s.WebGLRenderer, rf)
		},
	},
	{
		// G08: the GPU family must be plausible for the OS the UA claims — the catch
		// is an anti-detect browser that rewrites its OS in the UA but can't change
		// the real GPU WebGL reports. Fires ONLY on the enumerated impossible pairs
		// (gpuOSImpossible): Apple GPU on Windows/Linux/Android, desktop NVIDIA/AMD
		// on iOS/Android, mobile Adreno/Mali on macOS/iOS. Deliberately silent on
		// every ambiguous combination — AMD Radeon + macOS (Intel Macs exist),
		// Adreno + Windows (Snapdragon ARM laptops), Intel anywhere, any GPU +
		// Chrome OS, Mesa/unknown GPU, unparseable UA. The GPU family is read from
		// vendor and renderer together, so Firefox ("NVIDIA Corporation") and
		// Safari ("Apple Inc." / "Apple GPU") are classified as confidently as ANGLE.
		id: "gpu_os_mismatch", label: "WebGL GPU impossible on the claimed OS", tier: TierConsistency, subgroup: subgroupInternals, weight: 25, needsClient: true,
		eval: func(s Signals) (bool, string) {
			fam, os := gpuVendorFamily(s.WebGLVendor, s.WebGLRenderer), osFromUA(clientUA(s))
			if fam == "" || os == "" || !gpuOSImpossible[fam][os] {
				return false, ""
			}
			return true, fmt.Sprintf("%s GPU on %s", fam, os)
		},
	},
	{
		// NOT hard (unlike tostring_proxy): page-context patching by legitimate
		// privacy extensions (canvas/WebGL noise injectors) is conceivable for these
		// DOM-facing APIs, and such a patch can leave an impossible descriptor — so
		// this is a consistency hit, not a standalone bot proof.
		id: "native_descriptor_tamper", label: "Native function has an impossible property descriptor", tier: TierConsistency, subgroup: subgroupInternals, weight: 25, needsClient: true,
		eval: func(s Signals) (bool, string) {
			// Skip pre-v2 payloads (stale collector): false would mean "field
			// didn't exist yet", not tampering — see collectorVDeepTamper.
			if s.CollectorV < collectorVDeepTamper {
				return false, ""
			}
			return !s.NativeDescriptorsOK, ""
		},
	},
	{
		// Same not-hard reasoning as native_descriptor_tamper: a privacy extension's
		// JS override of a DOM API typically misses the constructor/brand-check
		// TypeErrors a genuine native throws.
		id: "native_callnew_tamper", label: "Native function misses its call/new TypeError traps", tier: TierConsistency, subgroup: subgroupInternals, weight: 25, needsClient: true,
		eval: func(s Signals) (bool, string) {
			// Skip pre-v2 payloads, same as native_descriptor_tamper.
			if s.CollectorV < collectorVDeepTamper {
				return false, ""
			}
			return !s.NativeCallNewOK, ""
		},
	},
	{
		// G11: the iframe's contentWindow is a Proxy — the puppeteer-extra-stealth
		// iframe.contentWindow patch wrapping the fresh context to inject spoofs
		// (CreepJS hasIframeProxy). True only when the patched getter verifiably
		// throws; a genuine engine never does.
		id: "iframe_proxy", label: "iframe contentWindow is proxied (stealth iframe patch)", tier: TierConsistency, subgroup: subgroupInternals, weight: 30, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.IframeProxied, "" },
	},
	{
		// G12: a phone UA reporting zero touch points. Real Android/iOS devices
		// always report maxTouchPoints > 0; a desktop browser wearing a mobile UA
		// reports 0. v3-gated: the field is damning when zero on a stale payload
		// that never sent it. Deliberately no reverse direction (desktop UA +
		// touch): touch-screen Windows laptops would false-fire constantly.
		id: "mobile_no_touch", label: "Mobile User-Agent reports zero touch points", tier: TierConsistency, subgroup: subgroupInternals, weight: 20, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.CollectorV < collectorVTamperV3 {
				return false, ""
			}
			os := osFromUA(clientUA(s))
			if (os == "Android" || os == "iOS") && s.MaxTouchPoints == 0 {
				return true, fmt.Sprintf("%s UA with maxTouchPoints=0", os)
			}
			return false, ""
		},
	},
	{
		// G17: per WebIDL, webdriver/plugins/languages are accessor (getter-only)
		// properties — enumerable, configurable, living on Navigator.prototype,
		// never own data properties on the navigator instance. A spoof installed
		// via defineProperty/assignment breaks at least one of those. Consistency,
		// not hard (same reasoning as native_descriptor_tamper): a legit privacy
		// extension could patch these the same way. v3-gated: the OK bool is
		// damning when false on a stale payload that never sent it.
		id: "navigator_proto_tamper", label: "Navigator.prototype accessor descriptor anomaly (webdriver/plugins/languages)", tier: TierConsistency, subgroup: subgroupInternals, weight: 25, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.CollectorV < collectorVTamperV3 {
				return false, ""
			}
			return !s.NavProtoDescriptorsOK, ""
		},
	},
	{
		// G22: a genuine window.chrome on Chrome carries chrome.runtime with native
		// non-constructor connect/sendMessage (no own prototype, `new fn()` throws a
		// TypeError); a stealth-bolted fake gets the shape or the error constructor
		// wrong (CreepJS hasBadChromeRuntime). Chrome UA only; v3-gated like the
		// other fail-to-pass OK bools.
		id: "chrome_runtime_tamper", label: "window.chrome.runtime fails the integrity probe", tier: TierConsistency, subgroup: subgroupInternals, weight: 20, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.CollectorV < collectorVTamperV3 {
				return false, ""
			}
			return strings.Contains(clientUA(s), "Chrome") && !s.ChromeRuntimeOK, ""
		},
	},
	{
		// G22: genuine Chrome creates window.chrome during page setup, so it sits
		// early among window keys; a stealth patch bolting on a fake chrome object
		// appends it late — 'chrome' in the last ~50 window keys (CreepJS
		// hasHighChromeIndex). Chrome UA only.
		id: "chrome_late_injection", label: "window.chrome was injected late (stealth bolt-on)", tier: TierConsistency, subgroup: subgroupInternals, weight: 15, needsClient: true,
		eval: func(s Signals) (bool, string) {
			return strings.Contains(clientUA(s), "Chrome") && s.ChromeLateInjection, ""
		},
	},
	{
		// G23: the JS engine detected from the Error-stack format (V8 " at "
		// frames, SpiderMonkey fileName/lineNumber, JSC otherwise) vs the engine
		// the UA claims — a second engine check, independent of the CSS/capability
		// probes engine_ua_mismatch uses, and robust against a spoofed UA string.
		// Both sides confident or no fire.
		id: "jsengine_ua_mismatch", label: "Feature-detected JS engine ≠ engine the User-Agent claims", tier: TierConsistency, subgroup: subgroupUA, weight: 25, needsClient: true,
		eval: func(s Signals) (bool, string) {
			want := jsEngineFromUA(clientUA(s))
			if want == "" || s.JSEngine == "" || s.JSEngine == want {
				return false, ""
			}
			return true, fmt.Sprintf("JS engine %s vs UA implies %s", s.JSEngine, want)
		},
	},
	{
		// G09: a PUBLIC WebRTC candidate IP that isn't the connection's egress IP —
		// the classic VPN/proxy pierce: the browser leaks the real address over
		// STUN while HTTP traffic egresses through the proxy. Private/link-local/
		// loopback/ULA/CGNAT candidates are excluded (a host candidate ≠ egress is
		// normal NAT, never a tell), and only same-family candidates are compared
		// (dual-stack IPv6-vs-IPv4 would false-fire real browsers). An empty
		// candidate list or an unknown egress means "not supplied" ⇒ no signal.
		id: "webrtc_ip_mismatch", label: "Public WebRTC candidate IP ≠ egress IP", tier: TierConsistency, subgroup: subgroupNetwork, weight: 25, needsClient: true,
		eval: func(s Signals) (bool, string) {
			egress, ok := publicIP(s.EgressIP)
			if !ok || len(s.WebRTCIPs) == 0 {
				return false, ""
			}
			for _, cand := range s.WebRTCIPs {
				ip, ok := publicIP(cand)
				if !ok || ip.Is4() != egress.Is4() {
					continue // private/loopback/etc., or a different address family
				}
				if ip != egress {
					return true, fmt.Sprintf("WebRTC candidate %s ≠ egress %s", ip, egress)
				}
			}
			return false, ""
		},
	},

	{
		// G41/G42: this exact stable fingerprint (UA, screen, GPU, timezone, …)
		// was recorded from many distinct IPs in the rolling 30-day Mongo
		// corpus — the scraping-farm tell (a farm locks one fingerprint and
		// rotates its proxy pool; the incolumitas ScrapingBee catch).
		// FingerprintIPs is 0 ("no corpus data") whenever Mongo is off or the
		// count failed, which never fires; one person roaming networks reaches
		// a couple of IPs honestly, hence the five-IP floor. Verified crawler
		// fleets legitimately share one fingerprint across many IPs, so this
		// deduction is suppressed for them (suppressedForGoodBot).
		id: "fingerprint_reuse", label: "This exact fingerprint was seen from many IP addresses", tier: TierConsistency, subgroup: subgroupNetwork, weight: 25, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.FingerprintIPs < fingerprintReuseMinIPs {
				return false, ""
			}
			return true, fmt.Sprintf("exact fingerprint seen from %d IPs in the 30-day corpus", s.FingerprintIPs)
		},
	},

	// ── Soft heuristics (only bite as a cluster of ≥3) ─────────────────────────
	{
		id: "empty_plugins", label: "No browser plugins", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.Plugins == 0, "" },
	},
	{
		id: "empty_languages", label: "navigator.languages is empty", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return len(s.Languages) == 0, "" },
	},
	{
		id: "default_geometry", label: "Default 800×600 screen", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.ScreenW == 800 && s.ScreenH == 600, "" },
	},
	{
		id: "impossible_window", label: "Outer window smaller than inner (impossible)", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			return s.OuterW > 0 && s.InnerW > 0 && s.OuterW < s.InnerW, ""
		},
	},
	{
		id: "no_chrome_object", label: "window.chrome missing on a Chrome User-Agent", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			return strings.Contains(clientUA(s), "Chrome") && !s.HasChromeObject, ""
		},
	},
	{
		id: "implausible_hardware", label: "Implausible hardwareConcurrency / deviceMemory", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.HardwareCores < 0 || s.HardwareCores > 128 {
				return true, fmt.Sprintf("cores=%d", s.HardwareCores)
			}
			if s.DeviceMemory < 0 || s.DeviceMemory > 128 {
				return true, fmt.Sprintf("memory=%.0f", s.DeviceMemory)
			}
			return false, ""
		},
	},
	{
		id: "screen_avail_impossible", label: "Available screen area larger than the physical screen", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			return (s.AvailW > 0 && s.ScreenW > 0 && s.AvailW > s.ScreenW) ||
				(s.AvailH > 0 && s.ScreenH > 0 && s.AvailH > s.ScreenH), ""
		},
	},
	{
		id: "low_color_depth", label: "Unusually low screen colour depth", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.ColorDepth > 0 && s.ColorDepth < 16 {
				return true, fmt.Sprintf("colorDepth=%d", s.ColorDepth)
			}
			return false, ""
		},
	},
	{
		// Real browsers send Sec-Fetch-* on every navigation and fetch; a scripted
		// client wearing a browser User-Agent usually omits them. Soft, because a
		// proxy could in theory strip them.
		id: "sec_fetch_missing", label: "Browser User-Agent but no Sec-Fetch-* headers", tier: TierSoft, weight: 8,
		eval: func(s Signals) (bool, string) {
			if s.SecFetchMode == "" && looksLikeBrowser(s.HTTPUserAgent) {
				return true, "no Sec-Fetch-Mode"
			}
			return false, ""
		},
	},
	{
		// Real browsers send Accept-Encoding on every request (they all support at
		// least gzip); a browser User-Agent without one is a scripted client that
		// didn't bother. Soft, not consistency: a proxy (CF/nginx) on the path can
		// strip or rewrite these headers — the exact caveat that made
		// sec_fetch_missing soft.
		id: "accept_encoding_missing", label: "Browser User-Agent but no Accept-Encoding header", tier: TierSoft, weight: 8,
		eval: func(s Signals) (bool, string) {
			if looksLikeBrowser(s.HTTPUserAgent) && s.HTTPAcceptEncoding == "" {
				return true, "no Accept-Encoding"
			}
			return false, ""
		},
	},
	{
		// Same shape: every real browser sends Accept-Language. Complements the
		// lang_mismatch consistency rule, which needs BOTH sides (navigator.languages
		// and the header) to compare values — this one catches the header's total
		// absence. Soft for the same proxy-strips-headers caveat as
		// sec_fetch_missing.
		id: "accept_language_missing", label: "Browser User-Agent but no Accept-Language header", tier: TierSoft, weight: 8,
		eval: func(s Signals) (bool, string) {
			if looksLikeBrowser(s.HTTPUserAgent) && s.AcceptLanguage == "" {
				return true, "no Accept-Language"
			}
			return false, ""
		},
	},
	{
		// A real browser's navigation/fetch Accept always includes text/html; a
		// scripted client wearing a browser User-Agent sends */* (bare curl) or
		// application/json. POST /check arrives from fetch() and the vendored
		// collector explicitly sets "Accept: text/html", so the genuine browser
		// flow never trips this — but JSON API consumers (Accept: application/json)
		// do. That's acceptable precisely because the rule is soft: it only bites
		// inside a >=3 soft cluster, and a proxy can rewrite the header anyway (the
		// caveat that made sec_fetch_missing soft). An EMPTY Accept means "not
		// supplied" and never fires.
		id: "accept_nav_mismatch", label: "Browser User-Agent but Accept doesn't include text/html", tier: TierSoft, weight: 8,
		eval: func(s Signals) (bool, string) {
			if looksLikeBrowser(s.HTTPUserAgent) && s.HTTPAccept != "" &&
				!strings.Contains(strings.ToLower(s.HTTPAccept), "text/html") {
				return true, "Accept: " + s.HTTPAccept
			}
			return false, ""
		},
	},
	{
		// A canvas that renders nothing (all transparent) is blocked or headless.
		id: "canvas_blank", label: "Canvas renders blank (blocked / headless)", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.CanvasSupported && s.CanvasBlank, "" },
	},
	{
		// Stock desktop Chrome/Edge/Safari ship H.264 + AAC; a stripped/Chromium
		// headless build often supports neither.
		id: "missing_proprietary_codecs", label: "Browser lacks H.264 and AAC (stripped/headless build)", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			return looksLikeBrowser(clientUA(s)) && !s.CodecH264 && !s.CodecAAC, ""
		},
	},
	{
		// No detectable fonts at all points to a neutralised font-enumeration
		// surface or a font-less headless/VM environment.
		id: "no_fonts", label: "No system fonts detectable", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.FontCount == 0, "" },
	},
	{
		// G10: a 1×1 data-URI image that MUST load in any real browser reported
		// naturalWidth == 0 or errored — images stripped/blocked, a headless tell.
		// Soft: an image-blocking extension is a user choice, so it only bites in
		// a cluster. true = bad keeps stale (pre-v3) payloads safe.
		id: "image_broken", label: "A guaranteed-loadable image failed (images stripped)", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.ImageBroken, "" },
	},
	{
		// A faked navigator.plugins array that forgot its paired mimeTypes: plugins
		// present but zero mimeTypes. v3-gated: mimeTypes is damning when zero on
		// a stale payload that never sent it.
		id: "plugins_mimetypes_incoherent", label: "Plugins present but no mimeTypes (incoherent fake)", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.CollectorV < collectorVTamperV3 {
				return false, ""
			}
			return s.Plugins > 0 && s.MimeTypes == 0, ""
		},
	},
	{
		// A zero window.outerHeight while innerHeight is positive — a headless
		// window tell. The InnerH > 0 guard makes stale pre-v3 payloads (where
		// both bind 0) skip instead of firing.
		id: "zero_outer_height", label: "window.outerHeight is zero", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.OuterH == 0 && s.InnerH > 0, "" },
	},
	{
		// G15: window.matchMedia is a function in every real browser, desktop and
		// mobile, since the CSS2 era — a browser-claimed UA without it is a
		// stripped JS environment (jsdom-style) wearing a browser UA. Soft, not
		// hard: an exotic embedded webview could conceivably lack it. v4-gated:
		// a stale collector never sent the env section, so a missing value would
		// bind false and read as evidence on a pre-v4 payload.
		id: "matchmedia_missing", label: "Browser User-Agent but window.matchMedia is missing", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.CollectorV < collectorVTamperV4 {
				return false, ""
			}
			return looksLikeBrowser(clientUA(s)) && !s.Env.MatchMedia, ""
		},
	},
	{
		// G21: navigator.connection derives its effectiveType from the very
		// rtt/downlink estimates it reports (the worst of the two, per the spec's
		// threshold table), so the type can never be FASTER than its own numbers
		// imply — a '4g' claim beside rtt 2000 is a spoofed override. The
		// thresholds are graced by the API's own reporting rounding (see
		// ectFromRTT) so a real browser's rounded values never contradict its
		// claim, and only a strictly-faster claim fires: a slower claim is
		// conceivable from a mid-update estimate and never counts. Silent when
		// connection is absent (most Firefox/Safari) — that absence is normal,
		// never a signal. Soft: network estimates update asynchronously, so a
		// live change mid-read could briefly disagree — it only bites in a
		// cluster.
		id: "netinfo_incoherent", label: "navigator.connection effectiveType contradicts its own rtt/downlink", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.CollectorV < collectorVTamperV4 {
				return false, ""
			}
			c := s.Env.Connection
			claimed := ectRank(c.EffectiveType)
			if claimed == 0 {
				return false, "" // API absent or a future/unknown type ⇒ can't compare
			}
			worst, seen := 4, false
			if c.RTT > 0 {
				worst, seen = min(worst, ectFromRTT(c.RTT)), true
			}
			if c.Downlink > 0 {
				worst, seen = min(worst, ectFromDownlink(c.Downlink)), true
			}
			if !seen || claimed <= worst {
				return false, "" // no metrics to check, or the claim isn't faster than implied
			}
			return true, fmt.Sprintf("effectiveType %q but rtt %dms / downlink %.2fMbps imply at most %s",
				c.EffectiveType, c.RTT, c.Downlink, ectName(worst))
		},
	},
	{
		// Downgraded from hard/weight-40 (2026-07-19): an audit tested this trap
		// (an Error.stack getter read during a console.debug call — see
		// cdpTrap() in shared/static/js/botcheck.js) against five genuinely
		// CDP-driven sessions — Puppeteer (headless + headful), Playwright,
		// Selenium/chromedriver, a hand-rolled CDP client with Runtime.enable
		// active and no --enable-automation, and puppeteer-extra-stealth — and it
		// fired zero times across all of them. The premise (a CDP client's
		// object-preview generation invokes property getters) doesn't hold on
		// current Chromium regardless of transport; it isn't one browser evading
		// it. Left running (harmless when silent, and free in case a future
		// Chromium regression or an older engine revives it) rather than deleted
		// — see tools/botcheck/docs/TESTING.md for the full writeup.
		id: "cdp_both", label: "CDP automation detected in main thread and Worker", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.CDPMainThread && s.CDPWorker, "" },
	},
	{
		// Same downgrade and same reasoning as cdp_both above.
		id: "cdp_main_only", label: "CDP automation detected in main thread only", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.CDPMainThread && !s.CDPWorker, "" },
	},
	{
		// Same downgrade and same reasoning as cdp_both above. Still guarded
		// against the main/worker flags so one observation never double-counts
		// with cdp_both / cdp_main_only in the soft-signal cluster count.
		id: "cdp_sw_only", label: "CDP automation detected in the Service Worker only", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.SWCDP && !s.CDPMainThread && !s.CDPWorker, "" },
	},
}
