package botcheck

import (
	"fmt"
	"strings"
)

// Weights are a starting proposal: tune them against botcheck/tests fixtures, not by feel. Evidence per
// rule: docs/testing/checks/<id>.md. needs* make Evaluate skip (not fail) a rule when that half of the
// signals is missing; clientUA's header fallback doesn't count as needing headers.
type rule struct {
	id           string
	label        string
	tier         string
	subgroup     string
	weight       int
	needsClient  bool
	needsHeaders bool
	needsIP      bool
	needsCorpus  bool
	eval         func(Signals) (bool, string)
}

// gpuOSImpossible lists only pairs no shipping hardware produces; plausible oddities stay silent:
// Radeon/NVIDIA Macs, Snapdragon Windows laptops, Intel Android phones, anything on Chrome OS.
var gpuOSImpossible = map[string]map[string]bool{
	"apple":  {"Windows": true, "Linux": true, "Android": true},
	"nvidia": {"iOS": true, "Android": true},
	"amd":    {"iOS": true, "Android": true},
	"adreno": {"macOS": true, "iOS": true},
	"mali":   {"macOS": true, "iOS": true},
}

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
		id: "bot_user_agent", label: "User-Agent is a known bot / HTTP client", tier: TierHard, weight: 60, needsHeaders: true,
		eval: func(s Signals) (bool, string) {
			if tok := botUAToken(s.HTTPUserAgent); tok != "" {
				return true, "matched " + tok
			}
			// Good-bot UAs like ChatGPT-User lack a bot/spider token, so match them too.
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
		// Hard, unlike the descriptor probes: privacy extensions patch DOM APIs, never toString itself.
		id: "tostring_proxy", label: "Function.prototype.toString is proxied or replaced (stealth hallmark)", tier: TierHard, weight: 45, needsClient: true,
		eval: func(s Signals) (bool, string) {
			// Skip pre-v2 payloads: key didn't exist, false would be a lie.
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
		// The iframe realm has its own Navigator.prototype, which top-frame patches miss.
		id: "iframe_webdriver", label: "navigator.webdriver is true inside the iframe", tier: TierHard, weight: 60, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.IframeWebdriver, "" },
	},
	{
		id: "webdriver_sw", label: "navigator.webdriver is true in the Service Worker", tier: TierHard, weight: 60, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.SWWebdriver, "" },
	},

	// ── Consistency (client claim vs. server / second context) ─────────────────
	{
		id: "ua_header_mismatch", label: "JS User-Agent ≠ HTTP User-Agent", tier: TierConsistency, subgroup: subgroupUA, weight: 35, needsClient: true, needsHeaders: true,
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
		// Primary subtags only: en-US and en are the same language.
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
		// Assumes throttling (Firefox RFP, Brave farbling) caps cores alike in every context.
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
		id: "context_webgl_mismatch", label: "Worker WebGL renderer ≠ main-thread WebGL renderer", tier: TierConsistency, subgroup: subgroupContext, weight: 20, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.WebGLRenderer == "" || s.WorkerWebGLRenderer == "" || s.WebGLRenderer == s.WorkerWebGLRenderer {
				return false, ""
			}
			return true, "worker renderer differs from main thread"
		},
	},
	{
		id: "ch_platform_mismatch", label: "Sec-CH-UA-Platform ≠ navigator.userAgentData.platform", tier: TierConsistency, subgroup: subgroupUA, weight: 30, needsClient: true, needsHeaders: true,
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
		id: "embedded_runtime", label: "User-Agent is an embedded app runtime (Electron/CEF)", tier: TierConsistency, subgroup: subgroupUA, weight: 25, needsHeaders: true,
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
		id: "tz_mismatch", label: "Browser timezone ≠ IP timezone", tier: TierConsistency, subgroup: subgroupNetwork, weight: 25, needsClient: true, needsIP: true,
		eval: func(s Signals) (bool, string) {
			if s.BrowserTZ == "" || s.IPTimezone == "" {
				return false, ""
			}
			// IP2Location gives "+03:00", the browser an IANA name: compare offsets, not strings.
			if offsetFormat(s.IPTimezone) {
				bo, ok := ianaOffset(s.BrowserTZ, s.Now)
				if !ok || bo == s.IPTimezone {
					return false, "" // unknown/unstampable zone ⇒ can't verify, don't fire
				}
				return true, fmt.Sprintf("browser %s (%s) vs IP %s", s.BrowserTZ, bo, s.IPTimezone)
			}
			// Both look like IANA names (other IP DB formats) -> name compare.
			if strings.EqualFold(s.BrowserTZ, s.IPTimezone) {
				return false, ""
			}
			return true, fmt.Sprintf("browser %s vs IP %s", s.BrowserTZ, s.IPTimezone)
		},
	},
	{
		id: "datacenter_ip", label: "Egress IP is a datacenter / Tor address", tier: TierConsistency, subgroup: subgroupNetwork, weight: 30, needsIP: true,
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
		// IP2Proxy marks datacenters and Tor as proxies too; don't double-count what datacenter_ip caught.
		id: "proxy_ip", label: "Egress IP is a proxy / VPN", tier: TierConsistency, subgroup: subgroupNetwork, weight: 20, needsIP: true,
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
		// Server-observed, so not client-spoofable: consistency tier, like datacenter_ip.
		id: "ip_blocklisted", label: "Egress IP is on a threat / abuse blocklist", tier: TierConsistency, subgroup: subgroupNetwork, weight: 25, needsIP: true,
		eval: func(s Signals) (bool, string) {
			if len(s.IPBlocklistSources) == 0 {
				return false, ""
			}
			if !s.IPBlocklistDeliberate && s.IPBlocklistCount < ipsumBlocklistFloor {
				return false, "" // ipsum-only and below the auto-ban confidence floor
			}
			detail := "listed by " + strings.Join(s.IPBlocklistSources, ", ")
			if s.IPBlocklistCount > 0 {
				detail += fmt.Sprintf(" (%d lists)", s.IPBlocklistCount)
			}
			return true, detail
		},
	},
	{
		id: "permission_impossible", label: "Impossible permission state (prompt while denied)", tier: TierConsistency, subgroup: subgroupInternals, weight: 25, needsClient: true,
		eval: func(s Signals) (bool, string) {
			return s.PermissionState == "prompt" && s.NotificationPerm == "denied", ""
		},
	},
	{
		id: "lang_mismatch", label: "navigator.languages ≠ Accept-Language", tier: TierConsistency, subgroup: subgroupUA, weight: 15, needsClient: true, needsHeaders: true,
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
		id: "tz_self_inconsistent", label: "Timezone name disagrees with getTimezoneOffset()", tier: TierConsistency, subgroup: subgroupInternals, weight: 25, needsClient: true,
		eval: func(s Signals) (bool, string) {
			secs, ok := zoneOffsetSeconds(s.BrowserTZ, s.Now)
			if s.BrowserTZ == "" || !ok {
				return false, ""
			}
			expected := -secs / 60 // getTimezoneOffset = minutes west of UTC
			if expected == s.TZOffset {
				return false, ""
			}
			return true, fmt.Sprintf("%s implies %d min but reported %d", s.BrowserTZ, expected, s.TZOffset)
		},
	},
	{
		id: "canvas_unstable", label: "Canvas output is randomised between draws", tier: TierConsistency, subgroup: subgroupInternals, weight: 15, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.CanvasSupported && !s.CanvasStable, "" },
	},
	{
		id: "ch_brands_mismatch", label: "Sec-CH-UA header brands ≠ userAgentData.brands", tier: TierConsistency, subgroup: subgroupUA, weight: 20, needsClient: true, needsHeaders: true,
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
			// Every mainstream browser reports appVersion as UA minus "Mozilla/".
			if s.NavMainUA == "" || s.AppVersion == "" || !strings.HasPrefix(s.NavMainUA, "Mozilla/") {
				return false, ""
			}
			return s.AppVersion != strings.TrimPrefix(s.NavMainUA, "Mozilla/"), ""
		},
	},
	{
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
		// Unparseable = no signal, so Android's "ARM" vendor beside a "Mali" renderer stays silent.
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
		// Reads vendor and renderer together so Firefox and Safari strings classify as surely as ANGLE's.
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
		// Soft: current stealth evades this whole tamper family while privacy extensions trip it; see
		// docs/testing/findings/2026-07-21-internals-tamper-downgraded-to-soft.md.
		id: "native_descriptor_tamper", label: "Native function has an impossible property descriptor", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			// Pre-v2 payloads lack the key, so false there isn't tampering.
			if s.CollectorV < collectorVDeepTamper {
				return false, ""
			}
			return !s.NativeDescriptorsOK, ""
		},
	},
	{
		// Soft for the same reasons as native_descriptor_tamper.
		id: "native_callnew_tamper", label: "Native function misses its call/new TypeError traps", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			// Skip pre-v2 payloads, same as native_descriptor_tamper.
			if s.CollectorV < collectorVDeepTamper {
				return false, ""
			}
			return !s.NativeCallNewOK, ""
		},
	},
	{
		// True only when the patched getter verifiably throws; a genuine engine never does.
		id: "iframe_proxy", label: "iframe contentWindow is proxied (stealth iframe patch)", tier: TierConsistency, subgroup: subgroupInternals, weight: 30, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.IframeProxied, "" },
	},
	{
		// No reverse check (desktop UA with touch): touch-screen Windows laptops would fire constantly.
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
		// Soft: modern stealth hides webdriver with a launch flag and never touches this prototype.
		id: "navigator_proto_tamper", label: "Navigator.prototype accessor descriptor anomaly (webdriver/plugins/languages)", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.CollectorV < collectorVTamperV3 {
				return false, ""
			}
			return !s.NavProtoDescriptorsOK, ""
		},
	},
	{
		// Soft: stealth fakes chrome.runtime perfectly and real Chrome for Testing lacks it.
		id: "chrome_runtime_tamper", label: "window.chrome.runtime fails the integrity probe", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.CollectorV < collectorVTamperV3 {
				return false, ""
			}
			return strings.Contains(clientUA(s), "Chrome") && !s.ChromeRuntimeOK, ""
		},
	},
	{
		// Soft: current stealth fakes chrome.runtime in place instead of late-injecting it.
		id: "chrome_late_injection", label: "window.chrome was injected late (stealth bolt-on)", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			return strings.Contains(clientUA(s), "Chrome") && s.ChromeLateInjection, ""
		},
	},
	{
		// Error-stack based, independent of the CSS/capability probes engine_ua_mismatch uses.
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
		// Same-family only: a dual-stack IPv6 candidate vs an IPv4 egress would fire on real browsers.
		id: "webrtc_ip_mismatch", label: "Public WebRTC candidate IP ≠ egress IP", tier: TierConsistency, subgroup: subgroupNetwork, weight: 25, needsClient: true, needsIP: true,
		eval: func(s Signals) (bool, string) {
			egress, ok := publicIP(s.EgressIP)
			if !ok || len(s.WebRTCIPs) == 0 {
				return false, ""
			}
			for _, cand := range s.WebRTCIPs {
				ip, ok := publicIP(cand)
				if !ok || ip.Is4() != egress.Is4() {
					continue // private/loopback/etc., or different address family
				}
				if ip != egress {
					return true, fmt.Sprintf("WebRTC candidate %s ≠ egress %s", ip, egress)
				}
			}
			return false, ""
		},
	},

	{
		id: "fingerprint_reuse", label: "This exact fingerprint was seen from many IP addresses", tier: TierConsistency, subgroup: subgroupNetwork, weight: 25, needsClient: true, needsCorpus: true,
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
		id: "sec_fetch_missing", label: "Browser User-Agent but no Sec-Fetch-* headers", tier: TierSoft, weight: 8, needsHeaders: true,
		eval: func(s Signals) (bool, string) {
			if s.SecFetchMode == "" && looksLikeBrowser(s.HTTPUserAgent) {
				return true, "no Sec-Fetch-Mode"
			}
			return false, ""
		},
	},
	{
		id: "accept_encoding_missing", label: "Browser User-Agent but no Accept-Encoding header", tier: TierSoft, weight: 8, needsHeaders: true,
		eval: func(s Signals) (bool, string) {
			if looksLikeBrowser(s.HTTPUserAgent) && s.HTTPAcceptEncoding == "" {
				return true, "no Accept-Encoding"
			}
			return false, ""
		},
	},
	{
		// Complements lang_mismatch, which needs both sides; this catches the header's total absence.
		id: "accept_language_missing", label: "Browser User-Agent but no Accept-Language header", tier: TierSoft, weight: 8, needsHeaders: true,
		eval: func(s Signals) (bool, string) {
			if looksLikeBrowser(s.HTTPUserAgent) && s.AcceptLanguage == "" {
				return true, "no Accept-Language"
			}
			return false, ""
		},
	},
	{
		// The collector sends "Accept: text/html" to POST /check, so only JSON API callers trip this.
		id: "accept_nav_mismatch", label: "Browser User-Agent but Accept doesn't include text/html", tier: TierSoft, weight: 8, needsHeaders: true,
		eval: func(s Signals) (bool, string) {
			if looksLikeBrowser(s.HTTPUserAgent) && s.HTTPAccept != "" &&
				!strings.Contains(strings.ToLower(s.HTTPAccept), "text/html") {
				return true, "Accept: " + s.HTTPAccept
			}
			return false, ""
		},
	},
	{
		id: "canvas_blank", label: "Canvas renders blank (blocked / headless)", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.CanvasSupported && s.CanvasBlank, "" },
	},
	{
		id: "missing_proprietary_codecs", label: "Browser lacks H.264 and AAC (stripped/headless build)", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			return looksLikeBrowser(clientUA(s)) && !s.CodecH264 && !s.CodecAAC, ""
		},
	},
	{
		id: "no_fonts", label: "No system fonts detectable", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.FontCount == 0, "" },
	},
	{
		// True = bad, so a stale pre-v3 payload (binds false) stays safe without a version gate.
		id: "image_broken", label: "A guaranteed-loadable image failed (images stripped)", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.ImageBroken, "" },
	},
	{
		id: "plugins_mimetypes_incoherent", label: "Plugins present but no mimeTypes (incoherent fake)", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.CollectorV < collectorVTamperV3 {
				return false, ""
			}
			return s.Plugins > 0 && s.MimeTypes == 0, ""
		},
	},
	{
		// The InnerH > 0 guard makes stale pre-v3 payloads (both 0) skip instead of firing.
		id: "zero_outer_height", label: "window.outerHeight is zero", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.OuterH == 0 && s.InnerH > 0, "" },
	},
	{
		// v4-gated: a stale collector never sent env, so MatchMedia would bind false and read as evidence.
		id: "matchmedia_missing", label: "Browser User-Agent but window.matchMedia is missing", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.CollectorV < collectorVTamperV4 {
				return false, ""
			}
			return looksLikeBrowser(clientUA(s)) && !s.Env.MatchMedia, ""
		},
	},
	{
		// The browser derives effectiveType from rtt/downlink (worst of the two), so only a strictly faster
		// claim fires; thresholds allow for the API's rounding (see ectFromRTT).
		id: "netinfo_incoherent", label: "navigator.connection effectiveType contradicts its own rtt/downlink", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.CollectorV < collectorVTamperV4 {
				return false, ""
			}
			c := s.Env.Connection
			claimed := ectRank(c.EffectiveType)
			if claimed == 0 {
				return false, "" // API absent or future/unknown type ⇒ can't compare
			}
			worst, seen := 4, false
			if c.RTT > 0 {
				worst, seen = min(worst, ectFromRTT(c.RTT)), true
			}
			if c.Downlink > 0 {
				worst, seen = min(worst, ectFromDownlink(c.Downlink)), true
			}
			if !seen || claimed <= worst {
				return false, "" // no metrics to check, or claim isn't faster than implied
			}
			return true, fmt.Sprintf("effectiveType %q but rtt %dms / downlink %.2fMbps imply at most %s",
				c.EffectiveType, c.RTT, c.Downlink, ectName(worst))
		},
	},
	{
		id: "ip_fingerprint_churn", label: "This IP presented many different fingerprints in a short window", tier: TierSoft, weight: 8, needsClient: true, needsCorpus: true,
		eval: func(s Signals) (bool, string) {
			if s.FingerprintChurn < fingerprintChurnMinHashes {
				return false, ""
			}
			return true, fmt.Sprintf("%d distinct fingerprints from this IP in the churn window", s.FingerprintChurn)
		},
	},
	{
		// Soft: the trap fired zero times against five CDP-driven frameworks on current Chromium; it stays
		// because it costs nothing while silent. See docs/testing/checks/cdp_both.md.
		id: "cdp_both", label: "CDP automation detected in main thread and Worker", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.CDPMainThread && s.CDPWorker, "" },
	},
	{
		// Same downgrade + reasoning as cdp_both above.
		id: "cdp_main_only", label: "CDP automation detected in main thread only", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.CDPMainThread && !s.CDPWorker, "" },
	},
	{
		// The main/worker guards stop one observation counting twice in the soft cluster.
		id: "cdp_sw_only", label: "CDP automation detected in the Service Worker only", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.SWCDP && !s.CDPMainThread && !s.CDPWorker, "" },
	},
}
