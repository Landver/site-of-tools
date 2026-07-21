package botcheck

import (
	"fmt"
	"strings"
)

// rule is one detection signal. eval reports whether anomaly fired + short
// human detail for table. needsClient marks rules reading client-collected
// field → Evaluate can skip (not fail) them on server-only request. Weights =
// starting proposal, tuned against botcheck/tests — not gospel; adjust there,
// w/ fixtures, not by feel.
type rule struct {
	id          string
	label       string
	tier        string
	subgroup    string
	weight      int
	needsClient bool
	eval        func(Signals) (bool, string)
}

// gpuOSImpossible = exhaustive list of GPU-family/OS pairs gpu_os_mismatch may
// fire on — combos no shipping hardware produces: Apple GPU off macOS/iOS,
// desktop discrete GPU (NVIDIA GeForce / AMD Radeon) on phone OS, mobile
// Adreno/Mali on Apple desktop OS. Everything else deliberately silent → real
// machines exist: AMD Radeon+macOS (Intel Macs), NVIDIA+macOS (pre-2014 Macs),
// Adreno+Windows (Snapdragon ARM laptops), Intel+Android (old Atom phones),
// anything+Chrome OS.
var gpuOSImpossible = map[string]map[string]bool{
	"apple":  {"Windows": true, "Linux": true, "Android": true},
	"nvidia": {"iOS": true, "Android": true},
	"amd":    {"iOS": true, "Android": true},
	"adreno": {"macOS": true, "iOS": true},
	"mali":   {"macOS": true, "iOS": true},
}

// rules = full ordered signal set. Hard tells first (each near-standalone),
// then cross-layer/cross-context consistency checks (the load-bearing ones),
// then soft heuristics (only counted as cluster — see Evaluate). Score = sum
// of triggered weights subtracted from 100.
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
			// → would otherwise escape this penalty. Check both header + any posted
			// navigator UA. *Verified* good bot has this deduction suppressed in
			// Evaluate; unverified one keeps it — recognition ≠ leniency.
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
		// Proxying Function.prototype.toString = puppeteer-extra-stealth hallmark:
		// exists precisely to defeat shallow native_tamper check, no legit software
		// does it — privacy extensions patch DOM leak-surface APIs (canvas/WebGL),
		// never toString itself. Why this one's hard while G04 descriptor/call-new
		// probes below stay consistency-tier.
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
		// G11: navigator.webdriver re-read inside iframe's fresh JS context. Stealth
		// toolkits patch top frame's navigator (even its prototype); iframe realm
		// has own Navigator.prototype → leaks truth.
		id: "iframe_webdriver", label: "navigator.webdriver is true inside the iframe", tier: TierHard, weight: 60, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.IframeWebdriver, "" },
	},
	{
		// G14: navigator.webdriver read inside Service Worker — third context a
		// top-frame-only webdriver patch forgets (incolumitas
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
		// tools patch top frame's navigator only → worker/iframe/SW still shows
		// real list. Compare primary subtags only (en-US vs en = same language),
		// only when both sides answered — empty context list means API unsupported
		// there, not mismatch.
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
		// (false-positive guard): anti-fingerprint throttling caps value GLOBALLY,
		// not per-context — Firefox resistFingerprinting + Brave farbling report
		// same capped number in every context of origin → real privacy browser
		// still agrees w/ itself. Only spoof that patched one context and forgot
		// others disagrees.
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
		// Safari/Firefox → simply skip). normPlatform both sides → "macOS" vs
		// "Mac OS X" spelling variants can't false-fire.
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
		// G03: worker's WebGL unmasked renderer (read via OffscreenCanvas) vs main
		// thread's — CreepJS hasBadWebGL diff. Same browser, same GPU ⇒ same
		// renderer string; spoofed top-frame WebGL read disagrees. Fires only when
		// both reads succeed (OffscreenCanvas WebGL often unsupported → leaves
		// worker side empty).
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
		// Feature-detect real rendering engine (Blink/Gecko/WebKit) client-side,
		// compare to engine UA claims. Robust against spoofed UA string: engine
		// probes read capabilities UA can't fake. Fires only on confident
		// disagreement (both sides known + different).
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
		// UA-string spoof editing "Chrome/NNN" but leaving userAgentData intact
		// disagrees here: UA's Chromium major must equal "Chromium" brand entry of
		// fullVersionList (see chVersionMajor). CreepJS/Electron frozen-UA catch.
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
			// IP2Location gives UTC offset ("+03:00"); browser gives IANA name
			// ("Europe/Moscow"). Compare offset-to-offset — plain string compare
			// would fire for every real visitor (formats never match).
			if offsetFormat(s.IPTimezone) {
				bo, ok := ianaOffset(s.BrowserTZ, s.Now)
				if !ok || bo == s.IPTimezone {
					return false, "" // unknown/unstampable zone ⇒ can't verify, don't fire
				}
				return true, fmt.Sprintf("browser %s (%s) vs IP %s", s.BrowserTZ, bo, s.IPTimezone)
			}
			// Both look like IANA names (other IP DB formats) → name compare.
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
		// Mutually exclusive w/ datacenter_ip: IP2Proxy marks datacenters/Tor as
		// proxies too → only fire here for VPN or otherwise-uncategorised proxy —
		// never double-count address the datacenter rule already caught.
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
		// G37: egress IP on the shared abuse/threat blocklist corpus — ipsum
		// aggregate feed (30+ lists) + anything another service writes into
		// ip_blocklist. Server-observed, not client-spoofable, same class as
		// datacenter_ip/proxy_ip → consistency tier. Fires only above a floor:
		// ipsum-only needs ≥ ipsumBlocklistFloor lists (ipsum's own auto-ban
		// grade — one feed drifting onto a recycled residential IP mustn't tank a
		// real human), a deliberate ban from any other source fires regardless of
		// count. Empty sources ("not listed" / Mongo off) never fire. Suppressed
		// for verified good bots (all their reputation deductions are).
		id: "ip_blocklisted", label: "Egress IP is on a threat / abuse blocklist", tier: TierConsistency, subgroup: subgroupNetwork, weight: 25,
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
		// Self-consistency (no IP needed): browser's own IANA timezone must agree
		// w/ own Date().getTimezoneOffset(). Spoofers commonly change one, forget
		// other.
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
		// Randomised canvas output (two identical draws hashing differently) =
		// noise-injecting anti-fingerprint / stealth tool.
		id: "canvas_unstable", label: "Canvas output is randomised between draws", tier: TierConsistency, subgroup: subgroupInternals, weight: 15, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.CanvasSupported && !s.CanvasStable, "" },
	},
	{
		// Parse Sec-CH-UA header brand list (server), compare to JS
		// userAgentData.brands (client); spoofed User-Agent forgetting to keep
		// the two in sync caught here. GREASE decoy brand ignored.
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
			// Every mainstream browser reports appVersion as UA minus "Mozilla/".
			if s.NavMainUA == "" || s.AppVersion == "" || !strings.HasPrefix(s.NavMainUA, "Mozilla/") {
				return false, ""
			}
			return s.AppVersion != strings.TrimPrefix(s.NavMainUA, "Mozilla/"), ""
		},
	},
	{
		// navigator.productSub = fixed per-engine constant ("20030107" on every
		// WebKit/Blink browser, "20100101" on Gecko). Value not matching engine UA
		// claims = classic spoof/patched-runtime tell.
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
		// G07: unmasked WebGL VENDOR + RENDERER both come from same GPU driver →
		// real browser never reports different vendor families — Chrome's ANGLE
		// pair internally consistent ("Google Inc. (NVIDIA)" / "ANGLE (NVIDIA,
		// ...)"), modern Safari generalises both to "Apple Inc." / "Apple GPU".
		// Cross-family pair (vendor says Apple, renderer says NVIDIA) = hand-edited
		// spoof. Fires only when BOTH sides parse to confident family AND differ:
		// empty/unparseable string (VM, software rasteriser, masked) = no signal →
		// e.g. "ARM" vendor beside "Mali" renderer (normal on Android) stays
		// silent.
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
		// G08: GPU family must be plausible for OS UA claims — catch is anti-detect
		// browser rewriting OS in UA but can't change real GPU WebGL reports. Fires
		// ONLY on enumerated impossible pairs (gpuOSImpossible): Apple GPU on
		// Windows/Linux/Android, desktop NVIDIA/AMD on iOS/Android, mobile
		// Adreno/Mali on macOS/iOS. Deliberately silent on every ambiguous combo —
		// AMD Radeon+macOS (Intel Macs exist), Adreno+Windows (Snapdragon ARM
		// laptops), Intel anywhere, any GPU+Chrome OS, Mesa/unknown GPU,
		// unparseable UA. GPU family read from vendor+renderer together → Firefox
		// ("NVIDIA Corporation") + Safari ("Apple Inc." / "Apple GPU") classified
		// as confidently as ANGLE.
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
		// Downgraded consistency → soft (2026-07-21). This probe + four other
		// deep-tamper siblings below (native_callnew_tamper, navigator_proto_tamper,
		// chrome_runtime_tamper, chrome_late_injection) built to catch
		// puppeteer-extra-stealth's signature. 2026-07-19 audit established two
		// things about whole class: (1) current stealth EVADES all of them cleanly
		// (shared _utils spreads original descriptor → nothing looks off) → adds
		// nothing against adversary they targeted; (2) only things that DO trip
		// them = legit privacy extension patching DOM API (real human) or naive
		// hand-patch, and at consistency/25 two firing on privacy-tool user dropped
		// genuine human to 50/"suspicious" — false positive tool shouldn't
		// manufacture. Soft (cluster-only, 8) keeps them as corroboration when
		// several fire w/ other soft tells, but no single one can dock human alone
		// again. Same handling + precedent as CDP-trap trio (see cdp_both). Full
		// rationale: docs/testing/findings/2026-07-21-internals-tamper-downgraded-to-soft.md.
		id: "native_descriptor_tamper", label: "Native function has an impossible property descriptor", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			// Skip pre-v2 payloads (stale collector): false would mean "field didn't
			// exist yet", not tampering — see collectorVDeepTamper.
			if s.CollectorV < collectorVDeepTamper {
				return false, ""
			}
			return !s.NativeDescriptorsOK, ""
		},
	},
	{
		// Downgraded consistency → soft (2026-07-21); same reasoning + precedent as
		// native_descriptor_tamper above — evaded by current stealth, real
		// false-positive risk against privacy extension's DOM-API override → only
		// bites as part of soft cluster now.
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
		// G11: iframe's contentWindow is a Proxy — puppeteer-extra-stealth
		// iframe.contentWindow patch wrapping fresh context to inject spoofs
		// (CreepJS hasIframeProxy). True only when patched getter verifiably
		// throws; genuine engine never does.
		id: "iframe_proxy", label: "iframe contentWindow is proxied (stealth iframe patch)", tier: TierConsistency, subgroup: subgroupInternals, weight: 30, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.IframeProxied, "" },
	},
	{
		// G12: phone UA reporting zero touch points. Real Android/iOS devices
		// always report maxTouchPoints > 0; desktop browser wearing mobile UA
		// reports 0. v3-gated: field damning when zero on stale payload that never
		// sent it. Deliberately no reverse direction (desktop UA + touch):
		// touch-screen Windows laptops would false-fire constantly.
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
		// G17: per WebIDL, webdriver/plugins/languages = accessor (getter-only)
		// properties — enumerable, configurable, living on Navigator.prototype,
		// never own data properties on navigator instance. Spoof installed via
		// defineProperty/assignment breaks at least one. Downgraded consistency →
		// soft (2026-07-21), same reasoning + precedent as native_descriptor_tamper
		// above: modern stealth doesn't patch navigator.webdriver in JS at all
		// (uses launch flag) → only catches naive hand-patch or legit privacy
		// extension — cluster-only now. v3-gated: OK bool damning when false on
		// stale payload that never sent it.
		id: "navigator_proto_tamper", label: "Navigator.prototype accessor descriptor anomaly (webdriver/plugins/languages)", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.CollectorV < collectorVTamperV3 {
				return false, ""
			}
			return !s.NavProtoDescriptorsOK, ""
		},
	},
	{
		// G22: genuine window.chrome on Chrome carries chrome.runtime w/ native
		// non-constructor connect/sendMessage (no own prototype, `new fn()` throws
		// a TypeError); stealth-bolted fake gets shape or error constructor wrong
		// (CreepJS hasBadChromeRuntime). Downgraded consistency → soft
		// (2026-07-21): most-evaded of group — current stealth fakes chrome.runtime
		// perfectly, AND official Chrome-for-Testing binary lacks chrome.runtime
		// entirely (tightened version risked flagging real visitors) → catches only
		// naive fake now. Cluster-only. Chrome UA only; v3-gated like other
		// fail-to-pass OK bools.
		id: "chrome_runtime_tamper", label: "window.chrome.runtime fails the integrity probe", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.CollectorV < collectorVTamperV3 {
				return false, ""
			}
			return strings.Contains(clientUA(s), "Chrome") && !s.ChromeRuntimeOK, ""
		},
	},
	{
		// G22: genuine Chrome creates window.chrome during page setup → sits early
		// among window keys; stealth patch bolting on fake chrome object appends it
		// late — 'chrome' in last ~50 window keys (CreepJS hasHighChromeIndex).
		// Downgraded consistency → soft (2026-07-21), same group as
		// chrome_runtime_tamper above: current stealth fakes chrome.runtime in
		// place rather than late-injecting → catches only naive bolt-on —
		// cluster-only now. Chrome UA only.
		id: "chrome_late_injection", label: "window.chrome was injected late (stealth bolt-on)", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			return strings.Contains(clientUA(s), "Chrome") && s.ChromeLateInjection, ""
		},
	},
	{
		// G23: JS engine detected from Error-stack format (V8 " at " frames,
		// SpiderMonkey fileName/lineNumber, JSC otherwise) vs engine UA claims —
		// second engine check, independent of CSS/capability probes
		// engine_ua_mismatch uses, robust against spoofed UA string. Both sides
		// confident or no fire.
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
		// G09: PUBLIC WebRTC candidate IP that isn't connection's egress IP —
		// classic VPN/proxy pierce: browser leaks real address over STUN while
		// HTTP traffic egresses through proxy. Private/link-local/loopback/
		// ULA/CGNAT candidates excluded (host candidate ≠ egress is normal NAT,
		// never a tell), only same-family candidates compared (dual-stack
		// IPv6-vs-IPv4 would false-fire real browsers). Empty candidate list or
		// unknown egress means "not supplied" ⇒ no signal.
		id: "webrtc_ip_mismatch", label: "Public WebRTC candidate IP ≠ egress IP", tier: TierConsistency, subgroup: subgroupNetwork, weight: 25, needsClient: true,
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
		// G41/G42: exact stable fingerprint (UA, screen, GPU, timezone, …)
		// recorded from many distinct IPs in rolling 30-day Mongo corpus —
		// scraping-farm tell (farm locks one fingerprint, rotates proxy pool;
		// incolumitas ScrapingBee catch). FingerprintIPs = 0 ("no corpus data")
		// whenever Mongo off or count failed → never fires; one person roaming
		// networks reaches couple IPs honestly, hence five-IP floor. Verified
		// crawler fleets legitimately share one fingerprint across many IPs →
		// deduction suppressed for them (suppressedForGoodBot).
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
		// Real browsers send Sec-Fetch-* on every navigation+fetch; scripted
		// client wearing browser User-Agent usually omits them. Soft: proxy could
		// in theory strip them.
		id: "sec_fetch_missing", label: "Browser User-Agent but no Sec-Fetch-* headers", tier: TierSoft, weight: 8,
		eval: func(s Signals) (bool, string) {
			if s.SecFetchMode == "" && looksLikeBrowser(s.HTTPUserAgent) {
				return true, "no Sec-Fetch-Mode"
			}
			return false, ""
		},
	},
	{
		// Real browsers send Accept-Encoding on every request (all support at
		// least gzip); browser User-Agent without one = scripted client that
		// didn't bother. Soft, not consistency: proxy (CF/nginx) on path can strip
		// or rewrite these headers — exact caveat that made sec_fetch_missing
		// soft.
		id: "accept_encoding_missing", label: "Browser User-Agent but no Accept-Encoding header", tier: TierSoft, weight: 8,
		eval: func(s Signals) (bool, string) {
			if looksLikeBrowser(s.HTTPUserAgent) && s.HTTPAcceptEncoding == "" {
				return true, "no Accept-Encoding"
			}
			return false, ""
		},
	},
	{
		// Same shape: every real browser sends Accept-Language. Complements
		// lang_mismatch consistency rule, which needs BOTH sides (navigator.languages
		// + header) to compare values — this one catches header's total absence.
		// Soft for same proxy-strips-headers caveat as sec_fetch_missing.
		id: "accept_language_missing", label: "Browser User-Agent but no Accept-Language header", tier: TierSoft, weight: 8,
		eval: func(s Signals) (bool, string) {
			if looksLikeBrowser(s.HTTPUserAgent) && s.AcceptLanguage == "" {
				return true, "no Accept-Language"
			}
			return false, ""
		},
	},
	{
		// Real browser's navigation/fetch Accept always includes text/html;
		// scripted client wearing browser User-Agent sends */* (bare curl) or
		// application/json. POST /check arrives from fetch() and vendored
		// collector explicitly sets "Accept: text/html" → genuine browser flow
		// never trips this — but JSON API consumers (Accept: application/json)
		// do. Acceptable precisely because rule is soft: only bites inside >=3
		// soft cluster, proxy can rewrite header anyway (caveat that made
		// sec_fetch_missing soft). EMPTY Accept means "not supplied", never
		// fires.
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
		// Canvas rendering nothing (all transparent) = blocked or headless.
		id: "canvas_blank", label: "Canvas renders blank (blocked / headless)", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.CanvasSupported && s.CanvasBlank, "" },
	},
	{
		// Stock desktop Chrome/Edge/Safari ship H.264+AAC; stripped/Chromium
		// headless build often supports neither.
		id: "missing_proprietary_codecs", label: "Browser lacks H.264 and AAC (stripped/headless build)", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			return looksLikeBrowser(clientUA(s)) && !s.CodecH264 && !s.CodecAAC, ""
		},
	},
	{
		// No detectable fonts at all → neutralised font-enumeration surface or
		// font-less headless/VM environment.
		id: "no_fonts", label: "No system fonts detectable", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.FontCount == 0, "" },
	},
	{
		// G10: 1×1 data-URI image that MUST load in any real browser reported
		// naturalWidth == 0 or errored — images stripped/blocked, headless tell.
		// Soft: image-blocking extension is user choice → only bites in cluster.
		// true = bad keeps stale (pre-v3) payloads safe.
		id: "image_broken", label: "A guaranteed-loadable image failed (images stripped)", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.ImageBroken, "" },
	},
	{
		// Faked navigator.plugins array that forgot paired mimeTypes: plugins
		// present but zero mimeTypes. v3-gated: mimeTypes damning when zero on
		// stale payload that never sent it.
		id: "plugins_mimetypes_incoherent", label: "Plugins present but no mimeTypes (incoherent fake)", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.CollectorV < collectorVTamperV3 {
				return false, ""
			}
			return s.Plugins > 0 && s.MimeTypes == 0, ""
		},
	},
	{
		// Zero window.outerHeight while innerHeight positive — headless window
		// tell. InnerH > 0 guard makes stale pre-v3 payloads (where both bind 0)
		// skip instead of firing.
		id: "zero_outer_height", label: "window.outerHeight is zero", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.OuterH == 0 && s.InnerH > 0, "" },
	},
	{
		// G15: window.matchMedia is a function in every real browser, desktop+
		// mobile, since CSS2 era — browser-claimed UA without it = stripped JS
		// environment (jsdom-style) wearing browser UA. Soft, not hard: exotic
		// embedded webview could conceivably lack it. v4-gated: stale collector
		// never sent env section → missing value would bind false and read as
		// evidence on pre-v4 payload.
		id: "matchmedia_missing", label: "Browser User-Agent but window.matchMedia is missing", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.CollectorV < collectorVTamperV4 {
				return false, ""
			}
			return looksLikeBrowser(clientUA(s)) && !s.Env.MatchMedia, ""
		},
	},
	{
		// G21: navigator.connection derives effectiveType from the very
		// rtt/downlink estimates it reports (worst of the two, per spec's
		// threshold table) → type can never be FASTER than its own numbers imply —
		// a '4g' claim beside rtt 2000 = spoofed override. Thresholds graced by
		// API's own reporting rounding (see ectFromRTT) → real browser's rounded
		// values never contradict its claim, only strictly-faster claim fires: a
		// slower claim is conceivable from a mid-update estimate, never counts.
		// Silent when connection absent (most Firefox/Safari) — that absence is
		// normal, never a signal. Soft: network estimates update asynchronously →
		// live change mid-read could briefly disagree — only bites in cluster.
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
		// G43: this egress IP presented many DISTINCT fingerprints inside rolling
		// churn window — fingerprint-rotation tell, temporal inverse of
		// fingerprint_reuse (reuse = one fingerprint from many IPs; churn = many
		// fingerprints from one IP). FingerprintChurn = 0 ("no corpus data")
		// whenever Mongo off or count failed → never fires; household's few
		// devices or person re-checking after browser tweaks stays under floor.
		// Soft, NOT consistency: large corporate NAT can legitimately present
		// many browsers from one address → only bites as part of cluster, never
		// docks lone visitor. Backed by same Mongo corpus as fingerprint_reuse
		// (see corpus.go).
		id: "ip_fingerprint_churn", label: "This IP presented many different fingerprints in a short window", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.FingerprintChurn < fingerprintChurnMinHashes {
				return false, ""
			}
			return true, fmt.Sprintf("%d distinct fingerprints from this IP in the churn window", s.FingerprintChurn)
		},
	},
	{
		// Downgraded from hard/weight-40 (2026-07-19): audit tested this trap
		// (Error.stack getter read during console.debug call — see cdpTrap() in
		// shared/static/js/botcheck.js) against five genuinely CDP-driven
		// sessions — Puppeteer (headless + headful), Playwright,
		// Selenium/chromedriver, hand-rolled CDP client w/ Runtime.enable active
		// + no --enable-automation, puppeteer-extra-stealth — fired zero times
		// across all of them. Premise (CDP client's object-preview generation
		// invokes property getters) doesn't hold on current Chromium regardless
		// of transport; not one browser evading it. Left running (harmless when
		// silent, free in case future Chromium regression or older engine
		// revives it) rather than deleted — see
		// tools/botcheck/docs/testing/findings/2026-07-19-cdp-trap-family-confirmed-dead.md for full writeup.
		id: "cdp_both", label: "CDP automation detected in main thread and Worker", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.CDPMainThread && s.CDPWorker, "" },
	},
	{
		// Same downgrade + reasoning as cdp_both above.
		id: "cdp_main_only", label: "CDP automation detected in main thread only", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.CDPMainThread && !s.CDPWorker, "" },
	},
	{
		// Same downgrade + reasoning as cdp_both above. Still guarded against
		// main/worker flags so one observation never double-counts w/ cdp_both /
		// cdp_main_only in the soft-signal cluster count.
		id: "cdp_sw_only", label: "CDP automation detected in the Service Worker only", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.SWCDP && !s.CDPMainThread && !s.CDPWorker, "" },
	},
}
