package linktools

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// TTLSummary holds the computed freshness lifetime for browser and CDN edge.
type TTLSummary struct {
	BrowserTTLSeconds int    `json:"browser_ttl_seconds"`
	BrowserTTLHuman   string `json:"browser_ttl_human"`
	EdgeTTLSeconds    int    `json:"edge_ttl_seconds"`
	EdgeTTLHuman      string `json:"edge_ttl_human"`
	StaleWhileReval   int    `json:"stale_while_revalidate_seconds"`
	StaleIfError      int    `json:"stale_if_error_seconds"`
	Public            bool   `json:"public"`
	Private           bool   `json:"private"`
	NoStore           bool   `json:"no_store"`
	NoCache           bool   `json:"no_cache"`
	MustRevalidate    bool   `json:"must_revalidate"`
	Immutable         bool   `json:"immutable"`
	Heuristic         bool   `json:"heuristic"`
	RemainingSeconds  int    `json:"remaining_seconds"`
}

// CacheAnalysis holds the full RFC 9111 and RFC 9213 cache audit result.
type CacheAnalysis struct {
	TTL          TTLSummary   `json:"ttl"`
	Directives   []Directive  `json:"directives"`
	Findings     []HeaderNote `json:"findings"`
	ETag         string       `json:"etag,omitempty"`
	IsWeakETag   bool         `json:"is_weak_etag,omitempty"`
	LastModified string       `json:"last_modified,omitempty"`
	VaryHeaders  []string     `json:"vary_headers,omitempty"`
	AgeSeconds   int          `json:"age_seconds,omitempty"`
}

// Directive is one parsed Cache-Control or CDN-Cache-Control directive.
type Directive struct {
	Source string `json:"source"` // "Cache-Control", "CDN-Cache-Control", etc.
	Name   string `json:"name"`
	Value  string `json:"value,omitempty"`
}

// HeaderNote represents an observation or finding about caching or security.
type HeaderNote struct {
	Severity string `json:"severity"` // "fail", "warn", "ok", "info"
	Category string `json:"category"` // "cache", "security", "cookie"
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	RFC      string `json:"rfc,omitempty"`
}

// parseDirectives splits comma-separated header directives like "public, max-age=3600, must-revalidate".
func parseDirectives(source, headerVal string) []Directive {
	var res []Directive
	parts := strings.Split(headerVal, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		var name, val string
		if idx := strings.IndexByte(p, '='); idx >= 0 {
			name = strings.TrimSpace(p[:idx])
			val = strings.Trim(strings.TrimSpace(p[idx+1:]), "\"")
		} else {
			name = p
		}
		res = append(res, Directive{
			Source: source,
			Name:   strings.ToLower(name),
			Value:  val,
		})
	}
	return res
}

func formatDuration(sec int) string {
	if sec <= 0 {
		return "0s (no caching)"
	}
	if sec < 60 {
		return fmt.Sprintf("%ds", sec)
	}
	if sec < 3600 {
		m := sec / 60
		s := sec % 60
		if s == 0 {
			return fmt.Sprintf("%dm", m)
		}
		return fmt.Sprintf("%dm %ds", m, s)
	}
	if sec < 86400 {
		h := sec / 3600
		m := (sec % 3600) / 60
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh %dm", h, m)
	}
	d := sec / 86400
	h := (sec % 86400) / 3600
	if h == 0 {
		return fmt.Sprintf("%dd", d)
	}
	return fmt.Sprintf("%dd %dh", d, h)
}

// AnalyzeCache inspects headers for RFC 9111 HTTP caching and RFC 9213 CDN-Cache-Control.
func AnalyzeCache(statusCode int, h http.Header) CacheAnalysis {
	var analysis CacheAnalysis
	var allDirectives []Directive

	rawCC := h.Get("Cache-Control")
	rawCDN := h.Get("CDN-Cache-Control")
	rawCFCDN := h.Get("Cloudflare-CDN-Cache-Control")
	rawSurrogate := h.Get("Surrogate-Control")
	rawExpires := h.Get("Expires")
	rawPragma := h.Get("Pragma")
	rawETag := strings.TrimSpace(h.Get("ETag"))
	rawAge := strings.TrimSpace(h.Get("Age"))
	rawVary := h.Get("Vary")

	analysis.ETag = rawETag
	if strings.HasPrefix(rawETag, "W/") || strings.HasPrefix(rawETag, "w/") {
		analysis.IsWeakETag = true
	}
	analysis.LastModified = h.Get("Last-Modified")

	if rawAge != "" {
		if a, err := strconv.Atoi(rawAge); err == nil && a >= 0 {
			analysis.AgeSeconds = a
		}
	}

	if rawVary != "" {
		for _, v := range strings.Split(rawVary, ",") {
			v = strings.TrimSpace(v)
			if v != "" {
				analysis.VaryHeaders = append(analysis.VaryHeaders, v)
			}
		}
	}

	ccDirs := parseDirectives("Cache-Control", rawCC)
	cdnDirs := parseDirectives("CDN-Cache-Control", rawCDN)
	cfDirs := parseDirectives("Cloudflare-CDN-Cache-Control", rawCFCDN)
	surrogateDirs := parseDirectives("Surrogate-Control", rawSurrogate)

	allDirectives = append(allDirectives, ccDirs...)
	allDirectives = append(allDirectives, cdnDirs...)
	allDirectives = append(allDirectives, cfDirs...)
	allDirectives = append(allDirectives, surrogateDirs...)
	analysis.Directives = allDirectives

	// Parse directives map for Cache-Control
	ccMap := make(map[string]string)
	for _, d := range ccDirs {
		ccMap[d.Name] = d.Value
	}

	// Parse directives map for Edge CDN
	edgeMap := make(map[string]string)
	for _, d := range cdnDirs {
		edgeMap[d.Name] = d.Value
	}
	for _, d := range cfDirs {
		if _, ok := edgeMap[d.Name]; !ok {
			edgeMap[d.Name] = d.Value
		}
	}
	for _, d := range surrogateDirs {
		if _, ok := edgeMap[d.Name]; !ok {
			edgeMap[d.Name] = d.Value
		}
	}

	ttl := TTLSummary{}

	// Flags
	if _, ok := ccMap["no-store"]; ok {
		ttl.NoStore = true
	}
	if _, ok := ccMap["no-cache"]; ok {
		ttl.NoCache = true
	}
	if _, ok := ccMap["must-revalidate"]; ok {
		ttl.MustRevalidate = true
	}
	if _, ok := ccMap["immutable"]; ok {
		ttl.Immutable = true
	}
	if _, ok := ccMap["public"]; ok {
		ttl.Public = true
	}
	if _, ok := ccMap["private"]; ok {
		ttl.Private = true
	}

	// Browser TTL
	if ttl.NoStore {
		ttl.BrowserTTLSeconds = 0
		ttl.BrowserTTLHuman = "0s (no-store: not cached)"
	} else if ttl.NoCache {
		ttl.BrowserTTLSeconds = 0
		ttl.BrowserTTLHuman = "0s (no-cache: must revalidate before use)"
	} else if maxAgeStr, ok := ccMap["max-age"]; ok {
		if ma, err := strconv.Atoi(maxAgeStr); err == nil && ma >= 0 {
			ttl.BrowserTTLSeconds = ma
			ttl.BrowserTTLHuman = formatDuration(ma)
		}
	} else if rawExpires != "" {
		// RFC 9111 §5.3 Expires fallback when max-age absent
		if t, err := http.ParseTime(rawExpires); err == nil {
			diff := int(time.Until(t).Seconds())
			if diff > 0 {
				ttl.BrowserTTLSeconds = diff
				ttl.BrowserTTLHuman = formatDuration(diff) + " (from Expires)"
			} else {
				ttl.BrowserTTLSeconds = 0
				ttl.BrowserTTLHuman = "0s (expired via Expires header)"
			}
		}
	} else if rawCC == "" && rawExpires == "" {
		ttl.Heuristic = true
		ttl.BrowserTTLSeconds = 0
		ttl.BrowserTTLHuman = "Heuristic (no Cache-Control or Expires)"
	}

	// Edge CDN TTL calculation:
	// Priority 1: Cloudflare-CDN-Cache-Control / CDN-Cache-Control max-age (RFC 9213)
	// Priority 2: s-maxage in Cache-Control
	// Priority 3: Surrogate-Control max-age
	// Priority 4: Browser max-age
	if edgeNoStore, ok := edgeMap["no-store"]; ok || (ttl.NoStore && len(edgeMap) == 0) {
		_ = edgeNoStore
		ttl.EdgeTTLSeconds = 0
		ttl.EdgeTTLHuman = "0s (no-store)"
	} else if edgeMaStr, ok := edgeMap["max-age"]; ok {
		if ma, err := strconv.Atoi(edgeMaStr); err == nil && ma >= 0 {
			ttl.EdgeTTLSeconds = ma
			ttl.EdgeTTLHuman = formatDuration(ma) + " (via CDN-Cache-Control)"
		}
	} else if sMaxAgeStr, ok := ccMap["s-maxage"]; ok {
		if sma, err := strconv.Atoi(sMaxAgeStr); err == nil && sma >= 0 {
			ttl.EdgeTTLSeconds = sma
			ttl.EdgeTTLHuman = formatDuration(sma) + " (via s-maxage)"
		}
	} else if surrMaStr, ok := edgeMap["max-age"]; ok {
		if ma, err := strconv.Atoi(surrMaStr); err == nil && ma >= 0 {
			ttl.EdgeTTLSeconds = ma
			ttl.EdgeTTLHuman = formatDuration(ma) + " (via Surrogate-Control)"
		}
	} else {
		ttl.EdgeTTLSeconds = ttl.BrowserTTLSeconds
		ttl.EdgeTTLHuman = ttl.BrowserTTLHuman + " (inherits Browser TTL)"
	}

	// Stale windows
	if swrStr, ok := ccMap["stale-while-revalidate"]; ok {
		if swr, err := strconv.Atoi(swrStr); err == nil {
			ttl.StaleWhileReval = swr
		}
	} else if swrStr, ok := edgeMap["stale-while-revalidate"]; ok {
		if swr, err := strconv.Atoi(swrStr); err == nil {
			ttl.StaleWhileReval = swr
		}
	}

	if sieStr, ok := ccMap["stale-if-error"]; ok {
		if sie, err := strconv.Atoi(sieStr); err == nil {
			ttl.StaleIfError = sie
		}
	} else if sieStr, ok := edgeMap["stale-if-error"]; ok {
		if sie, err := strconv.Atoi(sieStr); err == nil {
			ttl.StaleIfError = sie
		}
	}

	// Effective remaining seconds based on Age header
	if ttl.BrowserTTLSeconds > 0 && analysis.AgeSeconds > 0 {
		rem := ttl.BrowserTTLSeconds - analysis.AgeSeconds
		if rem < 0 {
			rem = 0
		}
		ttl.RemainingSeconds = rem
	} else {
		ttl.RemainingSeconds = ttl.BrowserTTLSeconds
	}

	analysis.TTL = ttl

	// Evaluate 12 Anti-Patterns & Rules
	var notes []HeaderNote

	// Rule 1: no-cache + immutable contradiction
	if ttl.NoCache && ttl.Immutable {
		notes = append(notes, HeaderNote{
			Severity: SevFail,
			Category: "cache",
			Title:    "Contradiction: no-cache combined with immutable",
			Detail:   "immutable instructs clients never to revalidate while fresh, but no-cache forces unconditional revalidation on every request. Browsers will execute revalidation.",
			RFC:      "RFC 8246 §2 & RFC 9111 §5.2.2.4",
		})
	}

	// Rule 2: no-store with max-age / s-maxage
	if ttl.NoStore && (ccMap["max-age"] != "" || ccMap["s-maxage"] != "") {
		notes = append(notes, HeaderNote{
			Severity: SevWarn,
			Category: "cache",
			Title:    "Contradictory directives: no-store with max-age",
			Detail:   "no-store strictly forbids any cache (private or shared) from storing the response. The presence of max-age or s-maxage is conflicting and ignored by conforming caches.",
			RFC:      "RFC 9111 §5.2.2.5",
		})
	}

	// Rule 3: public on authenticated or cookie response
	hasSetCookie := h.Get("Set-Cookie") != ""
	if ttl.Public && hasSetCookie {
		notes = append(notes, HeaderNote{
			Severity: SevFail,
			Category: "cache",
			Title:    "Security Risk: public cache-control with Set-Cookie",
			Detail:   "The response sets a cookie but Cache-Control is marked public. Shared proxy and CDN caches may store this response and serve sensitive user session cookies to other visitors.",
			RFC:      "RFC 9111 §5.2.2.9",
		})
	}

	// Rule 4: Missing Vary: Origin on CORS responses (CDN Cache Poisoning risk)
	hasCORS := h.Get("Access-Control-Allow-Origin") != ""
	if hasCORS {
		hasVaryOrigin := false
		for _, v := range analysis.VaryHeaders {
			if strings.EqualFold(v, "Origin") {
				hasVaryOrigin = true
				break
			}
		}
		if !hasVaryOrigin && !ttl.NoStore {
			notes = append(notes, HeaderNote{
				Severity: SevFail,
				Category: "cache",
				Title:    "Cache Poisoning Risk: CORS header without Vary: Origin",
				Detail:   "The response includes Access-Control-Allow-Origin, but lacks Vary: Origin. A CDN or intermediate cache may store the response for one origin and serve it to other origins or non-CORS callers, breaking client requests or leaking data.",
				RFC:      "RFC 9110 §12.5.5 & RFC 9111 §4.1",
			})
		}
	}

	// Rule 5: Missing Vary: Accept-Encoding on compressed responses
	contentEnc := strings.ToLower(strings.TrimSpace(h.Get("Content-Encoding")))
	if contentEnc != "" && contentEnc != "identity" {
		hasVaryAE := false
		for _, v := range analysis.VaryHeaders {
			if strings.EqualFold(v, "Accept-Encoding") {
				hasVaryAE = true
				break
			}
		}
		if !hasVaryAE && !ttl.NoStore {
			notes = append(notes, HeaderNote{
				Severity: SevWarn,
				Category: "cache",
				Title:    "Missing Vary: Accept-Encoding on compressed content",
				Detail:   fmt.Sprintf("Response is compressed with Content-Encoding: %s, but lacks Vary: Accept-Encoding. Proxies may serve compressed data to clients that do not support it.", contentEnc),
				RFC:      "RFC 9110 §12.5.5",
			})
		}
	}

	// Rule 6: must-revalidate without max-age
	if ttl.MustRevalidate && ccMap["max-age"] == "" && rawExpires == "" {
		notes = append(notes, HeaderNote{
			Severity: SevInfo,
			Category: "cache",
			Title:    "must-revalidate without freshness lifetime",
			Detail:   "must-revalidate instructs caches not to serve stale content without revalidating once the resource expires. Without a max-age or Expires lifetime, this directive has little effect.",
			RFC:      "RFC 9111 §5.2.2.2",
		})
	}

	// Rule 7: Negative caching trap (public caching on error statuses)
	if statusCode >= 400 && (ttl.Public || ttl.BrowserTTLSeconds > 0) {
		notes = append(notes, HeaderNote{
			Severity: SevWarn,
			Category: "cache",
			Title:    fmt.Sprintf("Caching HTTP error status %d", statusCode),
			Detail:   fmt.Sprintf("Response returned an HTTP %d status code with caching headers. Intermediate CDN edge caches may cache this temporary error and serve it to valid traffic.", statusCode),
			RFC:      "RFC 9111 §4.2.2",
		})
	}

	// Rule 8: Expired Expires header with modern max-age
	if rawExpires != "" && ccMap["max-age"] != "" {
		if t, err := http.ParseTime(rawExpires); err == nil && time.Now().After(t) {
			notes = append(notes, HeaderNote{
				Severity: SevInfo,
				Category: "cache",
				Title:    "Past Expires header superseded by max-age",
				Detail:   "Expires header is in the past, but Cache-Control: max-age takes precedence in all HTTP/1.1+ conforming caches.",
				RFC:      "RFC 9111 §5.3",
			})
		}
	}

	// Rule 9: Weak ETag on mutating endpoints or conditional checks
	if analysis.IsWeakETag {
		notes = append(notes, HeaderNote{
			Severity: SevInfo,
			Category: "cache",
			Title:    "Weak ETag (W/\"...\") detected",
			Detail:   "Weak validators indicate semantic equivalence rather than exact byte-for-byte identity. Weak ETags cannot be used for byte-range requests (RFC 9110 §8.8.1).",
			RFC:      "RFC 9110 §8.8.1",
		})
	}

	// Rule 10: Private browser cache combined with public CDN-Cache-Control
	if ttl.Private && (len(cdnDirs) > 0 || ccMap["s-maxage"] != "") {
		notes = append(notes, HeaderNote{
			Severity: SevOK,
			Category: "cache",
			Title:    "Dual TTL: Private browser cache with Edge CDN caching",
			Detail:   "Using RFC 9213 CDN-Cache-Control or s-maxage allows the CDN edge to cache public pages while browsers treat responses as private or revalidation-required.",
			RFC:      "RFC 9213 §2",
		})
	}

	// Rule 11: Heuristic caching vulnerability
	if ttl.Heuristic {
		notes = append(notes, HeaderNote{
			Severity: SevWarn,
			Category: "cache",
			Title:    "Heuristic caching active (no explicit cache lifetime)",
			Detail:   "Neither Cache-Control nor Expires was provided. RFC 9111 permits caches to calculate heuristic freshness (often ~10% of time since Last-Modified), causing inconsistent behavior across browsers.",
			RFC:      "RFC 9111 §4.2.2",
		})
	}

	// Rule 12: Legacy Pragma: no-cache without Cache-Control
	if strings.Contains(strings.ToLower(rawPragma), "no-cache") && rawCC == "" {
		notes = append(notes, HeaderNote{
			Severity: SevWarn,
			Category: "cache",
			Title:    "Legacy HTTP/1.0 Pragma: no-cache without Cache-Control",
			Detail:   "Pragma: no-cache is defined for requests only in HTTP/1.0. Modern response caching should use Cache-Control: no-cache or no-store.",
			RFC:      "RFC 9111 §5.4",
		})
	}

	analysis.Findings = notes
	return analysis
}
