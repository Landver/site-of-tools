package linktools

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// TTLSummary holds the browser and CDN edge freshness lifetimes; each Source names the header that set it.
type TTLSummary struct {
	BrowserTTLSeconds int    `json:"browser_ttl_seconds"`
	BrowserTTLHuman   string `json:"browser_ttl_human"`
	BrowserSource     string `json:"browser_source"`
	EdgeTTLSeconds    int    `json:"edge_ttl_seconds"`
	EdgeTTLHuman      string `json:"edge_ttl_human"`
	EdgeSource        string `json:"edge_source"`
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

// parseDirectives splits "public, max-age=3600"; the map keeps each name's first value (RFC 9111 §4.2.1).
func parseDirectives(source, raw string) ([]Directive, map[string]string) {
	var list []Directive
	byName := map[string]string{}
	for part := range strings.SplitSeq(raw, ",") {
		name, val, _ := strings.Cut(part, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		val = strings.Trim(strings.TrimSpace(val), `"`)
		list = append(list, Directive{Source: source, Name: name, Value: val})
		if _, seen := byName[name]; !seen {
			byName[name] = val
		}
	}
	return list, byName
}

func formatDuration(sec int) string {
	pair := func(n int, unit string, rest int, restUnit string) string {
		if rest == 0 {
			return fmt.Sprintf("%d%s", n, unit)
		}
		return fmt.Sprintf("%d%s %d%s", n, unit, rest, restUnit)
	}
	switch {
	case sec <= 0:
		return "0s (no caching)"
	case sec < 60:
		return fmt.Sprintf("%ds", sec)
	case sec < 3600:
		return pair(sec/60, "m", sec%60, "s")
	case sec < 86400:
		return pair(sec/3600, "h", sec%3600/60, "m")
	default:
		return pair(sec/86400, "d", sec%86400/3600, "h")
	}
}

// lifetime reads a delta-seconds directive; one that doesn't parse leaves the response stale.
func lifetime(v string) (int, string) {
	if sec, err := strconv.Atoi(v); err == nil && sec >= 0 {
		return sec, formatDuration(sec)
	}
	return 0, "0s (invalid value: stale)"
}

// heuristicStatus: the codes RFC 9110 §15.1 makes cacheable without explicit freshness.
func heuristicStatus(code int) bool {
	return slices.Contains([]int{200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501}, code)
}

// AnalyzeCache inspects headers for RFC 9111 HTTP caching and RFC 9213 CDN-Cache-Control.
func AnalyzeCache(statusCode int, h http.Header) CacheAnalysis {
	ccList, cc := parseDirectives("Cache-Control", h.Get("Cache-Control"))
	cdnList, cdn := parseDirectives("CDN-Cache-Control", h.Get("CDN-Cache-Control"))
	cfList, edge := parseDirectives("Cloudflare-CDN-Cache-Control", h.Get("Cloudflare-CDN-Cache-Control"))
	maps.Copy(edge, cdn) // where both set a directive, CDN-Cache-Control's wins
	surrList, surrogate := parseDirectives("Surrogate-Control", h.Get("Surrogate-Control"))
	expires := h.Get("Expires")

	a := CacheAnalysis{
		Directives:   slices.Concat(ccList, cdnList, cfList, surrList),
		ETag:         strings.TrimSpace(h.Get("ETag")),
		LastModified: h.Get("Last-Modified"),
	}
	a.IsWeakETag = strings.HasPrefix(strings.ToUpper(a.ETag), "W/")
	if age, err := strconv.Atoi(strings.TrimSpace(h.Get("Age"))); err == nil && age > 0 {
		a.AgeSeconds = age
	}
	for v := range strings.SplitSeq(h.Get("Vary"), ",") {
		if v = strings.TrimSpace(v); v != "" {
			a.VaryHeaders = append(a.VaryHeaders, v)
		}
	}
	varies := func(name string) bool {
		return slices.ContainsFunc(a.VaryHeaders, func(v string) bool { return strings.EqualFold(v, name) })
	}
	has := func(m map[string]string, name string) bool { _, ok := m[name]; return ok }

	ttl := TTLSummary{
		NoStore: has(cc, "no-store"), NoCache: has(cc, "no-cache"), MustRevalidate: has(cc, "must-revalidate"),
		Immutable: has(cc, "immutable"), Public: has(cc, "public"), Private: has(cc, "private"),
	}
	_, lmErr := http.ParseTime(a.LastModified)
	switch {
	case ttl.NoStore:
		ttl.BrowserTTLHuman, ttl.BrowserSource = "0s (no-store: not cached)", "Cache-Control: no-store"
	case ttl.NoCache:
		ttl.BrowserTTLHuman, ttl.BrowserSource = "0s (no-cache: must revalidate before use)", "Cache-Control: no-cache"
	case has(cc, "max-age"):
		ttl.BrowserTTLSeconds, ttl.BrowserTTLHuman = lifetime(cc["max-age"])
		ttl.BrowserSource = "Cache-Control: max-age"
	case expires != "":
		ttl.BrowserSource = "Expires"
		// RFC 9111 §5.3: an Expires that doesn't parse is already past.
		if t, err := http.ParseTime(expires); err == nil && time.Until(t) > 0 {
			diff := int(time.Until(t).Seconds())
			ttl.BrowserTTLSeconds, ttl.BrowserTTLHuman = diff, formatDuration(diff)
		} else {
			ttl.BrowserTTLHuman = "0s (expired)"
		}
	// RFC 9111 §4.2.2: browsers guess from Last-Modified only for a status cacheable by default, or public.
	case lmErr == nil && (statusCode == 0 || heuristicStatus(statusCode) || ttl.Public):
		ttl.Heuristic = true
		ttl.BrowserTTLHuman, ttl.BrowserSource = "Heuristic", "Last-Modified"
	default:
		ttl.BrowserTTLHuman, ttl.BrowserSource = "0s (no lifetime given)", "none"
	}

	// RFC 9213: CDN-Cache-Control beats Cache-Control at the edge, then s-maxage, then Surrogate-Control.
	ccOnly := len(edge) == 0 && len(surrogate) == 0
	switch {
	case has(edge, "no-store"):
		ttl.EdgeTTLHuman, ttl.EdgeSource = "0s (no-store)", "CDN-Cache-Control: no-store"
	case ttl.NoStore && ccOnly:
		ttl.EdgeTTLHuman, ttl.EdgeSource = "0s (no-store)", "Cache-Control: no-store"
	case has(edge, "max-age"):
		ttl.EdgeTTLSeconds, ttl.EdgeTTLHuman = lifetime(edge["max-age"])
		ttl.EdgeSource = "CDN-Cache-Control: max-age"
	case ttl.Private && ccOnly:
		ttl.EdgeTTLHuman, ttl.EdgeSource = "0s (private: CDNs must not store it)", "Cache-Control: private"
	case has(cc, "s-maxage"):
		ttl.EdgeTTLSeconds, ttl.EdgeTTLHuman = lifetime(cc["s-maxage"])
		ttl.EdgeSource = "Cache-Control: s-maxage"
	case has(surrogate, "max-age"):
		ttl.EdgeTTLSeconds, ttl.EdgeTTLHuman = lifetime(surrogate["max-age"])
		ttl.EdgeSource = "Surrogate-Control: max-age"
	default:
		ttl.EdgeTTLSeconds, ttl.EdgeTTLHuman = ttl.BrowserTTLSeconds, ttl.BrowserTTLHuman
		ttl.EdgeSource = "same as browser"
	}

	stale := func(name string) int {
		v, ok := cc[name]
		if !ok {
			v = edge[name]
		}
		sec, _ := strconv.Atoi(v)
		return sec
	}
	ttl.StaleWhileReval, ttl.StaleIfError = stale("stale-while-revalidate"), stale("stale-if-error")
	ttl.RemainingSeconds = max(ttl.BrowserTTLSeconds-a.AgeSeconds, 0)
	a.TTL = ttl

	var n []HeaderNote
	if ttl.NoCache && ttl.Immutable {
		n = append(n, HeaderNote{SevFail, "cache", "Contradiction: no-cache combined with immutable",
			"immutable instructs clients never to revalidate while fresh, but no-cache forces unconditional revalidation on every request. Browsers will execute revalidation.",
			"RFC 8246 §2 & RFC 9111 §5.2.2.4"})
	}
	if ttl.NoStore && (has(cc, "max-age") || has(cc, "s-maxage")) {
		n = append(n, HeaderNote{SevWarn, "cache", "Contradictory directives: no-store with max-age",
			"no-store strictly forbids any cache (private or shared) from storing the response. The presence of max-age or s-maxage is conflicting and ignored by conforming caches.",
			"RFC 9111 §5.2.2.5"})
	}
	if ttl.Public && h.Get("Set-Cookie") != "" {
		n = append(n, HeaderNote{SevFail, "cache", "Security Risk: public cache-control with Set-Cookie",
			"The response sets a cookie but Cache-Control is marked public. Shared proxy and CDN caches may store this response and serve sensitive user session cookies to other visitors.",
			"RFC 9111 §5.2.2.9"})
	}
	if h.Get("Access-Control-Allow-Origin") != "" && !varies("Origin") && !ttl.NoStore {
		n = append(n, HeaderNote{SevFail, "cache", "Cache Poisoning Risk: CORS header without Vary: Origin",
			"The response includes Access-Control-Allow-Origin, but lacks Vary: Origin. A CDN or intermediate cache may store the response for one origin and serve it to other origins or non-CORS callers, breaking client requests or leaking data.",
			"RFC 9110 §12.5.5 & RFC 9111 §4.1"})
	}
	if enc := strings.ToLower(strings.TrimSpace(h.Get("Content-Encoding"))); enc != "" && enc != "identity" && !varies("Accept-Encoding") && !ttl.NoStore {
		n = append(n, HeaderNote{SevWarn, "cache", "Missing Vary: Accept-Encoding on compressed content",
			fmt.Sprintf("Response is compressed with Content-Encoding: %s, but lacks Vary: Accept-Encoding. Proxies may serve compressed data to clients that do not support it.", enc),
			"RFC 9110 §12.5.5"})
	}
	if ttl.MustRevalidate && !has(cc, "max-age") && expires == "" {
		n = append(n, HeaderNote{SevInfo, "cache", "must-revalidate without freshness lifetime",
			"must-revalidate instructs caches not to serve stale content without revalidating once the resource expires. Without a max-age or Expires lifetime, this directive has little effect.",
			"RFC 9111 §5.2.2.2"})
	}
	if statusCode >= 400 && (ttl.Public || ttl.BrowserTTLSeconds > 0) {
		n = append(n, HeaderNote{SevWarn, "cache", fmt.Sprintf("Caching HTTP error status %d", statusCode),
			fmt.Sprintf("Response returned an HTTP %d status code with caching headers. Intermediate CDN edge caches may cache this temporary error and serve it to valid traffic.", statusCode),
			"RFC 9111 §4.2.2"})
	}
	if t, err := http.ParseTime(expires); err == nil && has(cc, "max-age") && time.Now().After(t) {
		n = append(n, HeaderNote{SevInfo, "cache", "Past Expires header superseded by max-age",
			"Expires header is in the past, but Cache-Control: max-age takes precedence in all HTTP/1.1+ conforming caches.",
			"RFC 9111 §5.3"})
	}
	if a.IsWeakETag {
		n = append(n, HeaderNote{SevInfo, "cache", `Weak ETag (W/"...") detected`,
			"Weak validators indicate semantic equivalence rather than exact byte-for-byte identity. Weak ETags cannot be used for byte-range requests (RFC 9110 §8.8.1).",
			"RFC 9110 §8.8.1"})
	}
	switch {
	case ttl.Private && len(edge) > 0:
		n = append(n, HeaderNote{SevOK, "cache", "Dual TTL: Private browser cache with Edge CDN caching",
			"RFC 9213 CDN-Cache-Control lets the CDN edge cache the response while browsers treat it as private.",
			"RFC 9213 §2"})
	case ttl.Private && has(cc, "s-maxage"):
		n = append(n, HeaderNote{SevWarn, "cache", "Contradictory directives: private with s-maxage",
			"private forbids every shared cache from storing the response, so s-maxage never applies. CDN-Cache-Control gives the edge its own lifetime.",
			"RFC 9111 §5.2.2.7"})
	}
	if ttl.Heuristic {
		n = append(n, HeaderNote{SevWarn, "cache", "Heuristic caching active (no explicit cache lifetime)",
			"Neither Cache-Control nor Expires sets a lifetime, so caches guess one from Last-Modified, typically 10% of the time since it. Browsers and CDNs may each guess differently.",
			"RFC 9111 §4.2.2"})
	}
	if strings.Contains(strings.ToLower(h.Get("Pragma")), "no-cache") && h.Get("Cache-Control") == "" {
		n = append(n, HeaderNote{SevWarn, "cache", "Legacy HTTP/1.0 Pragma: no-cache without Cache-Control",
			"Pragma: no-cache is defined for requests only in HTTP/1.0. Modern response caching should use Cache-Control: no-cache or no-store.",
			"RFC 9111 §5.4"})
	}
	a.Findings = n
	return a
}
