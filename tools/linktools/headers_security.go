package linktools

import (
	"cmp"
	"fmt"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// SecurityAnalysis represents modern browser security posture, cross-origin isolation, and cookie safety.
// Page is false when Content-Type names something a browser never renders as a page, such as JSON:
// CSP, framing, Referrer-Policy and isolation then don't apply and aren't audited.
type SecurityAnalysis struct {
	Page           bool                 `json:"page"`
	Isolation      CrossOriginIsolation `json:"isolation"`
	CSP            CSPReport            `json:"csp"`
	Permissions    PermissionsReport    `json:"permissions"`
	Cookies        []CookieReport       `json:"cookies,omitempty"`
	HSTS           HSTSReport           `json:"hsts"`
	XFrameOptions  string               `json:"x_frame_options,omitempty"`
	XContentType   string               `json:"x_content_type_options,omitempty"`
	ReferrerPolicy string               `json:"referrer_policy,omitempty"`
	Findings       []HeaderNote         `json:"findings"`
}

// CrossOriginIsolation models COOP, COEP, CORP needed for SharedArrayBuffer and Wasm multi-threading.
type CrossOriginIsolation struct {
	Isolated bool   `json:"isolated"`
	COOP     string `json:"coop,omitempty"` // Cross-Origin-Opener-Policy
	COEP     string `json:"coep,omitempty"` // Cross-Origin-Embedder-Policy
	CORP     string `json:"corp,omitempty"` // Cross-Origin-Resource-Policy
	Status   string `json:"status"`         // "Cross-Origin Isolated", "Not Cross-Origin Isolated", "Not applicable"
	Detail   string `json:"detail"`
}

// CSPReport summarizes Content-Security-Policy directives and weaknesses.
type CSPReport struct {
	Present       bool     `json:"present"`
	StrictDynamic bool     `json:"strict_dynamic"`
	HasUnsafeEval bool     `json:"has_unsafe_eval"`
	HasUnsafeInl  bool     `json:"has_unsafe_inline"`
	ObjectSrcNone bool     `json:"object_src_none"`
	BaseUriNone   bool     `json:"base_uri_none"`
	Directives    []string `json:"directives,omitempty"`
}

// PermissionsReport models RFC 8941 Structured Header permissions.
type PermissionsReport struct {
	Present       bool               `json:"present"`
	LegacyFeature bool               `json:"legacy_feature_policy"`
	Policies      []PermissionPolicy `json:"policies,omitempty"`
}

// PermissionPolicy is one directive in Permissions-Policy.
type PermissionPolicy struct {
	Feature string `json:"feature"`
	Allow   string `json:"allow"` // an allowNames label, else the allowlist as sent
}

// CookieReport audits an individual Set-Cookie header against RFC 6265bis.
type CookieReport struct {
	Name        string `json:"name"`
	ValueRedact string `json:"value_redacted"`
	Secure      bool   `json:"secure"`
	HttpOnly    bool   `json:"http_only"`
	SameSite    string `json:"same_site,omitempty"` // Strict, Lax, None
	Partitioned bool   `json:"partitioned"`         // CHIPS
	Domain      string `json:"domain,omitempty"`
	Path        string `json:"path,omitempty"`
	MaxAge      int    `json:"max_age,omitempty"`
	PrefixValid bool   `json:"prefix_valid"`
	PrefixError string `json:"prefix_error,omitempty"`
}

// HSTSReport models Strict-Transport-Security.
type HSTSReport struct {
	Present           bool `json:"present"`
	MaxAgeSeconds     int  `json:"max_age_seconds"`
	IncludeSubDomains bool `json:"include_sub_domains"`
	Preload           bool `json:"preload"`
}

// AnalyzeSecurity evaluates browser isolation, security headers, and cookie attributes.
func AnalyzeSecurity(h http.Header) SecurityAnalysis {
	rawCSP := h.Get("Content-Security-Policy")
	sec := SecurityAnalysis{
		Page:           isPage(h.Get("Content-Type")),
		CSP:            parseCSP(rawCSP),
		HSTS:           parseHSTS(h.Get("Strict-Transport-Security")),
		XFrameOptions:  strings.ToUpper(strings.TrimSpace(h.Get("X-Frame-Options"))),
		XContentType:   lowerHeader(h, "X-Content-Type-Options"),
		ReferrerPolicy: lowerHeader(h, "Referrer-Policy"),
	}
	sec.Isolation = isolation(h, sec.Page)

	var n []HeaderNote

	rawPerm := h.Get("Permissions-Policy")
	sec.Permissions = PermissionsReport{Present: rawPerm != "", LegacyFeature: rawPerm == "" && h.Get("Feature-Policy") != ""}
	if sec.Permissions.LegacyFeature {
		n = append(n, HeaderNote{SevWarn, "security", "Deprecated Feature-Policy header used",
			"Feature-Policy was deprecated and superseded by Permissions-Policy using RFC 8941 Structured Field syntax.",
			"W3C Permissions Policy"})
	}
	for part := range strings.SplitSeq(rawPerm, ",") {
		feat, allow, ok := strings.Cut(part, "=")
		if feat = strings.TrimSpace(feat); !ok || feat == "" {
			continue
		}
		allow = strings.TrimSpace(allow)
		if allow == "*" {
			n = append(n, HeaderNote{SevWarn, "security", fmt.Sprintf("Permissions-Policy allows %q for all origins (*)", feat),
				fmt.Sprintf("Granting unrestricted access to %q allows embedded third-party iframes to access this capability without restriction.", feat),
				"RFC 8941"})
		}
		sec.Permissions.Policies = append(sec.Permissions.Policies, PermissionPolicy{feat, cmp.Or(allowNames[allow], allow)})
	}

	for _, raw := range h.Values("Set-Cookie") {
		c := parseCookieAudit(raw)
		sec.Cookies = append(sec.Cookies, c)
		if c.SameSite == "None" && !c.Secure {
			n = append(n, HeaderNote{SevFail, "cookie", fmt.Sprintf("Cookie %q: SameSite=None without Secure", c.Name),
				"Modern browsers unconditionally reject cookies with SameSite=None unless the Secure attribute is also specified.",
				"RFC 6265bis §5.4.7"})
		}
		if c.PrefixError != "" {
			n = append(n, HeaderNote{SevFail, "cookie", fmt.Sprintf("Cookie prefix violation on %q", c.Name), c.PrefixError, "RFC 6265bis §4.1.3"})
		}
		if isAuthCookieName(c.Name) && !c.HttpOnly {
			n = append(n, HeaderNote{SevWarn, "cookie", fmt.Sprintf("Sensitive cookie %q missing HttpOnly", c.Name),
				"Authentication/session cookies should set the HttpOnly flag to prevent exfiltration via client-side JavaScript / XSS.",
				"RFC 6265bis §4.1.2.6"})
		}
	}

	switch {
	case !sec.HSTS.Present:
		n = append(n, HeaderNote{SevWarn, "security", "Missing Strict-Transport-Security (HSTS)",
			"Strict-Transport-Security enforces HTTPS connections and prevents SSL-stripping man-in-the-middle attacks.",
			"RFC 6797 §6.1"})
	case sec.HSTS.MaxAgeSeconds < 120*24*3600:
		n = append(n, HeaderNote{SevInfo, "security", "Short HSTS duration",
			fmt.Sprintf("HSTS max-age is %ds. Recommended production duration is at least 31536000s (1 year) with includeSubDomains and preload.", sec.HSTS.MaxAgeSeconds),
			"RFC 6797 §6.1"})
	}
	if sec.XContentType != "nosniff" {
		n = append(n, HeaderNote{SevWarn, "security", "Missing X-Content-Type-Options: nosniff",
			"Without nosniff, browsers may perform MIME-type sniffing on served assets, leading to executable script confusion.",
			"Fetch Spec §3.4"})
	}

	if sec.Page {
		if sec.Isolation.Isolated {
			n = append(n, HeaderNote{SevOK, "security", "Cross-Origin Isolation Active",
				"Both COOP (same-origin) and COEP (require-corp/credentialless) are active. This isolates the browsing context and unlocks SharedArrayBuffer and WebAssembly threads.",
				"HTML Living Standard §7.1.3"})
		}
		if sec.CSP.HasUnsafeInl && !sec.CSP.StrictDynamic {
			n = append(n, HeaderNote{SevWarn, "security", "CSP: 'unsafe-inline' without 'strict-dynamic'",
				"Allowing inline scripts without strict-dynamic, nonces, or hashes bypasses core XSS protections in Content-Security-Policy.",
				"W3C CSP Level 3"})
		}
		if sec.CSP.HasUnsafeEval {
			n = append(n, HeaderNote{SevWarn, "security", "CSP: 'unsafe-eval' detected",
				"'unsafe-eval' allows execution of strings via eval(), setTimeout(), and Function constructor, increasing XSS vulnerability surfaces.",
				"W3C CSP Level 3"})
		}
		if sec.CSP.Present && !sec.CSP.ObjectSrcNone {
			n = append(n, HeaderNote{SevInfo, "security", "CSP: object-src 'none' recommended",
				"Legacy plugins (Flash, Java, Silverlight) should be disabled by setting object-src 'none'.",
				"W3C CSP Level 3"})
		}
		if !sec.CSP.Present {
			n = append(n, HeaderNote{SevWarn, "security", "Missing Content-Security-Policy",
				"No Content-Security-Policy header detected. CSP provides essential defense-in-depth against Cross-Site Scripting (XSS) and data injection attacks.",
				"W3C CSP Level 3"})
		}
		if sec.XFrameOptions == "" && !strings.Contains(strings.ToLower(rawCSP), "frame-ancestors") {
			n = append(n, HeaderNote{SevWarn, "security", "Missing Clickjacking protection (X-Frame-Options / frame-ancestors)",
				"Neither X-Frame-Options nor CSP frame-ancestors is present. The page can be embedded in malicious iframes.",
				"RFC 7034"})
		}
		if rp := sec.ReferrerPolicy; rp == "unsafe-url" || rp == "no-referrer-when-downgrade" {
			n = append(n, HeaderNote{SevInfo, "security", "Permissive Referrer-Policy",
				rp + " sends the full URL, path and query included, to other sites. Without the header, browsers use strict-origin-when-cross-origin, which sends them only the origin.",
				"W3C Referrer Policy"})
		}
	}
	sec.Findings = n
	return sec
}

var allowNames = map[string]string{"()": "Disabled ()", "*": "Wildcard (*) - High Risk", "self": "Same-Origin (self)"}

func lowerHeader(h http.Header, name string) string {
	return strings.ToLower(strings.TrimSpace(h.Get(name)))
}

// isPage: an unknown or missing type may be a page, so it gets the page checks.
func isPage(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	return err != nil || mt == "text/html" || strings.HasSuffix(mt, "/xml") || strings.HasSuffix(mt, "+xml")
}

func isolation(h http.Header, page bool) CrossOriginIsolation {
	iso := CrossOriginIsolation{
		COOP:   lowerHeader(h, "Cross-Origin-Opener-Policy"),
		COEP:   lowerHeader(h, "Cross-Origin-Embedder-Policy"),
		CORP:   lowerHeader(h, "Cross-Origin-Resource-Policy"),
		Status: "Not Cross-Origin Isolated",
	}
	coopOK := strings.HasPrefix(iso.COOP, "same-origin")
	coepOK := strings.HasPrefix(iso.COEP, "require-corp") || strings.HasPrefix(iso.COEP, "credentialless")
	switch {
	case !page:
		iso.Status, iso.Detail = "Not applicable", "COOP and COEP isolate pages, and Content-Type says this response is not one."
	case coopOK && coepOK:
		iso.Isolated, iso.Status = true, "Cross-Origin Isolated"
		iso.Detail = "Site has enabled Cross-Origin Isolation. SharedArrayBuffer and high-precision performance timers are available in modern browsers."
	case iso.COOP == "" && iso.COEP == "":
		iso.Detail = "Missing COOP and COEP headers. Browsers cannot isolate this process from other origins."
	case !coopOK:
		iso.Detail = "Cross-Origin-Opener-Policy must be set to 'same-origin' to isolate the window object."
	default:
		iso.Detail = "Cross-Origin-Embedder-Policy must be set to 'require-corp' or 'credentialless' to prevent cross-origin leaks."
	}
	return iso
}

func parseCSP(raw string) CSPReport {
	lower := strings.ToLower(raw)
	r := CSPReport{
		Present:       raw != "",
		StrictDynamic: strings.Contains(lower, "'strict-dynamic'"),
		HasUnsafeEval: strings.Contains(lower, "'unsafe-eval'"),
		HasUnsafeInl:  strings.Contains(lower, "'unsafe-inline'"),
	}
	for d := range strings.SplitSeq(raw, ";") {
		if d = strings.TrimSpace(d); d == "" {
			continue
		}
		r.Directives = append(r.Directives, d)
		d = strings.ToLower(d)
		r.ObjectSrcNone = r.ObjectSrcNone || strings.HasPrefix(d, "object-src") && strings.Contains(d, "'none'")
		r.BaseUriNone = r.BaseUriNone || strings.HasPrefix(d, "base-uri") && (strings.Contains(d, "'none'") || strings.Contains(d, "'self'"))
	}
	return r
}

func parseHSTS(raw string) HSTSReport {
	r := HSTSReport{Present: raw != ""}
	for part := range strings.SplitSeq(raw, ";") {
		name, val, _ := strings.Cut(part, "=")
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "max-age":
			if sec, err := strconv.Atoi(strings.Trim(strings.TrimSpace(val), `"`)); err == nil {
				r.MaxAgeSeconds = sec
			}
		case "includesubdomains":
			r.IncludeSubDomains = true
		case "preload":
			r.Preload = true
		}
	}
	return r
}

var sameSiteNames = map[string]string{"strict": "Strict", "lax": "Lax", "none": "None"}

// parseCookieAudit reads one Set-Cookie line; the value is never kept.
func parseCookieAudit(raw string) CookieReport {
	first, attrs, _ := strings.Cut(raw, ";")
	name, _, hasValue := strings.Cut(first, "=")
	c := CookieReport{Name: strings.TrimSpace(name)}
	if hasValue {
		c.ValueRedact = "••• [hidden] •••"
	}
	for attr := range strings.SplitSeq(attrs, ";") {
		key, val, _ := strings.Cut(attr, "=")
		val = strings.TrimSpace(val)
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "secure":
			c.Secure = true
		case "httponly":
			c.HttpOnly = true
		case "partitioned":
			c.Partitioned = true
		case "samesite":
			c.SameSite = cmp.Or(sameSiteNames[strings.ToLower(val)], val)
		case "domain":
			c.Domain = val
		case "path":
			c.Path = val
		case "max-age":
			if sec, err := strconv.Atoi(val); err == nil {
				c.MaxAge = sec
			}
		}
	}

	// RFC 6265bis §4.1.3 cookie prefixes.
	host := strings.HasPrefix(c.Name, "__Host-")
	switch {
	case host && !c.Secure:
		c.PrefixError = "__Host- prefix requires the Secure attribute."
	case strings.HasPrefix(c.Name, "__Secure-") && !c.Secure:
		c.PrefixError = "__Secure- prefix requires the Secure attribute."
	case host && c.Domain != "":
		c.PrefixError = "__Host- cookies must not specify a Domain attribute (must be host-only)."
	case host && c.Path != "/":
		c.PrefixError = "__Host- cookies must specify Path=/."
	}
	c.PrefixValid = c.PrefixError == ""
	return c
}

var authCookieTerms = []string{"sess", "auth", "token", "jwt", "sid", "csrf", "xsrf", "login", "userid"}

func isAuthCookieName(name string) bool {
	n := strings.ToLower(name)
	return slices.ContainsFunc(authCookieTerms, func(t string) bool { return strings.Contains(n, t) }) ||
		n == "id" || strings.HasSuffix(n, "_id") || strings.HasSuffix(n, "-id") || strings.HasPrefix(n, "id_")
}
