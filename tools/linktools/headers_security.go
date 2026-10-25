package linktools

import (
	"fmt"
	"mime"
	"net/http"
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
	Allow   string `json:"allow"` // e.g. "Disabled ()", "Self", "Wildcard (*)", "Origins"
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
	var sec SecurityAnalysis
	var notes []HeaderNote
	sec.Page = isPage(h.Get("Content-Type"))

	// 1. Cross-Origin Isolation
	coop := strings.ToLower(strings.TrimSpace(h.Get("Cross-Origin-Opener-Policy")))
	coep := strings.ToLower(strings.TrimSpace(h.Get("Cross-Origin-Embedder-Policy")))
	corp := strings.ToLower(strings.TrimSpace(h.Get("Cross-Origin-Resource-Policy")))

	sec.Isolation.COOP = coop
	sec.Isolation.COEP = coep
	sec.Isolation.CORP = corp

	isCoopOk := strings.HasPrefix(coop, "same-origin")
	isCoepOk := strings.HasPrefix(coep, "require-corp") || strings.HasPrefix(coep, "credentialless")

	if !sec.Page {
		sec.Isolation.Status = "Not applicable"
		sec.Isolation.Detail = "COOP and COEP isolate pages, and Content-Type says this response is not one."
	} else if isCoopOk && isCoepOk {
		sec.Isolation.Isolated = true
		sec.Isolation.Status = "Cross-Origin Isolated"
		sec.Isolation.Detail = "Site has enabled Cross-Origin Isolation. SharedArrayBuffer and high-precision performance timers are available in modern browsers."
		notes = append(notes, HeaderNote{
			Severity: SevOK,
			Category: "security",
			Title:    "Cross-Origin Isolation Active",
			Detail:   "Both COOP (same-origin) and COEP (require-corp/credentialless) are active. This isolates the browsing context and unlocks SharedArrayBuffer and WebAssembly threads.",
			RFC:      "HTML Living Standard §7.1.3",
		})
	} else {
		sec.Isolation.Isolated = false
		sec.Isolation.Status = "Not Cross-Origin Isolated"
		if coop == "" && coep == "" {
			sec.Isolation.Detail = "Missing COOP and COEP headers. Browsers cannot isolate this process from other origins."
		} else if !isCoopOk {
			sec.Isolation.Detail = "Cross-Origin-Opener-Policy must be set to 'same-origin' to isolate the window object."
		} else if !isCoepOk {
			sec.Isolation.Detail = "Cross-Origin-Embedder-Policy must be set to 'require-corp' or 'credentialless' to prevent cross-origin leaks."
		}
	}

	// 2. Content-Security-Policy
	rawCSP := h.Get("Content-Security-Policy")
	if rawCSP != "" {
		sec.CSP.Present = true
		directives := strings.Split(rawCSP, ";")
		for _, d := range directives {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}
			sec.CSP.Directives = append(sec.CSP.Directives, d)
			dLower := strings.ToLower(d)
			if strings.Contains(dLower, "'strict-dynamic'") {
				sec.CSP.StrictDynamic = true
			}
			if strings.Contains(dLower, "'unsafe-eval'") {
				sec.CSP.HasUnsafeEval = true
			}
			if strings.Contains(dLower, "'unsafe-inline'") {
				sec.CSP.HasUnsafeInl = true
			}
			if strings.HasPrefix(dLower, "object-src") && strings.Contains(dLower, "'none'") {
				sec.CSP.ObjectSrcNone = true
			}
			if strings.HasPrefix(dLower, "base-uri") && (strings.Contains(dLower, "'none'") || strings.Contains(dLower, "'self'")) {
				sec.CSP.BaseUriNone = true
			}
		}

		if sec.CSP.HasUnsafeInl && !sec.CSP.StrictDynamic {
			notes = append(notes, HeaderNote{
				Severity: SevWarn,
				Category: "security",
				Title:    "CSP: 'unsafe-inline' without 'strict-dynamic'",
				Detail:   "Allowing inline scripts without strict-dynamic, nonces, or hashes bypasses core XSS protections in Content-Security-Policy.",
				RFC:      "W3C CSP Level 3",
			})
		}
		if sec.CSP.HasUnsafeEval {
			notes = append(notes, HeaderNote{
				Severity: SevWarn,
				Category: "security",
				Title:    "CSP: 'unsafe-eval' detected",
				Detail:   "'unsafe-eval' allows execution of strings via eval(), setTimeout(), and Function constructor, increasing XSS vulnerability surfaces.",
				RFC:      "W3C CSP Level 3",
			})
		}
		if !sec.CSP.ObjectSrcNone {
			notes = append(notes, HeaderNote{
				Severity: SevInfo,
				Category: "security",
				Title:    "CSP: object-src 'none' recommended",
				Detail:   "Legacy plugins (Flash, Java, Silverlight) should be disabled by setting object-src 'none'.",
				RFC:      "W3C CSP Level 3",
			})
		}
	} else if sec.Page {
		notes = append(notes, HeaderNote{
			Severity: SevWarn,
			Category: "security",
			Title:    "Missing Content-Security-Policy",
			Detail:   "No Content-Security-Policy header detected. CSP provides essential defense-in-depth against Cross-Site Scripting (XSS) and data injection attacks.",
			RFC:      "W3C CSP Level 3",
		})
	}

	// 3. Permissions-Policy (RFC 8941)
	rawPerm := h.Get("Permissions-Policy")
	rawFeature := h.Get("Feature-Policy")
	if rawFeature != "" && rawPerm == "" {
		sec.Permissions.LegacyFeature = true
		notes = append(notes, HeaderNote{
			Severity: SevWarn,
			Category: "security",
			Title:    "Deprecated Feature-Policy header used",
			Detail:   "Feature-Policy was deprecated and superseded by Permissions-Policy using RFC 8941 Structured Field syntax.",
			RFC:      "W3C Permissions Policy",
		})
	}
	if rawPerm != "" {
		sec.Permissions.Present = true
		parts := strings.Split(rawPerm, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			idx := strings.IndexByte(p, '=')
			if idx > 0 {
				feat := strings.TrimSpace(p[:idx])
				allow := strings.TrimSpace(p[idx+1:])
				readableAllow := allow
				switch allow {
				case "()":
					readableAllow = "Disabled ()"
				case "*":
					readableAllow = "Wildcard (*) - High Risk"
					notes = append(notes, HeaderNote{
						Severity: SevWarn,
						Category: "security",
						Title:    fmt.Sprintf("Permissions-Policy allows %q for all origins (*)", feat),
						Detail:   fmt.Sprintf("Granting unrestricted access to %q allows embedded third-party iframes to access this capability without restriction.", feat),
						RFC:      "RFC 8941",
					})
				case "self":
					readableAllow = "Same-Origin (self)"
				}
				sec.Permissions.Policies = append(sec.Permissions.Policies, PermissionPolicy{
					Feature: feat,
					Allow:   readableAllow,
				})
			}
		}
	}

	// 4. Set-Cookie & RFC 6265bis audit
	setCookies := h.Values("Set-Cookie")
	for _, sc := range setCookies {
		c := parseCookieAudit(sc)
		sec.Cookies = append(sec.Cookies, c)

		if c.SameSite == "None" && !c.Secure {
			notes = append(notes, HeaderNote{
				Severity: SevFail,
				Category: "cookie",
				Title:    fmt.Sprintf("Cookie %q: SameSite=None without Secure", c.Name),
				Detail:   "Modern browsers unconditionally reject cookies with SameSite=None unless the Secure attribute is also specified.",
				RFC:      "RFC 6265bis §5.4.7",
			})
		}
		if !c.PrefixValid && c.PrefixError != "" {
			notes = append(notes, HeaderNote{
				Severity: SevFail,
				Category: "cookie",
				Title:    fmt.Sprintf("Cookie prefix violation on %q", c.Name),
				Detail:   c.PrefixError,
				RFC:      "RFC 6265bis §4.1.3",
			})
		}
		if isAuthCookieName(c.Name) && !c.HttpOnly {
			notes = append(notes, HeaderNote{
				Severity: SevWarn,
				Category: "cookie",
				Title:    fmt.Sprintf("Sensitive cookie %q missing HttpOnly", c.Name),
				Detail:   "Authentication/session cookies should set the HttpOnly flag to prevent exfiltration via client-side JavaScript / XSS.",
				RFC:      "RFC 6265bis §4.1.2.6",
			})
		}
	}

	// 5. Strict-Transport-Security (HSTS)
	rawHSTS := h.Get("Strict-Transport-Security")
	if rawHSTS != "" {
		sec.HSTS.Present = true
		for _, part := range strings.Split(rawHSTS, ";") {
			part = strings.TrimSpace(part)
			partLower := strings.ToLower(part)
			if strings.HasPrefix(partLower, "max-age=") {
				if ma, err := strconv.Atoi(part[8:]); err == nil {
					sec.HSTS.MaxAgeSeconds = ma
				}
			} else if partLower == "includesubdomains" {
				sec.HSTS.IncludeSubDomains = true
			} else if partLower == "preload" {
				sec.HSTS.Preload = true
			}
		}
		if sec.HSTS.MaxAgeSeconds < 10368000 { // less than 120 days
			notes = append(notes, HeaderNote{
				Severity: SevInfo,
				Category: "security",
				Title:    "Short HSTS duration",
				Detail:   fmt.Sprintf("HSTS max-age is %ds. Recommended production duration is at least 31536000s (1 year) with includeSubDomains and preload.", sec.HSTS.MaxAgeSeconds),
				RFC:      "RFC 6797 §6.1",
			})
		}
	} else {
		notes = append(notes, HeaderNote{
			Severity: SevWarn,
			Category: "security",
			Title:    "Missing Strict-Transport-Security (HSTS)",
			Detail:   "Strict-Transport-Security enforces HTTPS connections and prevents SSL-stripping man-in-the-middle attacks.",
			RFC:      "RFC 6797 §6.1",
		})
	}

	// 6. X-Content-Type-Options
	xcto := strings.ToLower(strings.TrimSpace(h.Get("X-Content-Type-Options")))
	sec.XContentType = xcto
	if xcto != "nosniff" {
		notes = append(notes, HeaderNote{
			Severity: SevWarn,
			Category: "security",
			Title:    "Missing X-Content-Type-Options: nosniff",
			Detail:   "Without nosniff, browsers may perform MIME-type sniffing on served assets, leading to executable script confusion.",
			RFC:      "Fetch Spec §3.4",
		})
	}

	// 7. X-Frame-Options & Framing
	xfo := strings.ToUpper(strings.TrimSpace(h.Get("X-Frame-Options")))
	sec.XFrameOptions = xfo
	if sec.Page && xfo == "" && !strings.Contains(strings.ToLower(rawCSP), "frame-ancestors") {
		notes = append(notes, HeaderNote{
			Severity: SevWarn,
			Category: "security",
			Title:    "Missing Clickjacking protection (X-Frame-Options / frame-ancestors)",
			Detail:   "Neither X-Frame-Options nor CSP frame-ancestors is present. The page can be embedded in malicious iframes.",
			RFC:      "RFC 7034",
		})
	}

	// 8. Referrer-Policy: when absent, browsers use strict-origin-when-cross-origin, which is safe.
	rp := strings.ToLower(strings.TrimSpace(h.Get("Referrer-Policy")))
	sec.ReferrerPolicy = rp
	if sec.Page && (rp == "unsafe-url" || rp == "no-referrer-when-downgrade") {
		notes = append(notes, HeaderNote{
			Severity: SevInfo,
			Category: "security",
			Title:    "Permissive Referrer-Policy",
			Detail:   fmt.Sprintf("%s sends the full URL, path and query included, to other sites. Without the header, browsers use strict-origin-when-cross-origin, which sends them only the origin.", rp),
			RFC:      "W3C Referrer Policy",
		})
	}

	sec.Findings = notes
	return sec
}

// isPage: an unknown or missing type may be a page, so it gets the page checks.
func isPage(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return true
	}
	return mt == "text/html" || strings.HasSuffix(mt, "/xml") || strings.HasSuffix(mt, "+xml")
}

// parseCookieAudit parses attributes of a single Set-Cookie string.
func parseCookieAudit(raw string) CookieReport {
	c := CookieReport{PrefixValid: true}
	parts := strings.Split(raw, ";")
	if len(parts) == 0 {
		return c
	}

	// First part is Name=Value
	first := strings.TrimSpace(parts[0])
	if eqIdx := strings.IndexByte(first, '='); eqIdx > 0 {
		c.Name = strings.TrimSpace(first[:eqIdx])
		c.ValueRedact = "••• [hidden] •••"
	} else {
		c.Name = first
	}

	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		pLower := strings.ToLower(p)
		if pLower == "secure" {
			c.Secure = true
		} else if pLower == "httponly" {
			c.HttpOnly = true
		} else if pLower == "partitioned" {
			c.Partitioned = true
		} else if strings.HasPrefix(pLower, "samesite=") {
			val := strings.TrimSpace(p[9:])
			if strings.EqualFold(val, "strict") {
				c.SameSite = "Strict"
			} else if strings.EqualFold(val, "lax") {
				c.SameSite = "Lax"
			} else if strings.EqualFold(val, "none") {
				c.SameSite = "None"
			} else {
				c.SameSite = val
			}
		} else if strings.HasPrefix(pLower, "domain=") {
			c.Domain = strings.TrimSpace(p[7:])
		} else if strings.HasPrefix(pLower, "path=") {
			c.Path = strings.TrimSpace(p[5:])
		} else if strings.HasPrefix(pLower, "max-age=") {
			if ma, err := strconv.Atoi(strings.TrimSpace(p[8:])); err == nil {
				c.MaxAge = ma
			}
		}
	}

	// RFC 6265bis Prefix validation
	if strings.HasPrefix(c.Name, "__Host-") {
		if !c.Secure {
			c.PrefixValid = false
			c.PrefixError = "__Host- prefix requires the Secure attribute."
		} else if c.Domain != "" {
			c.PrefixValid = false
			c.PrefixError = "__Host- cookies must not specify a Domain attribute (must be host-only)."
		} else if c.Path != "/" {
			c.PrefixValid = false
			c.PrefixError = "__Host- cookies must specify Path=/."
		}
	} else if strings.HasPrefix(c.Name, "__Secure-") {
		if !c.Secure {
			c.PrefixValid = false
			c.PrefixError = "__Secure- prefix requires the Secure attribute."
		}
	}

	return c
}

func isAuthCookieName(name string) bool {
	n := strings.ToLower(name)
	for _, term := range []string{"sess", "auth", "token", "jwt", "sid", "csrf", "xsrf", "login"} {
		if strings.Contains(n, term) {
			return true
		}
	}
	if n == "id" || strings.HasSuffix(n, "_id") || strings.HasSuffix(n, "-id") || strings.HasPrefix(n, "id_") || strings.Contains(n, "userid") || strings.Contains(n, "sessionid") {
		return true
	}
	return false
}
