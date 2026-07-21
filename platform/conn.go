package platform

import (
	"strings"

	"github.com/labstack/echo/v5"
)

// ConnInfo is "your request" inspector's view of current request — pure
// transport metadata, no domain lookup. TLS + visitor's HTTP version absent:
// terminate at Cloudflare/nginx, unknowable here. Cookie + Authorization
// never read, on purpose. Shared by every tool's page → inspector renders
// identical across subdomains (see partials/conn).
//
// Last four fields = G38/G44 network attribution: optional, filled via
// WithNetwork by tool that also ran IP lookup (iptools always does;
// botcheck when its service up). platform never imports tool's domain
// package → enrichment arrives as plain strings. Zero values render
// nothing → tools that never call WithNetwork, or whose lookup lacks
// data, render same six transport rows as always.
type ConnInfo struct {
	IP       string // resolved client IP (c.RealIP())
	Via      string // how the IP was derived: Cloudflare / X-Forwarded-For / direct
	Scheme   string // http or https (from X-Forwarded-Proto, else the local conn)
	Host     string // Host header the visitor hit
	Browser  string // User-Agent
	Language string // first Accept-Language token

	ASN           string // egress ASN number (IP2Location), e.g. "12345"
	ASName        string // organisation owning the ASN, e.g. "Example ISP"
	ProxyKind     string // human-readable proxy/VPN kind, mapped from the IP2Proxy type code
	ProxyProvider string // VPN/proxy provider name (PX12), e.g. "NordVPN"
}

// ConnNetwork carries lookup-derived half of inspector (G38/G44) as plain
// strings → platform stays decoupled from iptools (imports platform, never
// reverse). ProxyType = raw IP2Proxy type code; WithNetwork maps it to
// readable ProxyKind.
type ConnNetwork struct {
	ASN       string // IP2Location ASN number ("12345"); blank when unresolved
	ASName    string // IP2Location AS name / ISP; blank when unresolved
	ProxyType string // IP2Proxy proxy-type code: VPN/TOR/PUB/WEB/DCH/SES/RES/CPN/EPN/AIC
	Provider  string // IP2Proxy provider name (e.g. "NordVPN"); often blank
}

// WithNetwork returns inspector enriched w/ IP lookup's network attribution.
// Additive + nil-safe by construction: empty input fields leave empty output
// fields, conn partial renders row only for non-empty values → lookup that
// found no proxy data changes nothing on page.
func (ci ConnInfo) WithNetwork(n ConnNetwork) ConnInfo {
	ci.ASN = n.ASN
	ci.ASName = n.ASName
	ci.ProxyKind = ProxyKindLabel(n.ProxyType)
	ci.ProxyProvider = n.Provider
	return ci
}

// ProxyKindLabel maps IP2Proxy proxy-type code to readable name. Code
// vocabulary fixed by PX12 database project bundles (see ip2proxy-go binding
// docs); unfamiliar code surfaced verbatim rather than hidden → future PX
// build w/ new type still shows *something*. "" stays "" — no proxy data,
// no row.
func ProxyKindLabel(code string) string {
	if label, ok := proxyKindLabels[code]; ok {
		return label
	}
	return code
}

// proxyKindLabels covers every proxy type the bundled PX12 BIN can return
// (verified against ip2proxy-go v4 binding's type table). RES = residential-
// proxy classification G44 surfaces; SES/AIC = search-engine + AI-crawler
// ranges.
var proxyKindLabels = map[string]string{
	"VPN": "VPN",
	"TOR": "Tor exit node",
	"PUB": "public proxy",
	"WEB": "web proxy",
	"DCH": "datacenter / hosting",
	"SES": "search-engine robot",
	"RES": "residential proxy",
	"CPN": "consumer privacy network",
	"EPN": "enterprise private network",
	"AIC": "AI crawler",
}

// Conn builds connection inspector's data from current request. Lives in
// platform (shared transport engine) so iptools, botcheck, future tools
// share one implementation, not each keeping own copy.
func Conn(c *echo.Context) ConnInfo {
	r := c.Request()

	via := "direct"
	switch {
	case r.Header.Get("CF-Connecting-IP") != "":
		via = "Cloudflare"
	case r.Header.Get("X-Forwarded-For") != "":
		via = "X-Forwarded-For"
	}

	// Browser-facing scheme: X-Forwarded-Proto is reliable signal (TLS
	// terminates upstream); fall back to local conn in dev.
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		scheme = "http"
		if r.TLS != nil {
			scheme = "https"
		}
	}

	lang := r.Header.Get("Accept-Language")
	if i := strings.IndexAny(lang, ",;"); i >= 0 {
		lang = lang[:i]
	}

	return ConnInfo{
		IP:       c.RealIP(),
		Via:      via,
		Scheme:   scheme,
		Host:     r.Host,
		Browser:  r.UserAgent(),
		Language: strings.TrimSpace(lang),
	}
}
