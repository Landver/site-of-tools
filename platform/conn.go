package platform

import (
	"strings"

	"github.com/labstack/echo/v5"
)

// ConnInfo is the "your request" inspector's view of the current request — pure
// transport metadata, no domain lookup. TLS and the visitor's HTTP version are
// absent: they terminate at Cloudflare/nginx and aren't knowable here. Cookie and
// Authorization are deliberately never read. Shared by every tool's page so the
// inspector renders identically across subdomains (see partials/conn).
//
// The last four fields are the G38/G44 network attribution: optional, filled via
// WithNetwork by a tool that also ran an IP lookup (iptools always does; botcheck
// when its service is up). platform never imports a tool's domain package, so
// the enrichment arrives as plain strings. Zero values render nothing, so tools
// that never call WithNetwork — or whose lookup lacks the data — render exactly
// the six transport rows they always did.
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

// ConnNetwork carries the lookup-derived half of the inspector (G38/G44) as
// plain strings, so platform stays decoupled from iptools (which imports
// platform, never the reverse). ProxyType is the raw IP2Proxy type code;
// WithNetwork maps it to the readable ProxyKind.
type ConnNetwork struct {
	ASN       string // IP2Location ASN number ("12345"); blank when unresolved
	ASName    string // IP2Location AS name / ISP; blank when unresolved
	ProxyType string // IP2Proxy proxy-type code: VPN/TOR/PUB/WEB/DCH/SES/RES/CPN/EPN/AIC
	Provider  string // IP2Proxy provider name (e.g. "NordVPN"); often blank
}

// WithNetwork returns the inspector enriched with the IP lookup's network
// attribution. Additive and nil-safe by construction: empty input fields leave
// empty output fields, and the conn partial renders a row only for non-empty
// values — a lookup that found no proxy data changes nothing on the page.
func (ci ConnInfo) WithNetwork(n ConnNetwork) ConnInfo {
	ci.ASN = n.ASN
	ci.ASName = n.ASName
	ci.ProxyKind = ProxyKindLabel(n.ProxyType)
	ci.ProxyProvider = n.Provider
	return ci
}

// ProxyKindLabel maps an IP2Proxy proxy-type code to a readable name. The code
// vocabulary is fixed by the PX12 database the project bundles (see the
// ip2proxy-go binding docs); an unfamiliar code is surfaced verbatim rather
// than hidden, so a future PX build with a new type still shows *something*.
// "" stays "" — no proxy data means no row.
func ProxyKindLabel(code string) string {
	if label, ok := proxyKindLabels[code]; ok {
		return label
	}
	return code
}

// proxyKindLabels covers every proxy type the bundled PX12 BIN can return
// (verified against the ip2proxy-go v4 binding's type table). RES is the
// residential-proxy classification G44 surfaces; SES/AIC are the search-engine
// and AI-crawler ranges.
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

// Conn builds the connection inspector's data from the current request. It lives
// in platform (the shared transport engine) so iptools, botcheck, and any future
// tool share one implementation rather than each keeping its own copy.
func Conn(c *echo.Context) ConnInfo {
	r := c.Request()

	via := "direct"
	switch {
	case r.Header.Get("CF-Connecting-IP") != "":
		via = "Cloudflare"
	case r.Header.Get("X-Forwarded-For") != "":
		via = "X-Forwarded-For"
	}

	// Browser-facing scheme: X-Forwarded-Proto is the reliable signal (TLS
	// terminates upstream); fall back to the local connection in dev.
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
