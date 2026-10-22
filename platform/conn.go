package platform

import (
	"strings"

	"github.com/labstack/echo/v5"
)

// ConnInfo is the "your request" inspector's data; Cookie and Authorization are never read, on purpose.
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

// ConnNetwork is the lookup-derived half as plain strings, so platform never imports iptools.
type ConnNetwork struct {
	ASN       string // IP2Location ASN number ("12345"); blank when unresolved
	ASName    string // IP2Location AS name / ISP; blank when unresolved
	ProxyType string // IP2Proxy proxy-type code: VPN/TOR/PUB/WEB/DCH/SES/RES/CPN/EPN/AIC
	Provider  string // IP2Proxy provider name (e.g. "NordVPN"); often blank
}

// WithNetwork adds the IP lookup's attribution; empty fields render no row, so a miss changes nothing.
func (ci ConnInfo) WithNetwork(n ConnNetwork) ConnInfo {
	ci.ASN = n.ASN
	ci.ASName = n.ASName
	ci.ProxyKind = ProxyKindLabel(n.ProxyType)
	ci.ProxyProvider = n.Provider
	return ci
}

// ProxyKindLabel returns an unknown code verbatim, so a newer PX build's type still shows something.
func ProxyKindLabel(code string) string {
	if label, ok := proxyKindLabels[code]; ok {
		return label
	}
	return code
}

// proxyKindLabels covers every type the bundled PX12 BIN returns (per ip2proxy-go v4's type table).
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

// Conn builds the inspector's data from the current request for every tool's page.
func Conn(c *echo.Context) ConnInfo {
	r := c.Request()

	via := "direct"
	switch {
	case r.Header.Get("CF-Connecting-IP") != "":
		via = "Cloudflare"
	case r.Header.Get("X-Forwarded-For") != "":
		via = "X-Forwarded-For"
	}

	// TLS terminates upstream, so X-Forwarded-Proto is the browser-facing scheme; dev uses the local conn.
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
