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
type ConnInfo struct {
	IP       string // resolved client IP (c.RealIP())
	Via      string // how the IP was derived: Cloudflare / X-Forwarded-For / direct
	Scheme   string // http or https (from X-Forwarded-Proto, else the local conn)
	Host     string // Host header the visitor hit
	Browser  string // User-Agent
	Language string // first Accept-Language token
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
