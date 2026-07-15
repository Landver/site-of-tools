// Package platform holds the shared engine: the app factory, the template
// renderer + content negotiation, and the embedded/disk asset toggle. It knows
// nothing about individual tools.
package platform

import (
	"io/fs"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

// NewApp builds a fresh *echo.Echo with the shared setup every subdomain uses:
// renderer, middleware, Cloudflare-aware IP extraction, and static serving.
func NewApp(r *Renderer, staticFS fs.FS, dev bool) *echo.Echo {
	e := echo.New()
	e.Renderer = r
	// Feeds c.RealIP(), so RequestLogger records the real client IP, not nginx's.
	e.IPExtractor = cfIPExtractor()

	e.Use(middleware.Recover())
	e.Use(middleware.RequestLogger())
	e.Use(middleware.Gzip())

	if dev {
		// Don't cache static assets in dev, so CSS/JS edits show on refresh
		// (no stale-stylesheet surprises).
		e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(c *echo.Context) error {
				if strings.HasPrefix(c.Request().URL.Path, "/static/") {
					c.Response().Header().Set("Cache-Control", "no-store")
				}
				return next(c)
			}
		})
	}

	e.StaticFS("/static", staticFS)
	return e
}

// SubFS returns a filesystem rooted at sub: live disk (devDir) in dev, else the
// embedded tree with the sub prefix stripped.
func SubFS(embedded fs.FS, sub, devDir string, dev bool) fs.FS {
	if dev {
		return os.DirFS(devDir)
	}
	s, err := fs.Sub(embedded, sub)
	if err != nil {
		panic(err)
	}
	return s
}

// cfIPExtractor prefers Cloudflare's CF-Connecting-IP, then a trusted
// X-Forwarded-For chain, then the socket address. Only nginx (loopback/private)
// is trusted to set these; in dev there is no proxy, so it falls through to
// RemoteAddr.
func cfIPExtractor() echo.IPExtractor {
	xff := echo.ExtractIPFromXFFHeader(
		echo.TrustLoopback(true),
		echo.TrustPrivateNet(true),
	)
	return func(req *http.Request) string {
		if ip := req.Header.Get("CF-Connecting-IP"); ip != "" {
			return ip
		}
		if ip := xff(req); ip != "" {
			return ip
		}
		host, _, _ := net.SplitHostPort(req.RemoteAddr)
		return host
	}
}
