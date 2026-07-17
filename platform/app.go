// Package platform holds the shared engine: the app factory, the template
// renderer + content negotiation, and the embedded/disk asset toggle. It knows
// nothing about individual tools.
package platform

import (
	"context"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

// NewApp builds a fresh *echo.Echo with the shared setup every subdomain uses:
// renderer, middleware, Cloudflare-aware IP extraction, and static serving. reqlog
// is the shared request-log corpus (one store across all subdomains); pass nil to
// disable persistence — the middleware then only logs to slog, as before.
func NewApp(r *Renderer, staticFS fs.FS, dev bool, reqlog *RequestLog) *echo.Echo {
	e := echo.New()
	e.Renderer = r
	// Feeds c.RealIP(), so RequestLogger records the real client IP, not nginx's.
	e.IPExtractor = cfIPExtractor()

	e.Use(middleware.Recover())
	e.Use(requestLogger(reqlog))
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
// X-Forwarded-For chain, then the socket address. CF-Connecting-IP is trusted
// unconditionally: ingress trust is enforced at the network layer (the app is
// published only behind nginx, which sits behind Cloudflare — see DEPLOYMENT.md
// §4), so no in-process peer check is needed and a direct client can't reach it
// to forge the header. The X-Forwarded-For chain, by contrast, is peer-verified
// here via TrustLoopback/TrustPrivateNet. In dev there is no proxy, so both fall
// through to RemoteAddr.
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

// requestLogger is the built-in v5 RequestLogger trimmed to the fields we care
// about: the slog line drops user_agent and request_id and puts status before uri
// (slog still prepends time/level/msg). One attribute list serves both the success
// and error cases (error appends its own field). When reqlog is non-nil it also
// persists each request (minus static assets) to the Mongo corpus — reusing the
// values this middleware already captures rather than adding a second pass; the
// corpus does keep user_agent even though the slog line omits it.
func requestLogger(reqlog *RequestLog) echo.MiddlewareFunc {
	return middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogLatency:       true,
		LogRemoteIP:      true,
		LogHost:          true,
		LogMethod:        true,
		LogURI:           true,
		LogStatus:        true,
		LogContentLength: true,
		LogResponseSize:  true,
		HandleError:      true, // forward errors to the global handler for the right status
		LogValuesFunc: func(c *echo.Context, v middleware.RequestLoggerValues) error {
			level, msg := slog.LevelInfo, "REQUEST"
			attrs := []slog.Attr{
				slog.String("method", v.Method),
				slog.Int("status", v.Status),
				slog.String("uri", v.URI),
				slog.Duration("latency", v.Latency),
				slog.String("host", v.Host),
				slog.String("bytes_in", v.ContentLength),
				slog.Int64("bytes_out", v.ResponseSize),
				slog.String("remote_ip", v.RemoteIP),
			}
			if v.Error != nil {
				level, msg = slog.LevelError, "REQUEST_ERROR"
				attrs = append(attrs, slog.String("error", v.Error.Error()))
			}
			c.Logger().LogAttrs(context.Background(), level, msg, attrs...)

			// Persist to the corpus off the request path (Record is non-blocking and
			// nil-safe). Skip static assets — high volume, no analytic value.
			if ShouldRecord(c.Request().URL.Path) {
				reqlog.Record(RequestEntry{
					Method:    v.Method,
					Host:      v.Host,
					URI:       v.URI,
					Status:    v.Status,
					RemoteIP:  v.RemoteIP,
					UserAgent: c.Request().UserAgent(),
					LatencyMS: v.Latency.Milliseconds(),
					BytesOut:  v.ResponseSize,
					CreatedAt: time.Now(),
				})
			}
			return nil
		},
	})
}
