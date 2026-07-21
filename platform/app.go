// Package platform: shared engine — app factory, template renderer + content
// negotiation, embedded/disk asset toggle. Knows nothing about individual
// tools.
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

// NewApp builds fresh *echo.Echo w/ shared setup every subdomain uses:
// renderer, middleware, Cloudflare-aware IP extraction, static serving. reqlog
// = shared request-log corpus (one store across all subdomains); nil disables
// persistence → middleware then just logs to slog, as before.
func NewApp(r *Renderer, staticFS fs.FS, dev bool, reqlog *RequestLog) *echo.Echo {
	e := echo.New()
	e.Renderer = r
	// Feeds c.RealIP() → RequestLogger records real client IP, not nginx's.
	e.IPExtractor = cfIPExtractor()

	e.Use(middleware.Recover())
	e.Use(requestLogger(reqlog))
	e.Use(middleware.Gzip())

	if dev {
		// Don't cache static assets in dev → CSS/JS edits show on refresh, no
		// stale-stylesheet surprises.
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

// SubFS returns filesystem rooted at sub: live disk (devDir) in dev, else
// embedded tree w/ sub prefix stripped.
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

// cfIPExtractor prefers Cloudflare's CF-Connecting-IP, then trusted
// X-Forwarded-For chain, then socket address. CF-Connecting-IP trusted
// unconditionally: ingress trust enforced at network layer (app published
// only behind nginx, which sits behind Cloudflare — see DEPLOYMENT.md §4) →
// no in-process peer check needed, direct client can't reach it to forge
// header. X-Forwarded-For chain, by contrast, peer-verified here via
// TrustLoopback/TrustPrivateNet. In dev no proxy exists → both fall through
// to RemoteAddr.
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

// requestLogger is built-in v5 RequestLogger trimmed to fields we care about:
// slog line drops user_agent + request_id, puts status before uri (slog still
// prepends time/level/msg). One attribute list serves both success + error
// cases (error appends its own field). When reqlog non-nil, also persists
// each request (minus static assets) to Mongo corpus — reuses values this
// middleware already captures rather than adding 2nd pass; corpus does keep
// user_agent even though slog line omits it.
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
		HandleError:      true, // forward errors to global handler for right status
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

			// Persist to corpus off request path (Record non-blocking + nil-safe).
			// Skip static assets — high volume, no analytic value.
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
