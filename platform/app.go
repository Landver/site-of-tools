// Package platform is the shared engine every subdomain builds on; it knows nothing about individual tools.
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

// NewApp builds a subdomain's *echo.Echo with the shared middleware; a nil reqlog logs to slog only.
func NewApp(r *Renderer, staticFS fs.FS, dev bool, reqlog *RequestLog) *echo.Echo {
	e := echo.New()
	e.Renderer = r
	// Feeds c.RealIP() → RequestLogger records real client IP, not nginx's.
	e.IPExtractor = cfIPExtractor()

	e.Use(middleware.Recover())
	e.Use(requestLogger(reqlog))
	e.Use(securityHeaders())
	e.Use(negotiationHeaders())
	// The ~13 MB cipher engine gzips itself once (tools/ciphertools); per response it costs ~0.25 s of CPU.
	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{
		Skipper: func(c *echo.Context) bool { return c.Request().URL.Path == "/static/wasm/cipher.wasm" },
	}))

	if dev {
		// No caching in dev, so CSS/JS edits show on refresh.
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

// SubFS returns the live devDir in dev, else the embedded tree rooted at sub.
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

// cfIPExtractor trusts CF-Connecting-IP without a peer check because the app is reachable only through
// nginx behind Cloudflare (DEPLOYMENT.md §4), so no client can forge it; X-Forwarded-For is peer-checked.
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

// requestLogger is Echo's RequestLogger trimmed to our fields; a non-nil reqlog also stores each request.
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
			// Redact for both sinks: the slog line lands on the host's disk via Docker with no TTL.
			uri := RedactURI(v.URI)
			attrs := []slog.Attr{
				slog.String("method", v.Method),
				slog.Int("status", v.Status),
				slog.String("uri", uri),
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

			// Record is non-blocking and nil-safe, so this stays off the request path.
			if ShouldRecord(v.Method, c.Request().URL.Path, v.Status) {
				reqlog.Record(RequestEntry{
					Method:    v.Method,
					Host:      v.Host,
					URI:       uri,
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

// negotiationHeaders: one URL serves page, fragment or JSON, so caches must Vary or Back shows a fragment.
func negotiationHeaders() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if !strings.HasPrefix(c.Request().URL.Path, "/static/") {
				h := c.Response().Header()
				h.Add("Vary", "Accept")
				h.Add("Vary", "HX-Request")
				h.Add("Vary", "HX-History-Restore-Request")
				if IsHTMX(c) {
					h.Set("Cache-Control", "no-store")
				}
			}
			return next(c)
		}
	}
}

// securityHeaders: script-src needs 'unsafe-eval' for Alpine's standard build and 'unsafe-inline' for
// inline <script> blocks; tightening it means Alpine's CSP build plus a per-request nonce on each block.
func securityHeaders() echo.MiddlewareFunc {
	const csp = "default-src 'self'; " +
		"script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
		// botcheck runs a blob: Worker; without worker-src it falls back to script-src, which bans blob:.
		"worker-src 'self' blob:; " +
		"child-src 'self' blob:; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; " +
		"font-src 'self'; " +
		// api6.ipify.org: the IP tool's IPv6 check only works from the visitor's own connection.
		"connect-src 'self' https://api6.ipify.org; " +
		"object-src 'none'; " +
		"base-uri 'none'; " +
		"form-action 'self'; " +
		"frame-ancestors 'none'"
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			h := c.Response().Header()
			h.Set("Content-Security-Policy", csp)
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			return next(c)
		}
	}
}
