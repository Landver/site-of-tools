// Package platform: shared engine — app factory, template renderer + content
// negotiation, embedded/disk asset toggle. Knows nothing about individual tools.
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
// persistence → middleware then logs to slog only, as before.
func NewApp(r *Renderer, staticFS fs.FS, dev bool, reqlog *RequestLog) *echo.Echo {
	e := echo.New()
	e.Renderer = r
	// Feeds c.RealIP() → RequestLogger records real client IP, not nginx's.
	e.IPExtractor = cfIPExtractor()

	e.Use(middleware.Recover())
	e.Use(requestLogger(reqlog))
	e.Use(securityHeaders())
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

// SubFS returns FS rooted at sub: live disk (devDir) in dev, else embedded tree
// w/ sub prefix stripped.
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
// X-Forwarded-For chain, then socket addr. CF-Connecting-IP trusted
// unconditionally: ingress trust enforced at network layer (app published only
// behind nginx, which sits behind Cloudflare — see DEPLOYMENT.md §4) → no
// in-process peer check needed, direct client can't reach it to forge header.
// X-Forwarded-For chain, by contrast, peer-verified here via
// TrustLoopback/TrustPrivateNet. In dev no proxy exists → both fall through to
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

// requestLogger is built-in v5 RequestLogger trimmed to fields we care about:
// slog line drops user_agent + request_id, puts status before uri (slog still
// prepends time/level/msg). One attribute list serves both success + error
// cases (error appends its own field). When reqlog non-nil, also persists each
// request (minus static assets) to Mongo corpus — reuses values this middleware
// already captures rather than adding 2nd pass; corpus keeps user_agent even
// though slog line omits it.
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
			// Redact once, here, and use the result for BOTH sinks below. The
			// slog line lands on the host's disk via Docker with no TTL, so
			// redacting only inside RequestLog.Record would leave the
			// longer-lived copy intact. See platform/redact.go.
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

			// Persist to corpus off request path (Record non-blocking + nil-safe).
			// Skip static assets — high volume, no analytic value.
			if ShouldRecord(c.Request().URL.Path) {
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

// securityHeaders sets the response headers every subdomain wants. Applied in
// NewApp so a new tool cannot forget them.
//
// The script-src is deliberately permissive and that is a known limitation, not
// an oversight. Alpine's directives (x-data, x-show, @click) are evaluated at
// runtime, so the standard build needs 'unsafe-eval'; and three templates carry
// inline <script> blocks, which need 'unsafe-inline'. Tightening this means
// switching to Alpine's CSP build AND giving every inline block a per-request
// nonce — a real change, not a header edit.
//
// What it buys even so: no script may be loaded from another origin, nothing
// may be framed, <base> cannot be rewritten, forms cannot post off-site, and
// plugins are gone. On link.corpberry.com — whose entire job is rendering
// attacker-chosen URLs — form-action and base-uri are the two that matter, and
// the whole policy is the containment layer that turns the next refactor slip
// in a template from stored XSS into a blocked load
// (tools/linktools/docs/06-security-and-abuse.md §8).
func securityHeaders() echo.MiddlewareFunc {
	const csp = "default-src 'self'; " +
		"script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
		// botcheck spawns a Worker from a blob: URL to time things off the main
		// thread. worker-src falls back to script-src when unset, and script-src
		// does not allow blob:, so omitting this silently breaks that tool —
		// found by loading the page, not by reading the policy.
		"worker-src 'self' blob:; " +
		"child-src 'self' blob:; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; " +
		"font-src 'self'; " +
		// api6.ipify.org is the IP tool's live IPv6 check: the page asks it from
		// the VISITOR's browser on purpose, because only the visitor's own
		// connection can answer "do you have working IPv6". It is the single
		// external endpoint the whole frontend talks to — verified by grepping
		// every fetch/XHR/Worker call in shared/ and tools/ — so connect-src
		// stays otherwise closed.
		"connect-src 'self' https://api6.ipify.org; " +
		"object-src 'none'; " +
		"base-uri 'none'; " +
		"form-action 'self'; " +
		"frame-ancestors 'none'"
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			h := c.Response().Header()
			h.Set("Content-Security-Policy", csp)
			// Stops a response whose body is attacker-influenced being sniffed
			// into something executable regardless of its declared type.
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			return next(c)
		}
	}
}
