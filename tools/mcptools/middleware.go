package mcptools

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Landver/site-of-tools/platform"
)

// codeRefused answers a message turned away; MCP defines no code for one.
const codeRefused = -32000

// outcome is what one MCP message came to. Records carry it, never the
// arguments, result or error text: cipher errors quote their input.
type outcome struct {
	name   string
	status int
}

var (
	outcomeOK        = outcome{"ok", http.StatusOK}
	outcomeToolError = outcome{"tool_error", http.StatusUnprocessableEntity}
	outcomeError     = outcome{"error", http.StatusBadRequest}
	outcomeLimited   = outcome{"limited", http.StatusTooManyRequests}
	outcomeBusy      = outcome{"busy", http.StatusServiceUnavailable}
	outcomeTimeout   = outcome{"timeout", http.StatusGatewayTimeout}
	outcomeCancelled = outcome{"cancelled", 499}
	outcomeInternal  = outcome{"internal", http.StatusInternalServerError}
	outcomePanic     = outcome{"panic", http.StatusInternalServerError}
)

type calls struct {
	protocol platform.Limiter // every message that isn't a tools/call
	reqlog   *platform.RequestLog
	log      *slog.Logger
}

// middleware wraps every message in recover, deadline, budget, sanitizer and
// record. The SDK has no recover: a panicking tool would take every host down.
func (m *calls) middleware(path string, specs map[string]*toolSpec) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (res mcp.Result, err error) {
			start := time.Now()
			who := callerFrom(ctx)
			call, _ := req.(*mcp.CallToolRequest)
			name, spec := method, (*toolSpec)(nil)
			if call != nil && call.Params != nil {
				name, spec = platform.Clip(call.Params.Name, 64), specs[call.Params.Name]
				// The SDK writes schema defaults into the nil map "arguments": null
				// decodes to, and panics.
				if string(call.Params.Arguments) == "null" {
					call.Params.Arguments = nil
				}
			}
			got, size := outcomeOK, 0
			defer func() {
				if p := recover(); p != nil {
					m.log.Error("mcp: panic", "uri", path+"#"+name, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
					got = outcomePanic
					res, err = refuse(call, jsonrpc.CodeInternalError, "Internal error; it has been logged.")
				}
				m.record(who, path+"#"+name, got, size, time.Since(start), req)
			}()

			deadline, lim := quickDeadline, m.protocol
			if spec != nil {
				deadline, lim = spec.deadline, spec.limiter
			}
			ctx, cancel := context.WithTimeout(ctx, deadline)
			defer cancel()
			// The SDK cancels only 2026-07-28 requests when the client goes.
			defer context.AfterFunc(who.http, cancel)()
			if !platform.AllowKey(lim, who.key) {
				got = outcomeLimited
				return refuse(call, codeRefused, platform.LimitedMessage)
			}
			if spec != nil {
				if spec.breaker != nil && !platform.AllowKey(spec.breaker, who.key) {
					got = outcomeBusy
					return refuse(call, codeRefused, platform.BusyMessage)
				}
				w := int64(1)
				if spec.weight != nil {
					w = spec.weight(call.Params.Arguments)
				}
				if !spec.cap.TryAcquire(who.key, w) {
					got = outcomeBusy
					return refuse(call, codeRefused, platform.BusyMessage)
				}
				defer spec.cap.Release(who.key, w)
			}

			res, err = next(ctx, method, req)
			if err != nil {
				got = outcomeError
				return res, err
			}
			r, ok := res.(*mcp.CallToolResult)
			if call == nil || !ok || r == nil {
				return res, err
			}
			if r.IsError {
				got = outcomeToolError
				switch {
				case errors.Is(ctx.Err(), context.DeadlineExceeded):
					got, r = outcomeTimeout, errorResult(fmt.Sprintf("Timed out after %s. Try again, or ask for less.", deadline))
				case ctx.Err() != nil:
					got = outcomeCancelled
				}
			}
			narrow, whole := "", false
			if spec != nil {
				narrow, whole = spec.narrow, spec.whole
			}
			out, n, serr := sanitize(r, narrow, whole)
			if serr != nil {
				m.log.Error("mcp: unusable tool result", "uri", path+"#"+name, "error", serr.Error())
				got = outcomeInternal
				return refuse(call, jsonrpc.CodeInternalError, "Internal error; it has been logged.")
			}
			if out.IsError && got == outcomeOK {
				got = outcomeToolError
			}
			size = n
			return out, nil
		}
	}
}

// refuse: an isError result for a call, which the model can act on; else a JSON-RPC error.
func refuse(call *mcp.CallToolRequest, code int64, msg string) (mcp.Result, error) {
	if call != nil {
		return errorResult(msg), nil
	}
	return nil, &jsonrpc.Error{Code: code, Message: msg}
}

// record logs a message as the REST logger does a request (ShouldRecord skips /mcp).
func (m *calls) record(who *caller, uri string, o outcome, size int, d time.Duration, req mcp.Request) {
	client := who.userAgent
	if ci, ok := req.(interface{ ClientInfo() *mcp.Implementation }); ok {
		if info := ci.ClientInfo(); info != nil && info.Name != "" {
			client = info.Name
			if info.Version != "" {
				client += "/" + info.Version
			}
		}
	}
	client = platform.Clip(client, 200)
	m.log.LogAttrs(context.Background(), slog.LevelInfo, "MCP",
		slog.String("outcome", o.name),
		slog.Int("status", o.status),
		slog.String("uri", uri),
		slog.Duration("latency", d),
		slog.String("host", who.host),
		slog.Int("bytes_out", size),
		slog.String("remote_ip", who.ip),
		slog.String("client", client),
	)
	m.reqlog.Record(platform.RequestEntry{
		Method:    "MCP",
		Host:      who.host,
		URI:       uri,
		Status:    o.status,
		RemoteIP:  who.ip,
		UserAgent: client,
		LatencyMS: d.Milliseconds(),
		BytesOut:  int64(size),
		CreatedAt: time.Now(),
	})
}
