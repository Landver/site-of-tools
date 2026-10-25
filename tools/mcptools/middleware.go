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

const statusCancelled = 499 // nginx's: the client hung up

type calls struct {
	reqlog *platform.RequestLog
	log    *slog.Logger
}

// The SDK has no recover: a panicking tool would take every host down.
func (m *calls) middleware(path string, specs map[string]*toolSpec) mcp.Middleware {
	protocol := &toolSpec{deadline: quickDeadline}
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (res mcp.Result, err error) {
			start := time.Now()
			who := callerFrom(ctx)
			call, _ := req.(*mcp.CallToolRequest)
			name, spec := method, protocol
			if call != nil && call.Params != nil {
				name = platform.Clip(call.Params.Name, 64)
				if s := specs[call.Params.Name]; s != nil {
					spec = s
				}
				// "arguments": null decodes to a nil map, which the SDK writes defaults into and panics.
				if string(call.Params.Arguments) == "null" {
					call.Params.Arguments = nil
				}
			}
			got, size := http.StatusOK, 0
			defer func() {
				if p := recover(); p != nil {
					m.log.Error("mcp: panic", "uri", path+"#"+name, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
					got = http.StatusInternalServerError
					res, err = refuse(call, "Internal error; it has been logged.")
				}
				m.record(who, path+"#"+name, got, size, time.Since(start), req)
			}()

			ctx, cancel := context.WithTimeout(ctx, spec.deadline)
			defer cancel()
			// The SDK doesn't cancel a call when its client hangs up.
			defer context.AfterFunc(who.http, cancel)()
			if spec != protocol && !platform.AllowKey(spec.limiter, who.ip) {
				got = http.StatusTooManyRequests
				return refuse(call, platform.LimitedMessage)
			}
			if !spec.cap.TryAcquire(who.ip, 1) {
				got = http.StatusServiceUnavailable
				return refuse(call, platform.BusyMessage)
			}
			defer spec.cap.Release(who.ip, 1)

			res, err = next(ctx, method, req)
			if err != nil {
				got = http.StatusBadRequest
				return res, err
			}
			r, ok := res.(*mcp.CallToolResult)
			if call == nil || !ok || r == nil {
				return res, err
			}
			if r.IsError {
				switch {
				case errors.Is(ctx.Err(), context.DeadlineExceeded):
					got, r = http.StatusGatewayTimeout, errorResult(fmt.Sprintf("Timed out after %s. Try again, or ask for less.", spec.deadline))
				case ctx.Err() != nil:
					got = statusCancelled
				}
			}
			out, n, serr := sanitize(r)
			if serr != nil {
				m.log.Error("mcp: unusable tool result", "uri", path+"#"+name, "error", serr.Error())
				got = http.StatusInternalServerError
				return refuse(call, "Internal error; it has been logged.")
			}
			if out.IsError && got == http.StatusOK {
				got = http.StatusUnprocessableEntity
			}
			size = n
			return out, nil
		}
	}
}

// A call is refused with an isError result, which the model can act on.
func refuse(call *mcp.CallToolRequest, msg string) (mcp.Result, error) {
	if call != nil {
		return errorResult(msg), nil
	}
	return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: msg}
}

// The request log skips /mcp: each message is recorded here instead, never with
// its arguments, result or error text: cipher errors quote their input.
func (m *calls) record(who *caller, uri string, status, size int, d time.Duration, req mcp.Request) {
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
		slog.Int("status", status),
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
		Status:    status,
		RemoteIP:  who.ip,
		UserAgent: client,
		LatencyMS: d.Milliseconds(),
		BytesOut:  int64(size),
		CreatedAt: time.Now(),
	})
}
