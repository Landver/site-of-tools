package mcptools

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Landver/site-of-tools/platform"
)

// A tool that runs past its deadline fails with its own error; the middleware turns that into one the model can act on.
func TestDeadlineAnswersTimedOut(t *testing.T) {
	var log bytes.Buffer
	m := &calls{log: slog.New(slog.NewTextHandler(&log, nil))}
	slow := &toolSpec{deadline: 10 * time.Millisecond, limiter: platform.NewLimiter(100, 100)}
	next := func(ctx context.Context, _ string, _ mcp.Request) (mcp.Result, error) {
		<-ctx.Done()
		return errorResult(ctx.Err().Error()), nil
	}
	ctx := context.WithValue(context.Background(), callerKey{}, &caller{ip: "198.51.100.1", http: context.Background()})
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "slow"}}

	res, err := m.middleware("/mcp", map[string]*toolSpec{"slow": slow})(next)(ctx, "tools/call", req)
	if err != nil {
		t.Fatal(err)
	}
	r := res.(*mcp.CallToolResult)
	if text := r.Content[0].(*mcp.TextContent).Text; !r.IsError || text != "Timed out after 10ms. Try again, or ask for less." {
		t.Errorf("result = %v %q, want the timeout message", r.IsError, text)
	}
	if !strings.Contains(log.String(), "status=504") {
		t.Errorf("log = %s, want status=504", log.String())
	}
}
