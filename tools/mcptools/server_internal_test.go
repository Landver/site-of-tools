package mcptools

import (
	"log/slog"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Landver/site-of-tools/platform"
)

func TestBuildEndpointsRefusesBadSpecs(t *testing.T) {
	lim := platform.NewLimiter(1, 1)
	spec := func(name, toolset string, l platform.Limiter) toolSpec {
		return toolSpec{toolset: toolset, tool: &mcp.Tool{Name: name}, limiter: l}
	}
	m := &calls{protocol: lim, log: slog.New(slog.DiscardHandler)}
	for name, specs := range map[string][]toolSpec{
		"dotted name":            {spec("ip.lookup", "ip", lim)},
		"duplicate":              {spec("ip_x", "ip", lim), spec("ip_x", "ip", lim)},
		"owner is not a toolset": {spec("link_x", ownerEndpoint, lim)},
		"no limiter":             {spec("ip_y", "ip", nil)},
	} {
		if _, err := buildEndpoints(specs, nil, m, "http://mcp.test"); err == nil {
			t.Errorf("%s: built", name)
		}
	}
}
