package tests

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var toolName = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// Budgets for what a client puts in the model's context before any call.
const (
	maxToolBytes = 2 << 10
	maxListBytes = 40 << 10
)

func listTools(t *testing.T, cs *mcp.ClientSession) *mcp.ListToolsResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// endpoints are the paths tools/list is pinned for, with the golden file and
// the cache scope each must carry.
var endpoints = []struct{ path, file, scope string }{
	{"/mcp", "tools-list.golden.json", "public"},
	{"/mcp/ip", "tools-list-ip.golden.json", "public"},
	{"/mcp/dns", "tools-list-dns.golden.json", "public"},
	{"/mcp/link", "tools-list-link.golden.json", "public"},
	{"/mcp/owner", "tools-list-owner.golden.json", "private"},
}

// TestToolsListGolden pins the agent-facing contract of each endpoint: names
// in order, titles, descriptions, schemas and hints. A change is a reviewed
// golden diff (UPDATE_GOLDEN=1 rewrites the files).
func TestToolsListGolden(t *testing.T) {
	s := newStack(t, stackOpts{owner: offlineOwner(t)})
	for _, ep := range endpoints {
		res := listTools(t, s.client(t, ep.path, map[string]string{"CF-Connecting-IP": clientIP, "X-Api-Key": ownerKey}, nil))
		got, err := json.MarshalIndent(res.Tools, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		golden := filepath.Join("testdata", ep.file)
		if os.Getenv("UPDATE_GOLDEN") == "1" {
			if err := os.WriteFile(golden, append(got, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatalf("%v (run with UPDATE_GOLDEN=1 to create it)", err)
		}
		var w, g any
		_ = json.Unmarshal(want, &w)
		_ = json.Unmarshal(got, &g)
		if diff := cmp.Diff(w, g); diff != "" {
			t.Errorf("%s tools/list changed (-golden +got):\n%s", ep.path, diff)
		}

		if len(got) > maxListBytes {
			t.Errorf("%s tools/list is %d bytes, over the %d budget", ep.path, len(got), maxListBytes)
		}
		for i, tool := range res.Tools {
			b, _ := json.Marshal(tool)
			switch {
			case !toolName.MatchString(tool.Name):
				t.Errorf("tool name %q is not %s", tool.Name, toolName)
			case len(b) > maxToolBytes:
				t.Errorf("%s is %d bytes, over the %d per-tool budget", tool.Name, len(b), maxToolBytes)
			case i > 0 && res.Tools[i-1].Name >= tool.Name:
				t.Errorf("tools/list not in name order at %s", tool.Name)
			case tool.Annotations == nil || tool.Annotations.DestructiveHint == nil || tool.Annotations.OpenWorldHint == nil:
				t.Errorf("%s leaves a hint unset, so it reads as destructive or open-world", tool.Name)
			}
		}
		if res.TTLMs != 3_600_000 || res.CacheScope != ep.scope {
			t.Errorf("%s list cache = %d %q, want 3600000 %s", ep.path, res.TTLMs, res.CacheScope, ep.scope)
		}
	}
}

// TestInstructionsNameOnlyTheirTools: a client connected to one endpoint must
// not be told about tools it can't call; only /mcp, which serves both, says
// which of two look-alike tools fits.
func TestInstructionsNameOnlyTheirTools(t *testing.T) {
	s := newStack(t, stackOpts{owner: offlineOwner(t)})
	const routing = "link_redirect_chain follows a URL's HTTP redirects"
	for _, ep := range endpoints {
		cs := s.client(t, ep.path, map[string]string{"CF-Connecting-IP": clientIP, "X-Api-Key": ownerKey}, nil)
		got := cs.InitializeResult().Instructions
		served := map[string]bool{}
		for _, tool := range listTools(t, cs).Tools {
			served[tool.Name] = true
			if !strings.Contains(got, tool.Name+" ("+tool.Title+")") {
				t.Errorf("%s instructions don't name %s", ep.path, tool.Name)
			}
		}
		for _, name := range []string{"ip_lookup", "dns_lookup", "dns_trace", "link_inspect", "link_short_create", "cipher_encode"} {
			if !served[name] && strings.Contains(got, name) {
				t.Errorf("%s instructions name %s, which it doesn't serve: %q", ep.path, name, got)
			}
		}
		if strings.Contains(got, routing) != (ep.path == "/mcp") {
			t.Errorf("%s instructions: routing hint present = %v, want it on /mcp only", ep.path, !strings.Contains(got, routing))
		}
	}
}
