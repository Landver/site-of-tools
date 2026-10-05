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

// TestToolsListGolden pins the agent-facing contract of each endpoint: names
// in order, titles, descriptions, schemas and hints. A change is a reviewed
// golden diff (UPDATE_GOLDEN=1 rewrites the files).
func TestToolsListGolden(t *testing.T) {
	s := newStack(t, stackOpts{})
	for path, file := range map[string]string{"/mcp": "tools-list.golden.json", "/mcp/ip": "tools-list-ip.golden.json"} {
		res := listTools(t, s.client(t, path, nil, nil))
		got, err := json.MarshalIndent(res.Tools, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		golden := filepath.Join("testdata", file)
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
			t.Errorf("%s tools/list changed (-golden +got):\n%s", path, diff)
		}

		if len(got) > maxListBytes {
			t.Errorf("%s tools/list is %d bytes, over the %d budget", path, len(got), maxListBytes)
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
		if res.TTLMs != 3_600_000 || res.CacheScope != "public" {
			t.Errorf("%s list cache = %d %q, want 3600000 public", path, res.TTLMs, res.CacheScope)
		}
	}
}

// TestInstructionsNameOnlyTheirTools: a client connected to one toolset must
// not be told about tools it can't call.
func TestInstructionsNameOnlyTheirTools(t *testing.T) {
	s := newStack(t, stackOpts{})
	for _, path := range []string{"/mcp", "/mcp/ip"} {
		got := s.client(t, path, nil, nil).InitializeResult().Instructions
		if !strings.Contains(got, "ip_lookup (IP lookup)") || !strings.Contains(got, "ip_cidr") {
			t.Errorf("%s instructions = %q, want its tools named", path, got)
		}
		for _, absent := range []string{"dns_", "link_", "cipher_"} {
			if strings.Contains(got, absent) {
				t.Errorf("%s instructions name %s tools it doesn't serve: %q", path, absent, got)
			}
		}
	}
}
