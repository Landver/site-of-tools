package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Landver/site-of-tools/platform/goldentest"
)

// Budgets for what a client puts in the model's context before any call. One
// tool may take 3 KB: a cipher op with eleven fields needs most of it.
const (
	maxToolBytes = 3 << 10
	maxListBytes = 64 << 10 // /mcp, every public tool
	maxSetBytes  = 32 << 10 // one toolset's endpoint
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

var endpoints = []struct{ path, scope string }{
	{"/mcp", "public"}, {"/mcp/ip", "public"}, {"/mcp/dns", "public"}, {"/mcp/link", "public"},
	{"/mcp/cipher", "public"}, {"/mcp/botcheck", "public"}, {"/mcp/site", "public"}, {"/mcp/owner", "private"},
}

// TestToolsListGolden pins each toolset's tools/list; /mcp must list their union.
func TestToolsListGolden(t *testing.T) {
	s := newStack(t, stackOpts{owner: offlineOwner(t)})
	var all, union []*mcp.Tool
	for i, ep := range endpoints {
		// One address per endpoint: every message spends the protocol budget.
		hdr := map[string]string{"CF-Connecting-IP": fmt.Sprintf("198.51.100.%d", 100+i), "X-Api-Key": ownerKey}
		res := listTools(t, s.client(t, ep.path, hdr, nil))
		switch ep.path {
		case "/mcp":
			all = res.Tools
		case "/mcp/owner":
			goldentest.JSON(t, "tools-list-owner", res.Tools)
		default:
			goldentest.JSON(t, "tools-list-"+path.Base(ep.path), res.Tools)
			union = append(union, res.Tools...)
		}

		wire := s.do(http.MethodPost, ep.path, listBody, mcpHeaders(hdr)).Body.Len()
		budget := maxSetBytes
		if ep.path == "/mcp" {
			budget = maxListBytes
		}
		t.Logf("%s tools/list: %d bytes", ep.path, wire)
		if wire > budget {
			t.Errorf("%s tools/list is %d bytes, over the %d budget", ep.path, wire, budget)
		}
		for _, tool := range res.Tools {
			if b, _ := json.Marshal(tool); len(b) > maxToolBytes {
				t.Errorf("%s is %d bytes, over the %d per-tool budget", tool.Name, len(b), maxToolBytes)
			}
		}
		if res.TTLMs != 3_600_000 || res.CacheScope != ep.scope {
			t.Errorf("%s list cache = %d %q, want 3600000 %s", ep.path, res.TTLMs, res.CacheScope, ep.scope)
		}
	}
	slices.SortFunc(union, func(a, b *mcp.Tool) int { return strings.Compare(a.Name, b.Name) })
	if diff := cmp.Diff(asJSON(t, union), asJSON(t, all)); diff != "" {
		t.Errorf("/mcp is not the union of the toolsets (-union +/mcp):\n%s", diff)
	}
}

func asJSON(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestInstructionsNameOnlyTheirTools: only /mcp tells look-alike tools apart.
func TestInstructionsNameOnlyTheirTools(t *testing.T) {
	s := newStack(t, stackOpts{owner: offlineOwner(t)})
	routing := []string{"link_redirect_chain follows a URL's HTTP redirects", "cipher_encode converts bytes"}
	for i, ep := range endpoints {
		cs := s.client(t, ep.path, map[string]string{"CF-Connecting-IP": fmt.Sprintf("198.51.100.%d", 100+i), "X-Api-Key": ownerKey}, nil)
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
		for _, hint := range routing {
			if strings.Contains(got, hint) != (ep.path == "/mcp") {
				t.Errorf("%s instructions: %q present = %v, want it on /mcp only", ep.path, hint, strings.Contains(got, hint))
			}
		}
	}
}
