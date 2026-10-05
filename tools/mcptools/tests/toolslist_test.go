package tests

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Landver/site-of-tools/platform/goldentest"
	"github.com/Landver/site-of-tools/tools/linktools"
)

// What a client puts in the model's context; a cipher op with eleven fields needs most of a tool's 3 KB.
const (
	maxToolBytes = 3 << 10
	maxListBytes = 64 << 10 // /mcp, every public tool
	maxSetBytes  = 32 << 10 // one toolset's endpoint
)

// An endpoint's list, its instructions and its landing-page entry name the same tools.
func TestToolsListGolden(t *testing.T) {
	s := newStack(t, stackOpts{owner: offlineOwner(t)})
	catalog := s.restOK(t, mcpHost, "/", "")
	if catalog["name"] != "corpberry" || catalog["version"] == "" {
		t.Errorf("catalog = %v, want name and version", catalog)
	}
	advertised := map[string][]string{}
	var paths []string
	for _, e := range catalog["endpoints"].([]any) {
		ep := e.(map[string]any)
		p := ep["path"].(string)
		paths = append(paths, p)
		if _, rest := ep["rest"]; ep["url"] != base+p || ep["title"] == "" || rest == (p == "/mcp") {
			t.Errorf("catalog %s = %v, want its url, a title and, for a toolset, its site", p, ep)
		}
		for _, tl := range ep["tools"].([]any) {
			tm := tl.(map[string]any)
			advertised[p] = append(advertised[p], tm["name"].(string))
			if tm["annotations"] == nil || tm["description"] == "" || tm["rate_limit"] == nil {
				t.Errorf("catalog %s lacks annotations, a description or its rate limit", tm["name"])
			}
		}
	}
	endpoints := []string{"/mcp", "/mcp/ip", "/mcp/dns", "/mcp/link", "/mcp/cipher", "/mcp/botcheck", "/mcp/site", "/mcp/owner"}
	// The owner's endpoint exists, but is not advertised.
	if diff := cmp.Diff(endpoints[:len(endpoints)-1], paths); diff != "" {
		t.Errorf("catalog endpoints (-want +got):\n%s", diff)
	}

	var all, union []*mcp.Tool
	for i, ep := range endpoints {
		// One address each: every message spends the protocol budget.
		hdr := map[string]string{"CF-Connecting-IP": fmt.Sprintf("198.51.100.%d", 100+i), "X-Api-Key": ownerKey}
		cs := s.client(t, ep, hdr)
		res := listTools(t, cs)
		var names []string
		for _, tool := range res.Tools {
			names = append(names, tool.Name)
			if b, _ := json.Marshal(tool); len(b) > maxToolBytes {
				t.Errorf("%s is %d bytes, over the %d per-tool budget", tool.Name, len(b), maxToolBytes)
			}
		}
		scope, budget := "public", maxSetBytes
		switch ep {
		case "/mcp":
			all, budget = res.Tools, maxListBytes
		case "/mcp/owner":
			scope = "private"
			goldentest.JSON(t, "tools-list-owner", res.Tools)
		default:
			goldentest.JSON(t, "tools-list-"+path.Base(ep), res.Tools)
			union = append(union, res.Tools...)
		}
		if diff := cmp.Diff(advertised[ep], names); ep != "/mcp/owner" && diff != "" {
			t.Errorf("%s landing-page entry vs tools/list (-landing +list):\n%s", ep, diff)
		}
		if wire := s.do(http.MethodPost, ep, listBody, mcpHeaders(hdr)).Body.Len(); wire > budget {
			t.Errorf("%s tools/list is %d bytes, over the %d budget", ep, wire, budget)
		}
		if res.TTLMs != 3_600_000 || res.CacheScope != scope {
			t.Errorf("%s list cache = %d %q, want 3600000 %s", ep, res.TTLMs, res.CacheScope, scope)
		}

		// Only /mcp tells look-alike tools apart; a client may connect to any one endpoint.
		got := cs.InitializeResult().Instructions
		for _, tool := range res.Tools {
			if !strings.Contains(got, tool.Name+" ("+tool.Title+")") {
				t.Errorf("%s instructions don't name %s", ep, tool.Name)
			}
		}
		for _, name := range []string{"ip_lookup", "dns_lookup", "dns_trace", "link_inspect", "link_short_create", "cipher_encode"} {
			if !slices.Contains(names, name) && strings.Contains(got, name) {
				t.Errorf("%s instructions name %s, which it doesn't serve: %q", ep, name, got)
			}
		}
		for _, hint := range []string{"link_redirect_chain follows a URL's HTTP redirects", "cipher_encode converts bytes"} {
			if strings.Contains(got, hint) != (ep == "/mcp") {
				t.Errorf("%s instructions: %q present = %v, want it on /mcp only", ep, hint, ep != "/mcp")
			}
		}
	}
	slices.SortFunc(union, func(a, b *mcp.Tool) int { return strings.Compare(a.Name, b.Name) })
	if diff := cmp.Diff(asJSON(t, union), asJSON(t, all)); diff != "" {
		t.Errorf("/mcp is not the union of the toolsets (-union +/mcp):\n%s", diff)
	}
}

func TestToolsNeedTheirDependencies(t *testing.T) {
	s := newStack(t, stackOpts{bare: true, dns: lookOnly{&fakeDNS{}}, link: linktools.NewService()})
	names := toolNames(t, s.client(t, "/mcp", nil))
	for _, name := range []string{"dns_consistency", "dns_trace", "dns_domain_info", "dns_email_auth",
		"link_redirect_chain", "link_short_resolve", "site_blog"} {
		if slices.Contains(names, name) {
			t.Errorf("%s is listed without what it runs on", name)
		}
	}
	if !slices.Contains(names, "dns_lookup") || !slices.Contains(names, "link_inspect") {
		t.Errorf("tools = %v, want dns_lookup and the link tools that need nothing more", names)
	}
	if rec := s.do(http.MethodPost, "/mcp/site", listBody, mcpHeaders(nil)); rec.Code != http.StatusNotFound {
		t.Errorf("/mcp/site without a blog = %d, want 404", rec.Code)
	}
}
