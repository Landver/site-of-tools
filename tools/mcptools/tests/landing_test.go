package tests

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestLandingJSON(t *testing.T) {
	s := newStack(t, stackOpts{owner: offlineOwner(t)})
	rec := s.do(http.MethodGet, "/", "", map[string]string{"Accept": "application/json"})
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d", rec.Code)
	}
	got := decode(t, rec.Body.Bytes())
	if got["name"] != "corpberry" || got["version"] == "" {
		t.Errorf("catalog = %v, want name and version", got)
	}
	var paths []string
	tools := map[string][]string{}
	for _, e := range got["endpoints"].([]any) {
		ep := e.(map[string]any)
		p := ep["path"].(string)
		paths = append(paths, p)
		if ep["url"] != base+p {
			t.Errorf("%s url = %v", p, ep["url"])
		}
		for _, tl := range ep["tools"].([]any) {
			tm := tl.(map[string]any)
			tools[p] = append(tools[p], tm["name"].(string))
			if tm["annotations"] == nil || tm["description"] == "" {
				t.Errorf("%s lacks annotations or a description", tm["name"])
			}
		}
	}
	// The owner's endpoint exists here, but is not advertised.
	if diff := cmp.Diff([]string{"/mcp", "/mcp/ip", "/mcp/dns", "/mcp/link", "/mcp/cipher", "/mcp/botcheck", "/mcp/site"}, paths); diff != "" {
		t.Errorf("endpoints (-want +got):\n%s", diff)
	}
	for path, want := range map[string][]string{
		"/mcp/ip": {"ip_cidr", "ip_lookup"}, "/mcp/botcheck": {"botcheck_score"}, "/mcp/site": {"site_blog"},
	} {
		if diff := cmp.Diff(want, tools[path]); diff != "" {
			t.Errorf("%s tools (-want +got):\n%s", path, diff)
		}
	}
	if n := len(tools["/mcp/cipher"]); n != 15 || len(tools["/mcp"]) != 35 {
		t.Errorf("%d cipher tools and %d in all, want 15 and the catalog's 35", n, len(tools["/mcp"]))
	}
}

func TestLandingPage(t *testing.T) {
	s := newStack(t, stackOpts{owner: offlineOwner(t)})
	rec := s.do(http.MethodGet, "/", "", map[string]string{"Accept": "text/html"})
	body := rec.Body.String()
	for _, want := range []string{
		`data-copy="http://mcp.test/mcp"`, `data-copy="http://mcp.test/mcp/ip"`,
		`data-copy="http://mcp.test/mcp/dns"`, `data-copy="http://mcp.test/mcp/link"`,
		"claude mcp add --scope user --transport http corpberry http://mcp.test/mcp",
		"ip_lookup", "ip_cidr", "IP Tools", `href="http://ip.test"`,
		"dns_lookup", "DNS Tools", "link_redirect_chain", "Link Tools", `href="http://link.test"`,
		`data-copy="http://mcp.test/mcp/cipher"`, "cipher_jwt_decode", "Cipher Tools", `href="http://cipher.test"`,
		`data-copy="http://mcp.test/mcp/botcheck"`, "botcheck_score", `href="http://botcheck.test"`,
		`data-copy="http://mcp.test/mcp/site"`, "site_blog", `href="https://corpberry.test"`,
		"IP2Location LITE", "DROP list", "InternetDB", "crt.sh", "rdap.org", // the footer's credits
	} {
		if !strings.Contains(body, want) {
			t.Errorf("landing page lacks %q", want)
		}
	}
	if rec.Code != http.StatusOK || strings.Contains(body, "/mcp/owner") || strings.Contains(body, "link_short_create") {
		t.Errorf("landing page = %d; it must not advertise the owner endpoint or its tools", rec.Code)
	}

	// Without the dns toolset nothing on the page reads its sources.
	bare := newStack(t, stackOpts{bare: true}).do(http.MethodGet, "/", "", map[string]string{"Accept": "text/html"}).Body.String()
	if strings.Contains(bare, "crt.sh") || strings.Contains(bare, "rdap.org") || strings.Contains(bare, "/mcp/dns") {
		t.Errorf("the page credits or lists the dns toolset, which isn't served")
	}
}
