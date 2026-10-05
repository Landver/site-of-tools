package tests

import (
	"html"
	"io/fs"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/Landver/site-of-tools/tools/botcheck"
	"github.com/Landver/site-of-tools/tools/ciphertools"
	"github.com/Landver/site-of-tools/tools/dnstools"
	"github.com/Landver/site-of-tools/tools/iptools"
	"github.com/Landver/site-of-tools/tools/linktools"
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
		if ep["url"] != base+p || ep["title"] == "" {
			t.Errorf("%s url = %v, title = %v", p, ep["url"], ep["title"])
		}
		if _, ok := ep["rest"]; ok != (p != "/mcp") {
			t.Errorf("%s rest = %v: every toolset names its site, /mcp none", p, ep["rest"])
		}
		for _, tl := range ep["tools"].([]any) {
			tm := tl.(map[string]any)
			tools[p] = append(tools[p], tm["name"].(string))
			if tm["annotations"] == nil || tm["description"] == "" || tm["rate_limit"] == nil {
				t.Errorf("%s lacks annotations, a description or its rate limit", tm["name"])
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

// TestLandingPage is built with the real Limits, so it checks the published rates.
func TestLandingPage(t *testing.T) {
	s := newStack(t, stackOpts{owner: offlineOwner(t), dnsLim: dnstools.NewLimits(), linkLim: linktools.NewLimits(),
		cipherLim: ciphertools.NewLimits(), botLim: botcheck.NewLimits()})
	rec := s.do(http.MethodGet, "/", "", map[string]string{"Accept": "text/html"})
	body := html.UnescapeString(rec.Body.String())
	for _, want := range []string{
		`data-copy="http://mcp.test/mcp"`, `data-copy="http://mcp.test/mcp/ip"`,
		`data-copy="http://mcp.test/mcp/dns"`, `data-copy="http://mcp.test/mcp/link"`,
		"ip_lookup", "ip_cidr", "IP Tools", `href="http://ip.test"`,
		"dns_lookup", "DNS Tools", "link_redirect_chain", "Link Tools", `href="http://link.test"`,
		`data-copy="http://mcp.test/mcp/cipher"`, "cipher_jwt_decode", "Cipher Tools", `href="http://cipher.test"`,
		`data-copy="http://mcp.test/mcp/botcheck"`, "botcheck_score", `href="http://botcheck.test"`,
		`data-copy="http://mcp.test/mcp/site"`, "site_blog", `href="https://corpberry.test"`,
		"IP2Location LITE", "DROP list", "InternetDB", "crt.sh", "rdap.org", // the footer's credits
		`href="https://lite.ip2location.com"`, // and each toolset's sources

		`id="setup"`,
		"claude mcp add --scope user --transport http corpberry http://mcp.test/mcp",
		"Customize → Connectors → Add custom connector", "Developer mode",
		`"corpberry-ip": { "type": "http", "url": "http://mcp.test/mcp/ip" }`,
		`"mcpServers": {`, `"corpberry-ip": { "url": "http://mcp.test/mcp/ip" }`, "~/.cursor/mcp.json",
		"codex mcp add corpberry-ip --url http://mcp.test/mcp/ip", "[mcp_servers.corpberry-ip]\nurl = \"http://mcp.test/mcp/ip\"",
		"gemini mcp add --transport http corpberry-ip http://mcp.test/mcp/ip", `"corpberry-ip": { "httpUrl": "http://mcp.test/mcp/ip" }`,
		"npx mcp-remote http://mcp.test/mcp/ip",

		"test material only", "Never the arguments",
		"5 a second (burst 20)", "20 a second (burst 100)",
		"2/s, burst 10", "10/s, burst 50", "1 per 2 s, burst 3", "1/s, burst 5", "20/s, burst 60",
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

var terminalBlock = regexp.MustCompile(`(?is)<summary[^>]*>[^<]*from the terminal</summary>.*?</details>`)

func TestEveryTerminalBlockPointsAtItsToolset(t *testing.T) {
	blocks := 0
	for toolset, fsys := range map[string]fs.FS{
		"ip": iptools.Templates, "dns": dnstools.Templates, "link": linktools.Templates,
		"cipher": ciphertools.Templates, "botcheck": botcheck.Templates,
	} {
		pages, _ := fs.Glob(fsys, "templates/*.html")
		for _, page := range pages {
			src, err := fs.ReadFile(fsys, page)
			if err != nil {
				t.Fatal(err)
			}
			for _, block := range terminalBlock.FindAllString(string(src), -1) {
				blocks++
				if !strings.Contains(block, `{{template "partials/mcp-hint" "`+toolset+`"}}`) {
					t.Errorf("%s %s: the terminal block has no MCP line for %s", toolset, page, toolset)
				}
			}
		}
	}
	if blocks < 29 {
		t.Errorf("found %d terminal blocks, want the 29 the pages carry", blocks)
	}

	// Rendered with the renderer's fallback funcs, as on an IP page.
	page := newStack(t, stackOpts{}).do(http.MethodGet, "/", "", map[string]string{"Host": ipHost, "Accept": "text/html"}).Body.String()
	for _, want := range []string{"https://mcp.corpberry.com/mcp/ip", `href="https://mcp.corpberry.com/#setup"`} {
		if !strings.Contains(page, want) {
			t.Errorf("the IP page lacks %q", want)
		}
	}
}
