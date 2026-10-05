package tests

import (
	"html"
	"io/fs"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/tools/botcheck"
	"github.com/Landver/site-of-tools/tools/ciphertools"
	"github.com/Landver/site-of-tools/tools/dnstools"
	"github.com/Landver/site-of-tools/tools/iptools"
	"github.com/Landver/site-of-tools/tools/linktools"
)

// Built with the real Limits, so it checks the published rates.
func TestLandingPage(t *testing.T) {
	s := newStack(t, stackOpts{owner: offlineOwner(t), ipLim: iptools.NewLimits(), dnsLim: dnstools.NewLimits(),
		linkLim: linktools.NewLimits(), cipherLim: ciphertools.NewLimits(), botLim: botcheck.NewLimits()})
	rec := s.do(http.MethodGet, "/", "", browser)
	body := html.UnescapeString(rec.Body.String())
	for _, want := range []string{
		`data-copy="http://mcp.test/mcp"`, `data-copy="http://mcp.test/mcp/ip"`, "ip_lookup", "IP Tools", `href="http://ip.test"`,
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

	bare := newStack(t, stackOpts{bare: true}).do(http.MethodGet, "/", "", browser).Body.String()
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
