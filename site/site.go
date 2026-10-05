// Package site: serves apex host corpberry.com — portfolio landing page,
// tools index, and the blog (posts embedded from site/posts/).
package site

import (
	"io/fs"
	"net/http"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
)

// Tools is single tool catalog, shared by apex tools index + header's Tools
// dropdown (wired as template func in main). Add new tools here -> both index
// + nav pick them up. Keep A→Z by Name: slice order = render order in both,
// and a site test fails on an out-of-order entry.
func Tools(cfg platform.Config) []platform.Tool {
	return []platform.Tool{
		{
			Name: "Bot check",
			Desc: "Score how much your browser looks like a human vs. an automated bot: client fingerprint signals cross-checked against your connection's headers and IP reputation, with a transparent per-signal breakdown.",
			URL:  cfg.URL("botcheck"),
		},
		{
			Name: "Cipher Tools",
			Desc: "Decode, verify and sign JWTs; hash text or files with every common algorithm at once; HMACs, password hashes, keys and certificates. It all runs in your browser, so nothing you paste leaves the page.",
			URL:  cfg.URL("cipher"),
		},
		{
			Name: "DNS Tools",
			Desc: "A suite of DNS tools: look up every record type for a domain in one query (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, and reverse PTR), against Cloudflare, Google or Quad9, with the TTL, rcode, header flags and query time behind every answer.",
			URL:  cfg.URL("dns"),
		},
		{
			Name: "IP Tools",
			Desc: "Look up geolocation, ASN, and proxy/VPN for any IP; inspect your own connection (live IPv6 check included); and calculate subnets with the CIDR tool.",
			URL:  cfg.URL("ip"),
		},
		{
			Name: "Link Tools",
			Desc: "Take a URL apart: every query parameter decoded, ordered and typed, with repeated keys, comma-lists and nested encodings made readable; then remove its tracking parameters, follow where it redirects, or compare it with another.",
			URL:  cfg.URL("link"),
		},
		{
			Name: "MCP server",
			Desc: "Every tool here, for AI agents: connect Claude, ChatGPT, Cursor, VS Code, Codex or Gemini by URL and they call the tools directly, free and with no key.",
			URL:  cfg.URL("mcp"),
		},
	}
}

// Register wires apex routes onto e and returns the blog it serves. blogFS =
// posts filesystem (embedded in prod, disk dir in dev — caller builds it via
// platform.SubFS). A malformed post fails Register in prod → main treats it as
// fatal, refusing to boot a broken blog.
func Register(e *echo.Echo, cfg platform.Config, blogFS fs.FS) (*Blog, error) {
	blog, err := NewBlog(blogFS, cfg.IsDev())
	if err != nil {
		return nil, err
	}

	e.GET("/", func(c *echo.Context) error {
		data := map[string]any{
			"Title": "Stas — corpberry.com",
			"Desc":  "Open-source web tools by Stas: Bot check (transparent bot-detection self-test), IP Tools (lookup, reputation, subnet calculator), DNS Tools (records, propagation, email auth) and Link Tools (URL inspection, tracker removal, redirect tracing). One Go binary, no tracking.",
			"Tools": Tools(cfg),
		}
		// No htmx fragment on apex -> same template for page + fragment.
		return platform.Respond(c, http.StatusOK, data, "site/home", "site/home")
	})

	blog.registerRoutes(e, cfg.URL(""))
	// Apex sitemap is dynamic (tracks published posts), so it's wired here
	// where the Blog lives. The tool subdomains' page lists are static and
	// get wired in main.go alongside the vhost map.
	platform.RegisterSEO(e, cfg.URL(""), blog.sitemapPages)
	return blog, nil
}
