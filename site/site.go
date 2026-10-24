// Package site serves the apex corpberry.com: landing page, tools index and blog.
package site

import (
	"io/fs"
	"net/http"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
)

// Tools is the one catalog for the apex index and header dropdown; keep it A→Z (a test enforces it).
func Tools(cfg platform.Config) []platform.Tool {
	return []platform.Tool{
		{
			Name: "Bot check",
			Desc: "Score how much your browser looks like a human vs. an automated bot: client fingerprint signals cross-checked against your connection's headers and IP reputation, with a transparent per-signal breakdown.",
			URL:  cfg.URL("botcheck"),
		},
		{
			Name: "Cipher Tools",
			Desc: "Decode, verify and sign JWTs; DPoP (RFC 9449) and PKCE (RFC 7636) generators; hash text or files; HMACs, passwords, keys and certificates. Zero-knowledge in browser WebAssembly.",
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
			Desc: "Take a URL apart, clean tracking tags, and trace redirects hop-by-hop. Analyze HTTP response headers for RFC 9111 caching, dual browser/CDN TTL, and security posture (CSP, HSTS, COOP/COEP).",
			URL:  cfg.URL("link"),
		},
		{
			Name: "Mail Tools",
			Desc: "Zero-knowledge DMARC aggregate report (RUA XML.GZ) visualizer, BIMI SVG Tiny P/S validator and auto-fixer, and ARC authentication trace analyzer.",
			URL:  cfg.URL("mail"),
		},
		{
			Name: "MCP server",
			Desc: "Every tool here, for AI agents: connect Claude, ChatGPT, Cursor, VS Code, Codex or Gemini by URL and they call the tools directly, free and with no key.",
			URL:  cfg.URL("mcp"),
		},
	}
}

// Register wires the apex routes; in prod a malformed post fails it, and main refuses to boot.
func Register(e *echo.Echo, cfg platform.Config, blogFS fs.FS) (*Blog, error) {
	blog, err := NewBlog(blogFS, cfg.IsDev())
	if err != nil {
		return nil, err
	}

	e.GET("/", func(c *echo.Context) error {
		data := map[string]any{
			"Title": "Stas — corpberry.com",
			"Desc":  "Open-source web tools by Stas: Bot check, IP Tools, DNS Tools, Link Tools (URL inspection, tracker removal, HTTP headers cache/security), Mail Tools (DMARC XML/gzip, BIMI SVG, ARC traces), and Cipher Tools (JWT, DPoP, PKCE). One Go binary, no tracking.",
			"Tools": Tools(cfg),
		}
		// No htmx fragment on apex -> same template for page + fragment.
		return platform.Respond(c, http.StatusOK, data, "site/home", "site/home")
	})

	blog.registerRoutes(e, cfg.URL(""))
	// The apex sitemap tracks posts, so it's wired here; the subdomains' static lists are wired in main.go.
	platform.RegisterSEO(e, cfg.URL(""), blog.sitemapPages)
	return blog, nil
}
