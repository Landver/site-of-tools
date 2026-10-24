package platform

import (
	"crypto/sha256"
	"encoding/hex"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"sync"

	"github.com/labstack/echo/v5"
)

// Tool is one entry in the catalog (site.Tools), shown on the apex index and in the header's dropdown.
type Tool struct {
	Name string
	Desc string
	URL  string
}

// navBaseFuncs are fallbacks so any renderer parses with nil funcs (tests); main.go overrides them.
var navBaseFuncs = template.FuncMap{
	"apexURL":    func() string { return "/" },
	"navTools":   func() []Tool { return nil },
	"navCatalog": func() []ToolSection { return defaultCatalog },
	// Origin of a sibling tool, for links that hand off to it.
	"toolURL": func(sub string) string { return "https://" + sub + ".corpberry.com" },
	"asset":   StaticURL,
	"credit":  creditFunc,
}

// StaticURL is the one place the "/static/" prefix is applied, so dev and prod URLs can't diverge.
func StaticURL(p string) string { return "/static/" + strings.TrimPrefix(p, "/") }

// AssetVersioner appends a content hash (?v=) so a deploy busts caches for exactly the changed assets.
func AssetVersioner(static fs.FS) func(string) string {
	var mu sync.Mutex
	cache := map[string]string{}
	return func(p string) string {
		p = strings.TrimPrefix(p, "/")
		mu.Lock()
		defer mu.Unlock()
		if u, ok := cache[p]; ok {
			return u
		}
		u := StaticURL(p)
		if b, err := fs.ReadFile(static, p); err == nil {
			sum := sha256.Sum256(b)
			u += "?v=" + hex.EncodeToString(sum[:4])
		}
		cache[p] = u
		return u
	}
}

// TemplateSource is a package's embedded "templates" dir plus the disk dir read in dev.
type TemplateSource struct {
	Embed  fs.FS  // e.g. shared.Templates (embeds a "templates" dir)
	DevDir string // disk dir for dev, e.g. "shared/templates"
}

func (s TemplateSource) fsys(dev bool) fs.FS { return SubFS(s.Embed, "templates", s.DevDir, dev) }

// Renderer parses every source into one template set: once in prod, on every render in dev.
type Renderer struct {
	sources []TemplateSource
	dev     bool
	funcs   template.FuncMap
	tmpl    *template.Template
}

// NewRenderer: nil funcs fall back to navBaseFuncs' safe defaults.
func NewRenderer(dev bool, funcs template.FuncMap, sources ...TemplateSource) *Renderer {
	r := &Renderer{sources: sources, dev: dev, funcs: funcs}
	if !dev {
		r.tmpl = r.parse()
	}
	return r
}

func (r *Renderer) parse() *template.Template {
	// Base nav funcs first, then caller overrides (Funcs additive; nil=no-op).
	t := template.New("").Funcs(navBaseFuncs).Funcs(r.funcs)
	for _, s := range r.sources {
		t = parseAll(t, s.fsys(r.dev))
	}
	return t
}

// parseAll parses every .html at any depth; {{define}} names must be unique across all sources.
func parseAll(t *template.Template, fsys fs.FS) *template.Template {
	var files []string
	_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".html") {
			files = append(files, p)
		}
		return nil
	})
	if len(files) == 0 {
		return t
	}
	return template.Must(t.ParseFS(fsys, files...))
}

func (r *Renderer) current() *template.Template {
	if r.dev {
		return r.parse()
	}
	return r.tmpl
}

// Render satisfies echo.Renderer (v5 signature: context first).
func (r *Renderer) Render(c *echo.Context, w io.Writer, name string, data any) error {
	return r.current().ExecuteTemplate(w, name, data)
}

// --- content negotiation ---------------------------------------------------

// IsHTMX: a history restore isn't a fragment request, since htmx swaps it in as the whole body.
func IsHTMX(c *echo.Context) bool {
	h := c.Request().Header
	return h.Get("HX-Request") == "true" && h.Get("HX-History-Restore-Request") != "true"
}

// prefersHTML: htmx and browsers (Accept: text/html) get HTML; curl's */* and API clients get JSON.
func prefersHTML(c *echo.Context) bool {
	h := c.Request().Header
	if h.Get("HX-Request") == "true" || h.Get("HX-History-Restore-Request") == "true" {
		return true
	}
	return strings.Contains(h.Get("Accept"), "text/html")
}

// WantsJSON: negation of prefersHTML → plain `curl` gets JSON for free.
func WantsJSON(c *echo.Context) bool { return !prefersHTML(c) }

// SetNegotiationHeaders repeats negotiationHeaders for handlers run without it (tests) and stops htmx
// pushing an error's URL, since partials/htmx-errors swaps errors in as successes.
func SetNegotiationHeaders(c *echo.Context, code int) {
	h := c.Response().Header()
	for _, v := range []string{"Accept", "HX-Request", "HX-History-Restore-Request"} {
		addVary(h, v)
	}
	if IsHTMX(c) {
		h.Set("Cache-Control", "no-store")
		if code >= 400 {
			h.Set("HX-Push-Url", "false")
		}
	}
}

// addVary adds v to the Vary header unless it is already listed.
func addVary(h http.Header, v string) {
	for _, line := range h.Values("Vary") {
		for _, have := range strings.Split(line, ",") {
			if strings.EqualFold(strings.TrimSpace(have), v) {
				return
			}
		}
	}
	h.Add("Vary", v)
}

// Respond picks JSON, htmx fragment or full page; with no fragment, pass the page template for both.
func Respond(c *echo.Context, code int, data any, pageTmpl, fragTmpl string) error {
	SetNegotiationHeaders(c, code)
	switch {
	case WantsJSON(c):
		return c.JSON(code, data)
	case IsHTMX(c):
		return c.Render(code, fragTmpl, data)
	default:
		return c.Render(code, pageTmpl, data)
	}
}

// Reply sends API callers body and pages vm, so page-only fields never reach JSON.
func Reply(c *echo.Context, code int, body any, vm map[string]any, page, frag string) error {
	if WantsJSON(c) {
		return Respond(c, code, body, page, frag)
	}
	return Respond(c, code, vm, page, frag)
}
