package platform

import (
	"crypto/sha256"
	"encoding/hex"
	"html/template"
	"io"
	"io/fs"
	"strings"
	"sync"

	"github.com/labstack/echo/v5"
)

// Tool: one entry in site's tool catalog — rendered in apex tools index +
// header's Tools dropdown. Lives here (base package everyone imports) →
// renderer + each feature share one type. Actual catalog: single func,
// site.Tools.
type Tool struct {
	Name string
	Desc string
	URL  string
}

// navBaseFuncs: safe fallbacks for template funcs shared header calls → any
// renderer parses even w/ nil funcs (e.g. tests). main.go overrides w/
// config-aware versions.
var navBaseFuncs = template.FuncMap{
	"apexURL":  func() string { return "/" },
	"navTools": func() []Tool { return nil },
	// Unversioned fallback → templates calling {{asset ...}} parse+render w/
	// nil funcs (tests). main.go overrides w/ content-hash version.
	"asset": StaticURL,
}

// StaticURL maps a static asset path (relative to static root, e.g.
// "js/botcheck.js") to its public URL under /static, tolerating an optional
// leading slash. Single place "/static/" prefix gets applied — shared by
// nil-funcs fallback above, dev asset helper in main, AssetVersioner's
// fallback → dev + prod can't diverge on prefix.
func StaticURL(p string) string { return "/static/" + strings.TrimPrefix(p, "/") }

// AssetVersioner returns a template helper mapping a static asset path
// (relative to static root, e.g. "js/botcheck.js") to its public URL w/
// content-hash cache-buster, e.g. "/static/js/botcheck.js?v=1a2b3c4d". Hash
// changes only when file bytes change → deploy invalidates CDN/browser
// cache for exactly the assets that changed — no stale max-age wait, no
// manual purge. Results memoised; read error falls back to unversioned URL.
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

// TemplateSource describes one package's templates: embedded FS (always
// contains a "templates" dir) + disk dir to read in dev.
type TemplateSource struct {
	Embed  fs.FS  // e.g. shared.Templates (embeds a "templates" dir)
	DevDir string // disk dir for dev, e.g. "shared/templates"
}

func (s TemplateSource) fsys(dev bool) fs.FS { return SubFS(s.Embed, "templates", s.DevDir, dev) }

// Renderer implements echo.Renderer, parses templates from several sources
// (shared partials + each project's own templates) into one set. Prod
// parses once; dev re-parses per render → edits show w/o rebuild.
type Renderer struct {
	sources []TemplateSource
	dev     bool
	funcs   template.FuncMap
	tmpl    *template.Template
}

// NewRenderer builds the renderer. funcs: template functions available to
// every template (e.g. shared header's apexURL/navTools). Pass nil for
// none → shared nav funcs fall back to safe defaults (see navBaseFuncs).
func NewRenderer(dev bool, funcs template.FuncMap, sources ...TemplateSource) *Renderer {
	r := &Renderer{sources: sources, dev: dev, funcs: funcs}
	if !dev {
		r.tmpl = r.parse()
	}
	return r
}

func (r *Renderer) parse() *template.Template {
	// Base nav funcs first, then caller overrides (Funcs additive; nil = no-op).
	t := template.New("").Funcs(navBaseFuncs).Funcs(r.funcs)
	for _, s := range r.sources {
		t = parseAll(t, s.fsys(r.dev))
	}
	return t
}

// parseAll walks fsys, parses every .html file (any depth) into t. Templates
// addressed by their {{define "name"}} names → must be unique across all
// sources (e.g. "site/home", "ip/index", "partials/head").
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

// IsHTMX reports whether the request came from htmx (wants an HTML fragment).
func IsHTMX(c *echo.Context) bool {
	return c.Request().Header.Get("HX-Request") == "true"
}

// prefersHTML reports whether the caller wants HTML: htmx always does,
// browsers send an Accept header containing text/html. Everything else
// (curl's default */*, explicit application/json, API clients) gets JSON.
func prefersHTML(c *echo.Context) bool {
	if IsHTMX(c) {
		return true
	}
	return strings.Contains(c.Request().Header.Get("Accept"), "text/html")
}

// WantsJSON: negation of prefersHTML → plain `curl` gets JSON for free.
func WantsJSON(c *echo.Context) bool { return !prefersHTML(c) }

// Respond renders one domain result in the representation the caller wants:
// JSON (API/CLI), an HTML fragment (htmx), or a full HTML page (browser).
// Pass same template name for page + fragment when a feature has no fragment.
func Respond(c *echo.Context, code int, data any, pageTmpl, fragTmpl string) error {
	switch {
	case WantsJSON(c):
		return c.JSON(code, data)
	case IsHTMX(c):
		return c.Render(code, fragTmpl, data)
	default:
		return c.Render(code, pageTmpl, data)
	}
}
