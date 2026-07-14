package platform

import (
	"html/template"
	"io"
	"io/fs"
	"strings"

	"github.com/labstack/echo/v5"
)

// TemplateSource describes one package's templates: its embedded FS (which
// always contains a "templates" dir) and the disk dir to read in dev.
type TemplateSource struct {
	Embed  fs.FS  // e.g. shared.Templates (embeds a "templates" dir)
	DevDir string // disk dir for dev, e.g. "shared/templates"
}

func (s TemplateSource) fsys(dev bool) fs.FS { return SubFS(s.Embed, "templates", s.DevDir, dev) }

// Renderer implements echo.Renderer, parsing templates from several sources
// (shared partials + each project's own templates) into one set. Prod parses
// once; dev re-parses per render so edits show without a rebuild.
type Renderer struct {
	sources []TemplateSource
	dev     bool
	tmpl    *template.Template
}

func NewRenderer(dev bool, sources ...TemplateSource) *Renderer {
	r := &Renderer{sources: sources, dev: dev}
	if !dev {
		r.tmpl = r.parse()
	}
	return r
}

func (r *Renderer) parse() *template.Template {
	t := template.New("")
	for _, s := range r.sources {
		t = parseAll(t, s.fsys(r.dev))
	}
	return t
}

// parseAll walks fsys and parses every .html file (any depth) into t. Templates
// are addressed by their {{define "name"}} names, which must be unique across
// all sources (e.g. "site/home", "ip/index", "partials/head").
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

// prefersHTML reports whether the caller wants HTML: htmx always does, and
// browsers send an Accept header containing text/html. Everything else (curl's
// default */*, an explicit application/json, API clients) gets JSON.
func prefersHTML(c *echo.Context) bool {
	if IsHTMX(c) {
		return true
	}
	return strings.Contains(c.Request().Header.Get("Accept"), "text/html")
}

// WantsJSON is the negation of prefersHTML, so plain `curl` gets JSON for free.
func WantsJSON(c *echo.Context) bool { return !prefersHTML(c) }

// Respond renders one domain result in the representation the caller wants:
// JSON (API/CLI), an HTML fragment (htmx), or a full HTML page (browser). Pass
// the same template name for page and fragment when a feature has no fragment.
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
