package mailtools

import (
	"bytes"
	"html/template"
	"io"
)

// FragmentTemplates parses the embedded mailtools templates alone for WASM execution.
func FragmentTemplates() (*template.Template, error) {
	return template.New("").Funcs(template.FuncMap{
		"asset":      func(string) string { return "" },
		"apexURL":    func() string { return "" },
		"navTools":   func() []struct{} { return nil },
		"navCatalog": func() []struct{} { return nil },
		"toolURL":    func(sub string) string { return "https://" + sub + ".corpberry.com" },
	}).ParseFS(Templates, "templates/*.html")
}

// RenderDMARC parses a DMARC report and renders the dmarc-result HTML fragment.
func RenderDMARC(t *template.Template, r io.Reader) (string, error) {
	rep, err := ParseDMARCReport(r)
	if err != nil {
		return renderError(t, err), err
	}
	var b bytes.Buffer
	if err := t.ExecuteTemplate(&b, "mail/dmarc-result", map[string]any{"Result": rep}); err != nil {
		return renderError(t, err), err
	}
	return b.String(), nil
}

// RenderBIMI validates an SVG logo and renders the bimi-result HTML fragment.
func RenderBIMI(t *template.Template, rawSVG string) (string, error) {
	val, err := ValidateBIMI(rawSVG)
	if err != nil {
		return renderError(t, err), err
	}
	var b bytes.Buffer
	if err := t.ExecuteTemplate(&b, "mail/bimi-result", map[string]any{"Result": val, "RawSVG": rawSVG}); err != nil {
		return renderError(t, err), err
	}
	return b.String(), nil
}

// RenderARC analyzes an ARC email header trace and renders the arc-result HTML fragment.
func RenderARC(t *template.Template, headers string) (string, error) {
	summary, err := AnalyzeARC(headers)
	if err != nil {
		return renderError(t, err), err
	}
	var b bytes.Buffer
	if err := t.ExecuteTemplate(&b, "mail/arc-result", map[string]any{"Result": summary, "Headers": headers}); err != nil {
		return renderError(t, err), err
	}
	return b.String(), nil
}

func renderError(t *template.Template, err error) string {
	var b bytes.Buffer
	if t != nil && t.ExecuteTemplate(&b, "mail/error", map[string]any{"Error": err.Error()}) == nil {
		return b.String()
	}
	return `<div class="alert-error" role="alert">` + template.HTMLEscapeString(err.Error()) + `</div>`
}
