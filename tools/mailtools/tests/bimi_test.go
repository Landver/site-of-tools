package tests

import (
	"encoding/base64"
	"html"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/Landver/site-of-tools/tools/mailtools"
)

const compliantSVG = `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Valid BIMI Logo</title>
  <circle cx="50" cy="50" r="45" fill="#b83266"/>
</svg>`

// failedRules lists the rules a validation failed, in checklist order.
func failedRules(v *mailtools.BIMIValidation) []string {
	var out []string
	for _, f := range v.Findings {
		if f.Severity == "fail" {
			out = append(out, f.Rule)
		}
	}
	return out
}

func TestBIMIValidationAndAutoFix(t *testing.T) {
	val, err := mailtools.ValidateBIMI(compliantSVG)
	if err != nil {
		t.Fatalf("ValidateBIMI failed: %v", err)
	}
	if !val.Compliant || val.FailCount != 0 || val.AutoFixedSVG != "" {
		t.Errorf("expected a compliant logo with nothing to fix, got %+v", val)
	}

	// Scripts, an event handler, no baseProfile/version and a 2:1 canvas without viewBox.
	badSVG := `<svg xmlns="http://www.w3.org/2000/svg" width="200" height="100" onload="alert(1)">
  <script>evil()</script>
  <rect width="200" height="100" fill="blue"/>
</svg>`
	badVal, err := mailtools.ValidateBIMI(badSVG)
	if err != nil {
		t.Fatalf("ValidateBIMI badSVG failed: %v", err)
	}
	wantFailed := []string{"SVG Version 1.2", "SVG Profile Tiny P/S", "Square Aspect Ratio (1:1)", "No Scripts or Embedded Content", "No Inline Event Handlers"}
	if diff := cmp.Diff(wantFailed, failedRules(badVal)); diff != "" {
		t.Errorf("failed rules (-want +got):\n%s", diff)
	}
	if badVal.Compliant || badVal.FailCount != len(wantFailed) {
		t.Errorf("Compliant = %v, FailCount = %d", badVal.Compliant, badVal.FailCount)
	}

	fixed, err := mailtools.AutoFixBIMI(badSVG)
	if err != nil {
		t.Fatalf("AutoFixBIMI failed: %v", err)
	}
	if fixed != badVal.AutoFixedSVG {
		t.Errorf("ValidateBIMI's AutoFixedSVG differs from AutoFixBIMI:\n%s\n%s", badVal.AutoFixedSVG, fixed)
	}
	wantFixed := `<svg xmlns="http://www.w3.org/2000/svg" width="200" height="100" onload="alert(1)" version="1.2" baseProfile="tiny-ps" viewBox="0 -50 200 200">
  <script>evil()</script>
  <rect width="200" height="100" fill="blue"/>
</svg>`
	if diff := cmp.Diff(wantFixed, fixed); diff != "" {
		t.Errorf("fixed SVG (-want +got):\n%s", diff)
	}

	// The root is now compliant; the content violations are the author's to remove.
	fixedVal, err := mailtools.ValidateBIMI(fixed)
	if err != nil {
		t.Fatalf("ValidateBIMI on fixed output failed: %v", err)
	}
	if diff := cmp.Diff([]string{"No Scripts or Embedded Content", "No Inline Event Handlers"}, failedRules(fixedVal)); diff != "" {
		t.Errorf("failed rules after fix (-want +got):\n%s", diff)
	}
	if fixedVal.AutoFixedSVG != "" {
		t.Errorf("nothing fixable should remain, got AutoFixedSVG %q", fixedVal.AutoFixedSVG)
	}
}

func TestAutoFixBIMI_EditsOnlyTheRoot(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{
			name: "keeps the prolog and xlink namespace",
			in: `<?xml version="1.0" encoding="UTF-8"?>
<!-- brand logo -->
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 200 100"><use xlink:href="#a"/></svg>`,
			want: `<?xml version="1.0" encoding="UTF-8"?>
<!-- brand logo -->
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 -50 200 200" version="1.2" baseProfile="tiny-ps"><use xlink:href="#a"/></svg>`,
		},
		{
			name: "adds a missing namespace to a self-closing root",
			in:   `<svg width="10px" height="40"/>`,
			want: `<svg width="10px" height="40" xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="-15 0 40 40"/>`,
		},
		{
			name: "replaces wrong values in place and escapes attributes",
			in:   `<svg version="1.1" baseProfile="full" xmlns="http://example.com/" aria-label="A &amp; B" viewBox="10 10 50 80"><g/></svg>`,
			want: `<svg version="1.2" baseProfile="tiny-ps" xmlns="http://www.w3.org/2000/svg" aria-label="A &amp; B" viewBox="-5 10 80 80"><g/></svg>`,
		},
		{
			name: "falls back to 512 without size information",
			in:   `<svg xmlns="http://www.w3.org/2000/svg" viewBox="junk"><g/></svg>`,
			want: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" version="1.2" baseProfile="tiny-ps"><g/></svg>`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mailtools.AutoFixBIMI(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("(-want +got):\n%s", diff)
			}
			v, err := mailtools.ValidateBIMI(got)
			if err != nil {
				t.Fatal(err)
			}
			if !v.Compliant {
				t.Errorf("fixed output still fails: %v", failedRules(v))
			}
		})
	}
}

func TestValidateBIMI_ContentRules(t *testing.T) {
	const open = `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0,0,100,100">`
	tests := []struct {
		name string
		body string
		want []string
	}{
		{"comma separated viewBox and handler-like text are fine", `<title>click on=here</title>`, nil},
		{"inline event handler", `<rect onclick="x()"/>`, []string{"No Inline Event Handlers"}},
		{"javascript URI", `<a href=" JavaScript:alert(1)"><rect/></a>`, []string{"No JavaScript URIs"}},
		{"remote image", `<image href="https://tracker.example/p.png"/>`, []string{"No External Network Resources"}},
		{"protocol-relative xlink href", `<image xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="//cdn.example/p.png"/>`, []string{"No External Network Resources"}},
		{"remote url() in style", `<rect style="fill:url('https://evil.example/x')"/>`, []string{"No External Network Resources"}},
		{"@import in a style element", `<style>@import "font.css";</style>`, []string{"No External Network Resources"}},
		{"internal references are fine", `<use href="#logo"/><rect fill="url(#grad)"/>`, nil},
		{"forbidden elements", `<script>x()</script><foreignObject/><iframe/><script/>`, []string{"No Scripts or Embedded Content"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := mailtools.ValidateBIMI(open + tt.body + `</svg>`)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, failedRules(v)); diff != "" {
				t.Errorf("failed rules (-want +got):\n%s", diff)
			}
		})
	}

	v, err := mailtools.ValidateBIMI(open + `<script>x()</script><foreignObject/><iframe/></svg>`)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range v.Findings {
		if f.Rule == "No Scripts or Embedded Content" && !strings.HasPrefix(f.Detail, "Found <script>, <foreignObject>, <iframe>.") {
			t.Errorf("forbidden detail = %q", f.Detail)
		}
	}
}

func TestValidateBIMI_Errors(t *testing.T) {
	for _, in := range []string{"", "  \n", "<svg><g></svg>", "<not-svg/>", "<!-- only a comment -->"} {
		if _, err := mailtools.ValidateBIMI(in); err == nil {
			t.Errorf("ValidateBIMI(%q): want error", in)
		}
		if _, err := mailtools.AutoFixBIMI(in); err == nil {
			t.Errorf("AutoFixBIMI(%q): want error", in)
		}
	}
}

func TestBIMIPreviewIsAnImage(t *testing.T) {
	logo := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10" onload="alert(1)"><script>alert(2)</script></svg>`
	v, err := mailtools.ValidateBIMI("  " + logo + "\n")
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString([]byte(logo))
	if v.PreviewBase64 != b64 {
		t.Errorf("PreviewBase64 = %q, want base64 of the trimmed logo", v.PreviewBase64)
	}

	tmpl, err := mailtools.FragmentTemplates()
	if err != nil {
		t.Fatal(err)
	}
	page, err := mailtools.RenderBIMI(tmpl, logo)
	if err != nil {
		t.Fatal(err)
	}
	// The browser decodes entities such as &#43; in attribute values before reading the URI.
	if !strings.Contains(html.UnescapeString(page), `<img src="data:image/svg+xml;base64,`+b64+`"`) {
		t.Errorf("preview is not a data: URI image of the logo:\n%s", page)
	}
	if strings.Contains(page, "<script>alert(2)") || strings.Contains(page, `onload="alert(1)"`) {
		t.Errorf("logo markup leaked into the page:\n%s", page)
	}
}
