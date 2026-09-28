package tests

import (
	"net/url"
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

// The browser's code path, natively: FragmentTemplates + Render are exactly what
// tools/ciphertools/wasm/main.go calls, so a template that fails here fails in
// every visitor's tab.

func TestFragmentTemplatesParseAndCoverEveryOp(t *testing.T) {
	tpl, err := ciphertools.FragmentTemplates()
	if err != nil {
		t.Fatalf("FragmentTemplates: %v", err)
	}
	if tpl.Lookup(ciphertools.ErrorFragment) == nil {
		t.Fatal("no error fragment")
	}
	for _, op := range ciphertools.Ops() {
		if tpl.Lookup(op.Fragment) == nil {
			t.Errorf("op %s names fragment %q, which no template defines", op.Name, op.Fragment)
		}
	}
}

func render(t *testing.T, op string, fields url.Values) string {
	t.Helper()
	tpl, err := ciphertools.FragmentTemplates()
	if err != nil {
		t.Fatal(err)
	}
	return ciphertools.Render(tpl, op, ciphertools.Input{Fields: fields})
}

func TestRenderJWT(t *testing.T) {
	html := render(t, "jwt-decode", url.Values{"token": {jwtioToken}, "key": {"your-256-bit-secret"}})
	for _, want := range []string{"Signature verified", "John Doe", "Issued at"} {
		if !strings.Contains(html, want) {
			t.Errorf("fragment lacks %q", want)
		}
	}
	if strings.Contains(html, "<!DOCTYPE") {
		t.Error("fragment rendered a whole page")
	}
}

func TestRenderEscapesInput(t *testing.T) {
	tok := token(`{"alg":"HS256"}`, `{"name":"<script>alert(1)</script>"}`, "AAAA")
	html := render(t, "jwt-decode", url.Values{"token": {tok}})
	if strings.Contains(html, "<script>alert") {
		t.Fatal("claim value reached the fragment unescaped")
	}
}

func TestRenderErrorsAreFragments(t *testing.T) {
	for op, fields := range map[string]url.Values{
		"jwt-decode": {"token": {"a.b"}},
		"no-such-op": {},
	} {
		html := render(t, op, fields)
		if !strings.Contains(html, "alert-error") {
			t.Errorf("%s: error not rendered as the error fragment: %s", op, html)
		}
	}
}
