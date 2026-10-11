package tests

import (
	"net/url"
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

// FragmentTemplates + Render are exactly what wasm/main.go calls: a template failing here fails in every tab.

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

// Errors read in the visitor's terms: no asn1 struct tags, no Go type names, no bare "EOF".
func TestErrorsDontLeakGoInternals(t *testing.T) {
	leaks := []string{"asn1:", "{class:", "Go struct", "Go value", "ciphertools.", "EOF"}
	check := func(name, msg string) {
		t.Helper()
		for _, l := range leaks {
			if strings.Contains(msg, l) {
				t.Errorf("%s: %q leaks %q", name, msg, l)
			}
		}
	}
	stub := func(typ string) string { return "-----BEGIN " + typ + "-----\nAAAA\n-----END " + typ + "-----\n" }
	for name, c := range map[string]struct {
		op     string
		fields url.Values
	}{
		"SPKI":           {"keys-inspect", url.Values{"key": {stub("PUBLIC KEY")}}},
		"PKCS#8":         {"keys-inspect", url.Values{"key": {stub("PRIVATE KEY")}}},
		"PKCS#1":         {"keys-inspect", url.Values{"key": {stub("RSA PRIVATE KEY")}}},
		"SEC 1":          {"keys-inspect", url.Values{"key": {stub("EC PRIVATE KEY")}}},
		"JWK member":     {"keys-inspect", url.Values{"key": {`{"kty":5}`}}},
		"JWKS keys":      {"keys-inspect", url.Values{"key": {`{"keys":5}`}}},
		"JWKS entry":     {"keys-inspect", url.Values{"key": {`{"keys":[5]}`}}},
		"CSR":            {"cert", url.Values{"cert": {stub("CERTIFICATE REQUEST")}}},
		"sign header":    {"jwt-sign", url.Values{"alg": {"HS256"}, "key": {"k"}, "header": {`{"kid":"a"`}}},
		"sign payload":   {"jwt-sign", url.Values{"alg": {"HS256"}, "key": {"k"}, "payload": {`{"sub":`}}},
		"sign JWK":       {"jwt-sign", url.Values{"alg": {"ES256"}, "key": {`{"kty":"EC","crv":5}`}}},
		"decode, header": {"jwt-decode", url.Values{"token": {"eyJhbGciOiJIUzI1NiI.e30.AAAA"}}},
	} {
		_, err := runOp(t, c.op, c.fields, nil)
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		check(name, err.Error())
	}
	// A key that doesn't parse is a verification detail, not an op error.
	j := decode(t, jwtioToken, `{"kty":"oct","k":5}`, "", rfcNow)
	check("verify JWK", j.Verification.Detail)
	j = decode(t, jwtioToken, stub("PUBLIC KEY"), "", rfcNow)
	check("verify PEM", j.Verification.Detail)
}
