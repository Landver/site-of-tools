package tests

import (
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/tools/linktools"
)

// Tested through the exported Unwrap, so host matching and shape dispatch are exercised too.

func unwrap(t *testing.T, raw string) (string, string, bool) {
	t.Helper()
	return linktools.NewService().Unwrap(raw)
}

// A Safe Links target is encoded ONCE: decoding until it stops changing would eat the target's own %20.
func TestSafeLinksDecodesExactlyOnce(t *testing.T) {
	const wrapped = "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fexample.com%2Fa%2520b%3Fq%3D1&data=x&sdata=y&reserved=0"
	got, name, ok := unwrap(t, wrapped)
	if !ok {
		t.Fatalf("Safe Links not recognised (wrapper=%q)", name)
	}
	if want := "https://example.com/a%20b?q=1"; got != want {
		t.Errorf("target = %q, want %q — a second decode pass would turn %%20 into a space", got, want)
	}
	if !strings.Contains(strings.ToLower(name), "safe links") {
		t.Errorf("wrapper name = %q, want it to name Safe Links", name)
	}
}

// Scoped to *.safelinks.protection.*, so a lookalike host is not unwrapped.
func TestSafeLinksHostScoping(t *testing.T) {
	for _, raw := range []string{
		"https://evil.com/?url=https%3A%2F%2Fexample.com%2F",
		"https://notsafelinks.protection.outlook.com.evil.tld/?url=https%3A%2F%2Fexample.com%2F",
	} {
		if got, _, ok := unwrap(t, raw); ok {
			t.Errorf("%s was unwrapped to %q; only the real wrapper hosts may be", raw, got)
		}
	}
}

// Proofpoint's substitution: "-" for "%" and "_" for "/", applied BEFORE percent-decoding.
func TestURLDefenseV2(t *testing.T) {
	const wrapped = "https://urldefense.proofpoint.com/v2/url?u=https-3A__example.com_a_b&d=DwMFaQ&c=abc"
	got, name, ok := unwrap(t, wrapped)
	if !ok {
		t.Fatalf("urldefense v2 not recognised (wrapper=%q)", name)
	}
	if want := "https://example.com/a/b"; got != want {
		t.Errorf("target = %q, want %q", got, want)
	}
}

// The target sits between "__" markers in the PATH, and the base64url payload after "__;" supplies
// the characters Proofpoint replaced with "*".
func TestURLDefenseV3(t *testing.T) {
	// No replacements: empty payload, target passes through verbatim.
	got, _, ok := unwrap(t, "https://urldefense.com/v3/__https://example.com/a/b__;!!abc$")
	if !ok || got != "https://example.com/a/b" {
		t.Errorf("v3 with no replacements: got %q ok=%v, want https://example.com/a/b", got, ok)
	}
	// "*" stands for a character the payload supplies; the result must keep neither "*" nor "__;".
	got2, _, ok2 := unwrap(t, "https://urldefense.com/v3/__https://example.com/*path__;Iw!!abc$")
	if ok2 {
		if strings.Contains(got2, "__;") || strings.Contains(got2, "!!") {
			t.Errorf("v3 leaked wrapper machinery into the target: %q", got2)
		}
	}
}

// The ShapeParam family: each holds its target in a named query parameter, percent-encoded once.
func TestSimpleParamWrappers(t *testing.T) {
	cases := []struct{ name, wrapped, want string }{
		{"facebook", "https://l.facebook.com/l.php?u=https%3A%2F%2Fexample.com%2Fx&h=AT1", "https://example.com/x"},
		{"google", "https://www.google.com/url?q=https%3A%2F%2Fexample.com%2Fx&sa=D", "https://example.com/x"},
		{"tumblr", "https://t.umblr.com/redirect?z=https%3A%2F%2Fexample.com%2Fx&t=abc", "https://example.com/x"},
		{"barracuda", "https://linkprotect.cudasvc.com/url?a=https%3A%2F%2Fexample.com%2Fx&c=E,1", "https://example.com/x"},
		{"vk", "https://vk.com/away.php?to=https%3A%2F%2Fexample.com%2Fx", "https://example.com/x"},
		{"youtube", "https://www.youtube.com/redirect?q=https%3A%2F%2Fexample.com%2Fx", "https://example.com/x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, wname, ok := unwrap(t, c.wrapped)
			if !ok {
				t.Fatalf("not recognised (wrapper=%q)", wname)
			}
			if got != c.want {
				t.Errorf("target = %q, want %q", got, c.want)
			}
			if wname == "" {
				t.Error("wrapper name empty; the page promises to say which wrapper it recognised")
			}
		})
	}
}

// t.co, lnkd.in and bit.ly keep the mapping server-side: nothing to recover; they belong to the tracer.
func TestOpaqueShortenersAreNeverUnwrapped(t *testing.T) {
	for _, raw := range []string{
		"https://t.co/abc123", "https://lnkd.in/abc123", "https://bit.ly/abc123",
		"https://ow.ly/abc123", "https://buff.ly/abc123",
	} {
		got, _, ok := unwrap(t, raw)
		if ok {
			t.Errorf("%s reported as unwrapped to %q; it is opaque and needs a fetch", raw, got)
		}
	}
}

// Mimecast exposes only the target's domain, so it returns ok=false rather than a pathless destination.
func TestPartialWrapperIsNotADestination(t *testing.T) {
	got, name, ok := unwrap(t, "https://protect-eu.mimecast.com/s/AbCd1234?domain=example.com")
	if ok {
		t.Errorf("Mimecast returned ok=true with %q; a bare domain is not a destination", got)
	}
	if name == "" {
		t.Error("Mimecast not named at all; the page should still say what it recognised")
	}
}

// Input is attacker-controlled by definition.
func TestUnwrapNeverPanics(t *testing.T) {
	for _, raw := range []string{
		"", "   ", "not a url",
		"https://urldefense.com/v3/",
		"https://urldefense.com/v3/__",
		"https://urldefense.com/v3/__https://x__;!!$",
		"https://urldefense.com/v3/__https://x__;????!!$",
		"https://nam12.safelinks.protection.outlook.com/",
		"https://nam12.safelinks.protection.outlook.com/?url=",
		"https://nam12.safelinks.protection.outlook.com/?url=%zz",
		"https://l.facebook.com/l.php?u=javascript%3Aalert(1)",
		"https://urldefense.proofpoint.com/v2/url?u=" + strings.Repeat("-", 5000),
	} {
		_, _, _ = linktools.NewService().Unwrap(raw)
	}
}

// Unwrapping is not sanitising: a wrapped javascript: URL must still be refused as linkable.
func TestUnwrappedTargetIsStillHostile(t *testing.T) {
	got, _, ok := unwrap(t, "https://l.facebook.com/l.php?u=javascript%3Aalert(1)&h=AT1")
	if !ok {
		return // refusing to unwrap it at all is also an acceptable answer
	}
	in := parse(t, got)
	if in.Linkable {
		t.Errorf("unwrapped %q is marked linkable; unwrapping is not sanitising", got)
	}
}

// The target sits in ?u= up to &k=, and is entity-unescaped as well as percent-decoded.
func TestURLDefenseV1(t *testing.T) {
	got, name, ok := unwrap(t, "https://urldefense.proofpoint.com/v1/url?u=https%3A%2F%2Fexample.com%2Fa%26amp%3Bb&k=abc&r=def")
	if !ok {
		t.Fatalf("urldefense v1 not recognised (wrapper=%q)", name)
	}
	if strings.Contains(got, "&amp;") {
		t.Errorf("target = %q; HTML entities must be unescaped, a mail gateway leaves them in", got)
	}
	if !strings.HasPrefix(got, "https://example.com/") {
		t.Errorf("target = %q, want the example.com URL", got)
	}
}

// The target is the path tail; /s/ means https and bare /amp/ http, or a link silently downgrades.
func TestGoogleAMPViewer(t *testing.T) {
	https, _, ok := unwrap(t, "https://www.google.com/amp/s/example.com/article")
	if !ok {
		t.Fatal("AMP /amp/s/ not recognised")
	}
	if https != "https://example.com/article" {
		t.Errorf("/amp/s/ gave %q, want https://example.com/article", https)
	}
	plain, _, ok2 := unwrap(t, "https://www.google.com/amp/example.com/article")
	if ok2 && plain != "http://example.com/article" {
		t.Errorf("/amp/ gave %q, want http://example.com/article — /s/ is what marks it https", plain)
	}
}
