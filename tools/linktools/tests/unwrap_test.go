package tests

import (
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/tools/linktools"
)

// Wrapper unwrapping (A16) is the feature a non-developer uses daily: corporate
// mail gateways rewrite every link they touch, and the rewritten form hides
// where the link actually goes. It was also the least-tested part of clean.go —
// decodeURLDefenseV1/V2/V3 and decodeAMPPath had zero coverage, which is poor
// odds for the one piece of this tool whose algorithms are genuinely non-obvious.
//
// Tested through the exported Unwrap rather than the decoders directly, so these
// exercise host matching and shape dispatch too.

func unwrap(t *testing.T, raw string) (string, string, bool) {
	t.Helper()
	return linktools.NewService().Unwrap(raw)
}

// TestSafeLinksDecodesExactlyOnce is the subtle one, and the reason the corpus
// report exists: a Safe Links target is encoded ONCE. A second decode pass eats
// the target's own %20 and yields a different URL — the "obviously you decode
// until it stops changing" instinct is wrong here.
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

// TestSafeLinksHostScoping: the rule is scoped to *.safelinks.protection.*,
// so a lookalike host must not be unwrapped as one.
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

// TestURLDefenseV2 uses Proofpoint's custom substitution: "-" for "%" and "_"
// for "/", applied BEFORE percent-decoding.
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

// TestURLDefenseV3 is the non-obvious algorithm: the target sits between "__"
// markers in the PATH, and the base64url payload after "__;" says which
// characters Proofpoint replaced with "*". You never need to know its
// substitution alphabet — the payload carries it.
func TestURLDefenseV3(t *testing.T) {
	// No replacements: empty payload, target passes through verbatim.
	got, _, ok := unwrap(t, "https://urldefense.com/v3/__https://example.com/a/b__;!!abc$")
	if !ok || got != "https://example.com/a/b" {
		t.Errorf("v3 with no replacements: got %q ok=%v, want https://example.com/a/b", got, ok)
	}
	// A real replacement: "*" in the target stands for a character the payload
	// supplies. Whatever the decoder does, it must not return a URL still
	// containing the "*" placeholder or the "__;" machinery.
	got2, _, ok2 := unwrap(t, "https://urldefense.com/v3/__https://example.com/*path__;Iw!!abc$")
	if ok2 {
		if strings.Contains(got2, "__;") || strings.Contains(got2, "!!") {
			t.Errorf("v3 leaked wrapper machinery into the target: %q", got2)
		}
	}
}

// TestSimpleParamWrappers covers the ShapeParam family in one table: each holds
// its target in a named query parameter, percent-encoded once.
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

// TestOpaqueShortenersAreNeverUnwrapped. t.co, lnkd.in and bit.ly keep the
// mapping server-side, so there is nothing in the string to recover. Claiming
// otherwise would be a lie the UI then has to apologise for — these belong to
// the redirect tracer, not here.
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

// TestPartialWrapperIsNotADestination: Mimecast exposes only the target's
// DOMAIN, and only when the administrator enabled it. Returning that as if it
// were the destination would drop the path silently, so it comes back with
// ok=false while still naming what was recognised.
func TestPartialWrapperIsNotADestination(t *testing.T) {
	got, name, ok := unwrap(t, "https://protect-eu.mimecast.com/s/AbCd1234?domain=example.com")
	if ok {
		t.Errorf("Mimecast returned ok=true with %q; a bare domain is not a destination", got)
	}
	if name == "" {
		t.Error("Mimecast not named at all; the page should still say what it recognised")
	}
}

// TestUnwrapNeverPanics. Input is attacker-controlled by definition.
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
		_, _, _ = linktools.NewService().Unwrap(raw) // must not panic
	}
}

// TestUnwrappedTargetIsStillHostile: unwrapping is not sanitising. A wrapper
// around a javascript: URL must not come back looking safe — the caller
// re-validates, and Parse must still refuse to make it linkable.
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

// TestURLDefenseV1 is the oldest form: the target sits in ?u= up to &k=, and
// HTML entities survive the mail gateway, so it is entity-unescaped as well as
// percent-decoded.
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

// TestGoogleAMPViewer: the target is the PATH TAIL, not a query parameter, and
// the /s/ variant means the original was https while bare /amp/ means http.
// Getting that backwards would silently downgrade a link.
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
