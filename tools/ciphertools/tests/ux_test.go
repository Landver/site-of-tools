package tests

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// Markup checks: the page on a phone, to a screen reader, and with JavaScript
// off. Parsed with scripting off, which is how a no-JS browser reads it.

func parseHTML(t *testing.T, s string) *html.Node {
	t.Helper()
	doc, err := html.ParseWithOptions(strings.NewReader(s), html.ParseOptionEnableScripting(false))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func attr(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val, true
		}
	}
	return "", false
}

func hasClass(n *html.Node, class string) bool {
	v, _ := attr(n, "class")
	return slices.Contains(strings.Fields(v), class)
}

// walk calls fn on every element under n, n included.
func walk(n *html.Node, fn func(*html.Node)) {
	if n.Type == html.ElementNode {
		fn(n)
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walk(c, fn)
	}
}

func findAll(n *html.Node, match func(*html.Node) bool) []*html.Node {
	var out []*html.Node
	walk(n, func(e *html.Node) {
		if match(e) {
			out = append(out, e)
		}
	})
	return out
}

func text(n *html.Node) string {
	var b strings.Builder
	var rec func(*html.Node)
	rec = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			rec(c)
		}
	}
	rec(n)
	return strings.Join(strings.Fields(b.String()), " ")
}

// A grid item's minimum width is its content's, and a <pre> that scrolls still
// counts its longest line: one PEM or JWK line then widens the column, and the
// page, past a phone's screen. min-w-0 lets the item shrink so the <pre> scrolls.
func TestScrollingBlocksInGridsCanShrink(t *testing.T) {
	for name, frag := range map[string]string{
		"jwt":  render(t, "jwt-decode", url.Values{"token": {jwtioToken}}),
		"keys": render(t, "keys-generate", url.Values{"type": {"ed25519"}}),
	} {
		grids := findAll(parseHTML(t, frag), func(n *html.Node) bool { return hasClass(n, "grid") })
		if len(grids) == 0 {
			t.Fatalf("%s: no grid in the fragment", name)
		}
		for _, g := range grids {
			for c := g.FirstChild; c != nil; c = c.NextSibling {
				if c.Type != html.ElementNode || hasClass(c, "min-w-0") {
					continue
				}
				pres := findAll(c, func(n *html.Node) bool { return n.Data == "pre" && hasClass(n, "overflow-x-auto") })
				if len(pres) > 0 {
					t.Errorf("%s: grid item <%s> holds a scrolling <pre> but has no min-w-0", name, c.Data)
				}
			}
		}
	}
}

// The TOTP countdown ticks every second inside the result's polite live
// region; a screen reader would read out every tick.
func TestTOTPCountdownIsNotAnnounced(t *testing.T) {
	e := newCipherApp(t)
	body := url.Values{"secret": {"JBSWY3DPEHPK3PXP"}}.Encode()
	rec := do(t, e, http.MethodPost, "/totp", body, form, asBrowser)
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d", rec.Code)
	}
	ticks := findAll(parseHTML(t, rec.Body.String()), func(n *html.Node) bool {
		v, _ := attr(n, "x-text")
		return v == "left"
	})
	if len(ticks) != 1 {
		t.Fatalf("want one countdown, got %d", len(ticks))
	}
	for n := ticks[0]; n != nil; n = n.Parent {
		if v, ok := attr(n, "aria-live"); ok {
			if v != "off" {
				t.Errorf("countdown sits in an aria-live=%q region", v)
			}
			return
		}
	}
}

// Tab buttons only work with Alpine, and without it every panel shows anyway:
// like the page's other JS-only controls, they stay hidden until Alpine runs.
func TestTabButtonsHiddenWithoutJS(t *testing.T) {
	e := newCipherApp(t)
	for _, path := range []string{"/", "/random"} {
		rec := do(t, e, http.MethodGet, path, "", "", asBrowser)
		lists := findAll(parseHTML(t, rec.Body.String()), func(n *html.Node) bool {
			v, _ := attr(n, "role")
			return v == "tablist"
		})
		if len(lists) == 0 {
			t.Fatalf("GET %s: no tablist", path)
		}
		for _, l := range lists {
			if _, ok := attr(l, "x-cloak"); !ok {
				t.Errorf("GET %s: tablist shows without JavaScript, where its buttons do nothing", path)
			}
		}
	}
}

// A no-JS sign posts a signing key; the page that comes back must not copy it
// into the decode form, where the next decode would send it again.
func TestJWTSignKeyStaysInSignForm(t *testing.T) {
	e := newCipherApp(t)
	const secret = "sign-only-secret-0123456789abcdef"
	body := url.Values{"alg": {"HS256"}, "key": {secret}, "payload": {`{"sub":"1"}`}}.Encode()
	rec := do(t, e, http.MethodPost, "/jwt/sign", body, form, asBrowser)
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d: %s", rec.Code, rec.Body)
	}
	for _, f := range findAll(parseHTML(t, rec.Body.String()), func(n *html.Node) bool { return n.Data == "form" }) {
		action, _ := attr(f, "action")
		for _, ta := range findAll(f, func(n *html.Node) bool { v, _ := attr(n, "name"); return n.Data == "textarea" && v == "key" }) {
			got := strings.Contains(text(ta), secret)
			if want := action == "/jwt/sign"; got != want {
				t.Errorf("form %s: key field holds the signing key = %v, want %v", action, got, want)
			}
		}
	}
}

// With JavaScript off the form, file included, goes to the server. A line
// promising the file never leaves the tab, or that a key is made in the
// browser, must say so in the same breath.
func TestBrowserOnlyClaimsHoldWithoutJS(t *testing.T) {
	e := newCipherApp(t)
	for path, claim := range map[string]string{
		"/hash": "never uploaded",
		"/cert": "never uploaded",
		"/keys": "generated in your browser",
	} {
		rec := do(t, e, http.MethodGet, path, "", "", asBrowser)
		ps := findAll(parseHTML(t, rec.Body.String()), func(n *html.Node) bool {
			return n.Data == "p" && strings.Contains(text(n), claim)
		})
		if len(ps) == 0 {
			t.Fatalf("GET %s: no line says %q", path, claim)
		}
		for _, p := range ps {
			if !strings.Contains(text(p), "JavaScript off") {
				t.Errorf("GET %s: %q, with no word on JavaScript off: %s", path, claim, text(p))
			}
		}
	}
}
