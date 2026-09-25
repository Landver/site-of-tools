// Package tests holds linktools' black-box tests: exported API only, per
// CLAUDE.md rule #6. White-box tests that need unexported symbols sit beside the
// code instead (trace_test.go is the one that genuinely does).
package tests

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/Landver/site-of-tools/tools/linktools"
)

// The probe URL the whole research corpus was driven with
// (docs/reports/README.md). Every pathology in one string, so the parser is
// tested against exactly what the competitors were tested against.
const probe = "https://example.com/a/b/../c?cityIdList=95&subdistrictIds=6%2C7%2C8%2C9%2C10%2C11&currencyId=1&rooms=1%2C2&id=1&id=2&debug&q=a+b&x=%2520&bad=%zz&utm_source=test&t=YWJjK2RlZg%3D%3D#frag=1&access_token=abc"

func parse(t *testing.T, raw string) *linktools.Inspection {
	t.Helper()
	in, err := linktools.NewService().Parse(raw)
	if err != nil {
		t.Fatalf("Parse(%q) returned an error: %v", raw, err)
	}
	return in
}

// findParam returns the nth param with the given key (0-indexed among repeats).
func findParam(t *testing.T, in *linktools.Inspection, key string, nth int) linktools.Param {
	t.Helper()
	seen := 0
	for _, p := range in.Params {
		if p.Key != key {
			continue
		}
		if seen == nth {
			return p
		}
		seen++
	}
	t.Fatalf("no param %q (occurrence %d); got %d params", key, nth, len(in.Params))
	return linktools.Param{}
}

// TestProbeURL is the headline case: the example this tool was asked for.
func TestProbeURL(t *testing.T) {
	in := parse(t, probe)

	if got, want := len(in.Params), 12; got != want {
		t.Errorf("param count = %d, want %d", got, want)
	}

	sub := findParam(t, in, "subdistrictIds", 0)
	if diff := cmp.Diff([]string{"6", "7", "8", "9", "10", "11"}, sub.List); diff != "" {
		t.Errorf("subdistrictIds not split into a list (-want +got):\n%s", diff)
	}
	if sub.Delimiter != "," {
		t.Errorf("delimiter = %q, want %q — it must be NAMED, never applied silently", sub.Delimiter, ",")
	}
	if sub.RawValue == "" {
		t.Error("raw value dropped; the raw and decoded forms are shown side by side")
	}
}

// TestOrderPreserved is the test that fails the moment anyone reaches for
// url.ParseQuery, which returns a map and loses the original order.
func TestOrderPreserved(t *testing.T) {
	in := parse(t, "https://example.com/?b=1&a=2&c=3")
	var keys []string
	for _, p := range in.Params {
		keys = append(keys, p.Key)
	}
	if diff := cmp.Diff([]string{"b", "a", "c"}, keys); diff != "" {
		t.Errorf("parameter order not preserved (-want +got):\n%s\nurl.ParseQuery returns a map; this parser must hand-split.", diff)
	}
}

// TestRepeatedKeys: two rows, the second marked. Collapsing to last-wins is what
// every surveyed parser does and it hides a real class of bug.
func TestRepeatedKeys(t *testing.T) {
	in := parse(t, "https://example.com/?id=1&id=2")
	if got := len(in.Params); got != 2 {
		t.Fatalf("got %d params, want 2 — repeats must not be collapsed", got)
	}
	if in.Params[0].Repeat {
		t.Error("first occurrence marked as a repeat")
	}
	if !in.Params[1].Repeat {
		t.Error("second occurrence not marked as a repeat")
	}
	if in.Params[0].Value != "1" || in.Params[1].Value != "2" {
		t.Errorf("values = %q, %q; want 1, 2 — neither may be dropped", in.Params[0].Value, in.Params[1].Value)
	}
}

// TestValuelessVsEmpty: "?debug", "?debug=" and an absent key are three states.
func TestValuelessVsEmpty(t *testing.T) {
	valueless := findParam(t, parse(t, "https://example.com/?debug"), "debug", 0)
	if !valueless.Valueless {
		t.Error("?debug not marked valueless")
	}
	empty := findParam(t, parse(t, "https://example.com/?debug="), "debug", 0)
	if empty.Valueless {
		t.Error("?debug= wrongly marked valueless: it has a value, which is the empty string")
	}
}

// TestMalformedEscape: the raw text survives and a warning is set.
//
// url.QueryUnescape returns the EMPTY STRING plus an error here, so a parser
// that takes its return value blindly turns ?bad=%zz into ?bad=, which looks
// like a real, empty value (docs/reports/go-url-stdlib-behaviour.md §2).
func TestMalformedEscape(t *testing.T) {
	for _, raw := range []string{"https://example.com/?bad=%zz", "https://example.com/?bad=%2"} {
		p := findParam(t, parse(t, raw), "bad", 0)
		if p.Value == "" {
			t.Errorf("%s: value was emptied; the raw text must survive a bad escape", raw)
		}
		if p.Warn == "" {
			t.Errorf("%s: no warning set for a malformed percent-escape", raw)
		}
	}
}

// TestOtherParamsSurviveABadEscape: one broken pair must not cost the rest.
// url.ParseQuery drops the offending pair AND returns an error.
func TestOtherParamsSurviveABadEscape(t *testing.T) {
	in := parse(t, "https://example.com/?a=1&bad=%zz&c=3")
	if got := len(in.Params); got != 3 {
		t.Fatalf("got %d params, want 3 — a malformed escape must not drop its neighbours", got)
	}
}

// TestDoubleEncoding: %2520 -> %20 -> space, shown as rungs.
func TestDoubleEncoding(t *testing.T) {
	p := findParam(t, parse(t, "https://example.com/?x=%2520"), "x", 0)
	if p.Value != "%20" {
		t.Errorf("value = %q, want %q (one layer off)", p.Value, "%20")
	}
	if len(p.Layers) == 0 {
		t.Fatal("no decode ladder for a double-encoded value")
	}
	if got := p.Layers[len(p.Layers)-1].Value; got != " " {
		t.Errorf("ladder bottoms out at %q, want a single space", got)
	}
}

// TestPlusAmbiguity: where a value contains '+' AND looks like base64, both
// readings are offered. calcbe and jsonutilities return opposite answers here
// and neither says so (docs/reports/).
func TestPlusAmbiguity(t *testing.T) {
	p := findParam(t, parse(t, "https://example.com/?t=YWJjK2Rl+mc="), "t", 0)
	if p.AltValue == "" {
		t.Error("no alternate reading offered for a base64-shaped value containing '+'")
	}
	if p.Warn == "" {
		t.Error("no warning naming the '+' ambiguity")
	}
}

// TestUserinfoPhishing: the host is what follows '@', and that must be stated.
func TestUserinfoPhishing(t *testing.T) {
	in := parse(t, "https://paypal.com@evil.tld/login")
	if in.Host != "evil.tld" {
		t.Errorf("host = %q, want evil.tld", in.Host)
	}
	if !hasNote(in.Notes, linktools.SevFail, "Credentials before the host") {
		t.Error("no fail-severity note for userinfo disguising the host")
	}
	if in.HasPass {
		t.Error("HasPass set when no password was present")
	}
}

// TestPasswordNeverEchoed: HasPass is a bool precisely so the value cannot leak.
func TestPasswordNeverEchoed(t *testing.T) {
	in := parse(t, "https://user:hunter2@example.com/")
	if !in.HasPass {
		t.Error("HasPass not set for a URL carrying a password")
	}
	if strings.Contains(in.Canonical, "hunter2") {
		t.Error("password echoed in the canonical form")
	}
}

// TestDangerousSchemeNotLinkable: the Inspect page displays hostile URLs, so
// only http(s) is ever rendered as an anchor.
func TestDangerousSchemeNotLinkable(t *testing.T) {
	for _, raw := range []string{"javascript:alert(1)", "data:text/html,<script>alert(1)</script>", "file:///etc/passwd"} {
		in := parse(t, raw)
		if in.Linkable {
			t.Errorf("%s marked linkable; only http and https may ever be", raw)
		}
	}
	if in := parse(t, "https://example.com/"); !in.Linkable {
		t.Error("https not marked linkable")
	}
}

// TestDotSegments resolves over the escaped path and keeps RFC 3986's trailing
// slash, both of which path.Clean gets wrong.
func TestDotSegments(t *testing.T) {
	in := parse(t, "https://example.com/a/b/../c")
	if !strings.Contains(in.Canonical, "/a/c") {
		t.Errorf("canonical = %q, want the path resolved to /a/c", in.Canonical)
	}
	if !hasNoteTitle(in.Notes, "Path contains . or .. segments") {
		t.Error("dot segments not reported")
	}
}

// TestEncodedSlashIsNotASeparator: %2F inside a segment is a literal slash.
// url.URL.Path has already decoded it, so splitting Path turns one segment into
// two (docs/reports/go-url-stdlib-behaviour.md §5).
func TestEncodedSlashIsNotASeparator(t *testing.T) {
	in := parse(t, "https://example.com/a%2Fb/c")
	if got := len(in.Segments); got != 2 {
		t.Errorf("got %d path segments, want 2 — %%2F is not a separator", got)
	}
}

// TestFragmentParams: every hosted parser surveyed throws the fragment away,
// which hides an OAuth implicit-flow access token completely.
func TestFragmentParams(t *testing.T) {
	in := parse(t, "https://example.com/cb#access_token=secret&state=xyz")
	if len(in.FragParams) != 2 {
		t.Fatalf("got %d fragment params, want 2", len(in.FragParams))
	}
	if in.FragParams[0].Key != "access_token" {
		t.Errorf("first fragment param = %q, want access_token", in.FragParams[0].Key)
	}
	if !hasNote(in.Notes, linktools.SevFail, "Credentials in the fragment") {
		t.Error("no note for a token sitting in the fragment")
	}
}

// TestJWTNeverClaimsVerification. Decoding is not verifying, and the page must
// never imply otherwise.
func TestJWTNeverClaimsVerification(t *testing.T) {
	const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.sig"
	p := findParam(t, parse(t, "https://example.com/?t="+jwt), "t", 0)
	if len(p.Layers) == 0 {
		t.Fatal("JWT not decoded")
	}
	joined := ""
	for _, l := range p.Layers {
		joined += l.Value
	}
	if !strings.Contains(joined, "not verified") {
		t.Error("decoded JWT does not state that the signature was not verified")
	}
}

// TestNestedURLRecognised.
func TestNestedURLRecognised(t *testing.T) {
	p := findParam(t, parse(t, "https://example.com/?u=https%3A%2F%2Finner.example%2F%3Fa%3D1"), "u", 0)
	if p.Kind != linktools.KindURL {
		t.Errorf("kind = %q, want %q", p.Kind, linktools.KindURL)
	}
}

// TestLadderIsBounded: a nested-base64 bomb must stop and SAY it stopped rather
// than truncating silently or running out of memory.
func TestLadderIsBounded(t *testing.T) {
	v := "aGVsbG8gd29ybGQgaGVsbG8gd29ybGQ="
	for i := 0; i < 12; i++ {
		v = b64(v)
	}
	p := findParam(t, parse(t, "https://example.com/?x="+v), "x", 0)
	if len(p.Layers) > 8 {
		t.Errorf("ladder ran to %d rungs; it must be depth-capped", len(p.Layers))
	}
}

// TestGarbageDoesNotPanic. Parse takes attacker-controlled strings by
// definition, so it must fail cleanly rather than crash.
func TestGarbageDoesNotPanic(t *testing.T) {
	for _, raw := range []string{
		"", " ", "not a url at all", "://", "http://", "%", "?a=%", "#", "http://[::1", strings.Repeat("a", 100000),
	} {
		_, _ = linktools.NewService().Parse(raw) // must not panic
	}
}

// TestOversizedInputRejected.
func TestOversizedInputRejected(t *testing.T) {
	if _, err := linktools.NewService().Parse("https://example.com/?x=" + strings.Repeat("a", 200000)); err == nil {
		t.Error("oversized input accepted; Parse is reachable unauthenticated and must be bounded")
	}
}

func hasNote(notes []linktools.Note, sev, title string) bool {
	for _, n := range notes {
		if n.Severity == sev && n.Title == title {
			return true
		}
	}
	return false
}

func hasNoteTitle(notes []linktools.Note, title string) bool {
	for _, n := range notes {
		if n.Title == title {
			return true
		}
	}
	return false
}

// b64 is the ladder-bomb helper: base64 of base64 of base64 ...
func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
