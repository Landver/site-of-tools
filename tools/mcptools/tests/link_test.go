package tests

import (
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/Landver/site-of-tools/tools/linktools"
)

const safeLinks = "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.example.com%2Farticle%3Fid%3D42%26utm_source%3Dnewsletter&data=05%7C02&reserved=0"

// newsletter is a click-tracked HTML email with n stories behind ESP redirects.
func newsletter(n int) string {
	var b strings.Builder
	b.WriteString("<html><body><p>Hi there,</p>")
	for i := range n {
		fmt.Fprintf(&b, `<p><a href="https://u1234567.ct.sendgrid.net/ls/click?upn=%s-%03d&utm_source=newsletter&utm_medium=email&utm_campaign=october">Story %d: what we shipped this week</a></p>`,
			strings.Repeat("u001.Gp2Xz7Q-2BqHk", 8), i, i)
	}
	for range 3 {
		b.WriteString(`<a href="https://example.com/unsubscribe?u=abc123">Unsubscribe</a> <a href="https://example.com/view?id=42">View in browser</a>`)
	}
	b.WriteString("</body></html>")
	return b.String()
}

func TestLinkInspect(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/link", nil, nil)
	got := object(t, call(t, cs, "link_inspect", map[string]any{"url": " https://example.com/p?utm_source=news&id=7 "}))
	params := rows(t, got, "params")
	if got["host"] != "example.com" || len(params) != 2 || !strings.HasPrefix(params[0]["tracking"].(string), "utm_") || params[1]["key"] != "id" {
		t.Errorf("inspect = %v, want example.com with utm_source marked as a tracker", got)
	}
	failsWith(t, call(t, cs, "link_inspect", map[string]any{"url": "curl -H 'X: y' https://example.com/"}), "link_curl_parse")
	failsWith(t, call(t, cs, "link_inspect", map[string]any{"url": "see https://a.example/ and https://b.example/"}), "link_extract")
	failsWith(t, call(t, cs, "link_inspect", map[string]any{"url": ""}), "url")
}

func TestLinkCleanDefaults(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/link", nil, nil)
	clean := func(args map[string]any) map[string]any {
		t.Helper()
		return object(t, call(t, cs, "link_clean", args))
	}
	for name, args := range map[string]map[string]any{
		"omitted": {"url": safeLinks},
		"true":    {"url": safeLinks, "unwrap": true},
	} {
		if got := clean(args); got["output"] != "https://www.example.com/article?id=42" || got["unwrapped"] == nil {
			t.Errorf("unwrap %s = %v, want the destination, unwrapped and cleaned", name, got)
		}
	}
	if got := clean(map[string]any{"url": safeLinks, "unwrap": false}); got["unwrapped"] != nil || !strings.Contains(got["output"].(string), "safelinks") {
		t.Errorf("unwrap false = %v, want the wrapper left in place", got)
	}

	const amazon = "https://www.amazon.com/dp/B000?tag=site-20&b=2&a=1"
	if got := clean(map[string]any{"url": amazon}); !strings.Contains(got["output"].(string), "tag=site-20&b=2&a=1") {
		t.Errorf("affiliate and sort omitted = %v, want the tag and the order kept", got["output"])
	}
	if got := clean(map[string]any{"url": amazon, "strip_affiliate": true, "sort": true}); got["output"] != "https://www.amazon.com/dp/B000?a=1&b=2" {
		t.Errorf("strip_affiliate and sort = %v", got["output"])
	}
	failsWith(t, call(t, cs, "link_clean", map[string]any{"url": "curl https://example.com/"}), "link_curl_parse")
}

func TestLinkTrackingRules(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/link", nil, nil)
	cat := linktools.Rules()

	got := object(t, call(t, cs, "link_tracking_rules", map[string]any{}))
	if got["version"] != cat.Version || got["scope"] != cat.Scope || len(rows(t, got, "tracking")) != len(cat.Tracking) ||
		len(rows(t, got, "never_strip")) != len(cat.NeverStrip) || len(rows(t, got, "wrappers")) != len(cat.Wrappers) || len(cat.Tracking) == 0 {
		t.Errorf("no argument = version %v, %d tracking rules, want the whole table: %s and all %d", got["version"], len(rows(t, got, "tracking")), cat.Version, len(cat.Tracking))
	}
	ref := object(t, call(t, cs, "link_tracking_rules", map[string]any{"param": "REF"}))
	if ref["param"] != "ref" || len(rows(t, ref, "tracking")) == 0 || len(rows(t, ref, "never_strip")) == 0 {
		t.Errorf("param ref = %v, want its host-scoped rules and never-strip entries", ref)
	}
	if hosts := rows(t, ref, "never_strip")[0]["hosts"]; hosts == nil {
		t.Errorf("the never-strip entry for ref lists no hosts")
	}
	failsWith(t, call(t, cs, "link_tracking_rules", map[string]any{"param": "ref", "full": true}), "full")
}

func TestLinkDiff(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/link", nil, nil)
	got := object(t, call(t, cs, "link_diff", map[string]any{"url_a": "https://example.com/?a=1&b=2", "url_b": "https://example.com/?b=2&a=3"}))
	if got["identical"] != false || len(rows(t, got, "params")) == 0 {
		t.Errorf("diff = %v, want a's change found", got)
	}
	failsWith(t, call(t, cs, "link_diff", map[string]any{"url_a": "http://[::1", "url_b": "https://example.com/"}), "URL A: not a valid URL")
	failsWith(t, call(t, cs, "link_diff", map[string]any{"url_a": "https://example.com/", "url_b": "see https://a.example/ and https://b.example/"}),
		"URL B: That looks like text with links in it, not one URL. Pull them out with link_extract.")
	failsWith(t, call(t, cs, "link_diff", map[string]any{"url_a": "https://example.com/"}), "url_b")
}

func TestLinkRedirectChainRefusesOwnHostsAndLoopback(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/link", nil, nil)
	for _, u := range []string{"http://mcp.localhost:8080/mcp", "https://mcp.corpberry.com/mcp", "http://mcp.test/mcp", "http://127.0.0.1/", "http://[::1]/"} {
		got := object(t, call(t, cs, "link_redirect_chain", map[string]any{"url": u}))
		hops := rows(t, got, "hops")
		notes, _ := hops[0]["notes"].([]any)
		if len(hops) != 1 || len(notes) == 0 || notes[0].(map[string]any)["title"] != "Refused before connecting" || got["final"] != nil {
			t.Errorf("%s = %v, want one hop refused before connecting and no destination", u, got)
		}
		if got["persona"] != "browser" {
			t.Errorf("persona omitted = %v, want browser", got["persona"])
		}
	}
	if got := object(t, call(t, cs, "link_redirect_chain", map[string]any{"url": "http://127.0.0.1/", "persona": "googlebot"})); got["persona"] != "googlebot" {
		t.Errorf("persona googlebot = %v", got["persona"])
	}
	failsWith(t, call(t, cs, "link_redirect_chain", map[string]any{"url": "https://example.com/", "persona": "nobody"}), "persona")
	failsWith(t, call(t, cs, "link_redirect_chain", map[string]any{"url": "curl https://example.com/"}), "link_curl_parse")
}

func TestLinkCurl(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/link", nil, nil)
	got := object(t, call(t, cs, "link_curl_parse", map[string]any{
		"command": "curl -X POST -H 'Accept: application/json' --data 'a=1' 'https://api.example.com/v1/items?x=1'",
	}))
	if got["method"] != "POST" || got["method_why"] == "" || got["body_bytes"] != num(3) || got["url"] != "https://api.example.com/v1/items?x=1" ||
		len(rows(t, got, "headers")) != 1 || got["inspection"].(map[string]any)["host"] != "api.example.com" {
		t.Errorf("parse = %v", got)
	}
	failsWith(t, call(t, cs, "link_curl_parse", map[string]any{"command": "curl 'https://example.com/"}), "never closed")
}

func TestLinkExtract(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/link", nil, nil)
	text := newsletter(120)

	got := object(t, call(t, cs, "link_extract", map[string]any{"text": text}))
	urls := rows(t, got, "urls")
	if len(urls) != 30 || got["unique"] != num(122) || got["source"] != "html" {
		t.Errorf("concise = %d rows of %v unique, want the first 30 of 122", len(urls), got["unique"])
	}
	for _, u := range urls {
		if _, ok := u["positions"]; ok {
			t.Fatalf("concise row kept its positions: %v", u)
		}
	}
	notes := rows(t, got, "notes")
	if last := notes[len(notes)-1]; last["title"] != "The first 30 of 122 links" {
		t.Errorf("notes = %v, want one saying the list was cut", notes)
	}

	full := object(t, call(t, cs, "link_extract", map[string]any{"text": text, "detailed": true}))
	if rs := rows(t, full, "urls"); len(rs) != 122 || rs[len(rs)-1]["positions"] != nil {
		t.Errorf("detailed = %d rows, want all 122 without positions", len(rs))
	}
	failsWith(t, call(t, cs, "link_extract", map[string]any{"text": "  \n "}), "no text given")
}

// TestLinkUTMAbsentOrEmptyKeeps: a tag left out or passed empty keeps the URL's own, as on REST.
func TestLinkUTMAbsentOrEmptyKeeps(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/link", nil, nil)
	const tagged = "https://example.com/landing?utm_source=old&utm_medium=email&id=1"
	cases := []struct {
		args map[string]any
		url  string
	}{
		{map[string]any{}, tagged},
		{map[string]any{"utm_source": ""}, tagged},
		{map[string]any{"utm_source": "new"}, "https://example.com/landing?utm_source=new&utm_medium=email&id=1"},
		{map[string]any{"utm_campaign": "spring"}, tagged + "&utm_campaign=spring"},
	}
	for _, tc := range cases {
		args := maps.Clone(tc.args)
		args["url"] = tagged
		if got := object(t, call(t, cs, "link_utm", args)); got["url"] != tc.url {
			t.Errorf("utm %v = %v, want %s", tc.args, got["url"], tc.url)
		}
	}
	replaced := object(t, call(t, cs, "link_utm", map[string]any{"url": tagged, "utm_source": "new"}))
	if tag := rows(t, replaced, "tags")[0]; tag["source"] != linktools.TagReplaced || tag["was"] != "old" {
		t.Errorf("tags = %v, want utm_source replaced, was old", replaced["tags"])
	}
	failsWith(t, call(t, cs, "link_utm", map[string]any{"url": "curl https://example.com/"}), "link_curl_parse")
}

func TestLinkPercentEncode(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/link", nil, nil)
	got := object(t, call(t, cs, "link_percent_encode", map[string]any{"value": "a b+c/d"}))
	if enc := rows(t, got, "encoded"); enc[0]["value"] != "a+b%2Bc%2Fd" || enc[1]["value"] != "a%20b+c%2Fd" {
		t.Errorf("encoded = %v, want query and path rules side by side", enc)
	}
	failsWith(t, call(t, cs, "link_percent_encode", map[string]any{"value": ""}), "value")
}

// TestLinkWholeStrings: a tool reworking only the caller's input returns it uncut.
func TestLinkWholeStrings(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/link", nil, nil)
	state := strings.Repeat("a", 2500)
	long := "https://example.com/p?state=" + state + "&utm_source=x"
	for tool, args := range map[string]map[string]any{
		"link_clean":          {"url": long},
		"link_utm":            {"url": long, "utm_campaign": "c"},
		"link_percent_encode": {"value": state},
		"link_diff":           {"url_a": long, "url_b": "https://example.com/p?state=b"},
		"link_curl_parse":     {"command": "curl '" + long + "'"},
		"link_inspect":        {"url": long},
		"link_extract":        {"text": "see " + long},
	} {
		if txt := text(t, call(t, cs, tool, args)); !strings.Contains(txt, state) {
			t.Errorf("%s cut the caller's own %d-byte value: %.120s", tool, len(state), txt)
		}
	}
}

// TestLinkShortResolveOffline: refusals before the store; owner_test.go has the live trip.
func TestLinkShortResolveOffline(t *testing.T) {
	var log syncBuffer
	cs := newStack(t, stackOpts{log: &log}).client(t, "/mcp/link", nil, nil)
	for _, code := range []string{"https://bit.ly/abc", "link.test/clean", "http://link.test/x/abc", "no such!"} {
		failsWith(t, call(t, cs, "link_short_resolve", map[string]any{"code": code}), "Not a corpberry.com short link")
	}
	res := call(t, cs, "link_short_resolve", map[string]any{"code": "http://link.test/s/abc-def"})
	failsWith(t, res, "Something went wrong on our side")
	if !strings.Contains(log.String(), "mcp: link storage error") || strings.Contains(text(t, res), "127.0.0.1") {
		t.Errorf("a storage failure must be logged with its detail and answered without it: %q", text(t, res))
	}
}

func TestLinkToolsNeedTheirDependencies(t *testing.T) {
	cs := newStack(t, stackOpts{bare: true, link: linktools.NewService()}).client(t, "/mcp/link", nil, nil)
	for _, name := range toolNames(t, cs) {
		if name == "link_redirect_chain" || name == "link_headers_inspect" || name == "link_short_resolve" {
			t.Errorf("%s is listed without its tracer or short-link store", name)
		}
	}
	if n := len(toolNames(t, cs)); n != 9 {
		t.Errorf("%d link tools without a tracer and a store, want the 9 that need neither", n)
	}
}

// extractDetailed and extractConcise are link_extract's projections of the REST body, restated.
func extractDetailed(body map[string]any) {
	for _, u := range body["urls"].([]any) {
		delete(u.(map[string]any), "positions")
	}
}

func extractConcise(body map[string]any) {
	extractDetailed(body)
	if urls := body["urls"].([]any); len(urls) > 30 {
		body["urls"] = urls[:30]
		notes, _ := body["notes"].([]any)
		body["notes"] = append(notes, map[string]any{"severity": "info",
			"title": fmt.Sprintf("The first 30 of %d links", len(urls)), "detail": "Pass detailed: true for all of them."})
	}
}

// TestLinkParity: every public link tool against its REST twin; timings are left out.
func TestLinkParity(t *testing.T) {
	s := newStack(t, stackOpts{})
	cs := s.client(t, "/mcp", nil, nil)
	q := url.QueryEscape
	letter := newsletter(80)
	const cmd = "curl -X POST -H 'Accept: application/json' -H 'Cookie: s=1' --data 'a=1' 'https://api.example.com/v1/items?x=1'"
	const pasted = "HTTP/2 200\ncache-control: public, max-age=3600\nset-cookie: sid=1; Secure\nstrict-transport-security: max-age=31536000"
	cases := []struct {
		tool                 string
		args                 map[string]any
		method, target, form string
		project              func(map[string]any)
	}{
		{"link_inspect", map[string]any{"url": "https://Example.com:443/a/../b?utm_source=x&id=7#frag"}, http.MethodGet, "/?u=" + q("https://Example.com:443/a/../b?utm_source=x&id=7#frag"), "", nil},
		{"link_clean", map[string]any{"url": safeLinks}, http.MethodGet, "/clean?u=" + q(safeLinks), "", nil},
		{"link_clean", map[string]any{"url": safeLinks, "unwrap": false, "strip_affiliate": true, "sort": true}, http.MethodGet, "/clean?unwrap=false&affiliate=true&sort=true&u=" + q(safeLinks), "", nil},
		{"link_tracking_rules", map[string]any{}, http.MethodGet, "/clean/rules", "", nil},
		{"link_diff", map[string]any{"url_a": "https://example.com/?a=1&b=2", "url_b": "https://EXAMPLE.com/?b=2&a=3"}, http.MethodGet, "/diff?a=" + q("https://example.com/?a=1&b=2") + "&b=" + q("https://EXAMPLE.com/?b=2&a=3"), "", nil},
		{"link_redirect_chain", map[string]any{"url": "http://127.0.0.1/admin"}, http.MethodGet, "/trace?u=" + q("http://127.0.0.1/admin"), "", nil},
		{"link_curl_parse", map[string]any{"command": cmd}, http.MethodPost, "/curl", "curl=" + q(cmd), nil},
		{"link_extract", map[string]any{"text": letter}, http.MethodPost, "/extract", "text=" + q(letter), extractConcise},
		{"link_extract", map[string]any{"text": letter, "detailed": true}, http.MethodPost, "/extract", "text=" + q(letter), extractDetailed},
		{"link_headers_parse", map[string]any{"headers": pasted}, http.MethodPost, "/headers", "headers=" + q(pasted), nil},
		{"link_utm", map[string]any{"url": "https://example.com/?utm_source=old", "utm_source": "News", "utm_campaign": "spring"}, http.MethodGet, "/utm?utm_source=News&utm_campaign=spring&u=" + q("https://example.com/?utm_source=old"), "", nil},
		{"link_percent_encode", map[string]any{"value": "a b+c/d%2F"}, http.MethodGet, "/encode?v=" + q("a b+c/d%2F"), "", nil},
	}
	for _, tc := range cases {
		got := object(t, call(t, cs, tc.tool, tc.args))
		want := s.rest(t, linkHost, tc.method, tc.target, tc.form)
		if tc.project != nil {
			tc.project(want)
		}
		delete(got, "elapsed_ms")
		delete(want, "elapsed_ms")
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("%s %.80v vs REST %s (-rest +mcp):\n%s", tc.tool, tc.args, tc.target, diff)
		}
	}
}

func TestLinkHeadersParse(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp", nil, nil)
	rawHeaders := "HTTP/2 200 OK\n" +
		"content-type: text/html\n" +
		"cache-control: public, max-age=3600, s-maxage=7200\n" +
		"cdn-cache-control: max-age=86400\n" +
		"cross-origin-opener-policy: same-origin\n" +
		"cross-origin-embedder-policy: require-corp\n" +
		"set-cookie: __Host-id=secret123; Secure; Path=/\n"

	res := object(t, call(t, cs, "link_headers_parse", map[string]any{"headers": rawHeaders}))
	if fmt.Sprint(res["status_code"]) != "200" {
		t.Errorf("status code: want 200, got %v", res["status_code"])
	}
	ttl := res["cache"].(map[string]any)["ttl"].(map[string]any)
	if fmt.Sprint(ttl["browser_ttl_seconds"]) != "3600" || fmt.Sprint(ttl["edge_ttl_seconds"]) != "86400" {
		t.Errorf("TTL mismatch: browser=%v, edge=%v", ttl["browser_ttl_seconds"], ttl["edge_ttl_seconds"])
	}
	if iso := res["security"].(map[string]any)["isolation"].(map[string]any); iso["isolated"] != true {
		t.Errorf("expected cross-origin isolated: true")
	}
	failsWith(t, call(t, cs, "link_headers_parse", map[string]any{}), "headers")
}

// TestLinkHeadersInspect: refusals before any request; linktools' white-box tests drive a real fetch.
func TestLinkHeadersInspect(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp", nil, nil)
	for _, u := range []string{"http://mcp.test/mcp", "https://link.corpberry.com/", "http://127.0.0.1/", "http://[::1]/"} {
		failsWith(t, call(t, cs, "link_headers_inspect", map[string]any{"url": u}), "never contacted")
	}
	failsWith(t, call(t, cs, "link_headers_inspect", map[string]any{"url": "https://example.com:8443/"}), "only ports 80 and 443")
	failsWith(t, call(t, cs, "link_headers_inspect", map[string]any{}), "url")
	failsWith(t, call(t, cs, "link_headers_inspect", map[string]any{"url": "curl https://example.com"}), "Take it apart with link_curl_parse")
	failsWith(t, call(t, cs, "link_headers_inspect", map[string]any{"url": "https://example.com/", "persona": "nobody"}), "persona")
}
