package tests

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/Landver/site-of-tools/tools/iptools"
)

// Required arguments only, the least of several, so every optional one takes its default.
var required = map[string]map[string]any{
	"ip_lookup":           {"ip": "8.8.8.8"},
	"ip_cidr":             {"cidr": "192.168.1.0/24"},
	"dns_lookup":          {"name": "example.com"},
	"dns_consistency":     {"name": "example.com"},
	"dns_trace":           {"name": "example.com"},
	"dns_domain_info":     {"name": "example.com"},
	"dns_email_auth":      {"name": "example.com"},
	"link_inspect":        {"url": "https://example.com/?a=1"},
	"link_clean":          {"url": "https://example.com/?utm_source=x&a=1"},
	"link_tracking_rules": {},
	"link_diff":           {"url_a": "https://example.com/?a=1", "url_b": "https://example.com/?a=2"},
	"link_redirect_chain": {"url": "http://127.0.0.1/"},
	"link_curl_parse":     {"command": "curl https://example.com/"},
	"link_curl_build":     {"url": "https://example.com/"},
	"link_extract":        {"text": "see https://example.com/"},
	"link_utm":            {"url": "https://example.com/"},
	"link_percent_encode": {"value": "a b"},

	"cipher_jwt_decode":      {"token": jwtioToken},
	"cipher_jwt_sign":        {"key": signKey},
	"cipher_hash":            {},
	"cipher_hmac":            {},
	"cipher_password_hash":   {},
	"cipher_password_verify": {"hash": hunter2Hash},
	"cipher_encrypt":         {},
	"cipher_keys_generate":   {},
	"cipher_keys_inspect":    {"key": rfcEdKey},
	"cipher_cert":            {"cert": testCert()},
	"cipher_totp":            {"secret": "JBSWY3DPEHPK3PXP"},
	"cipher_random":          {},
	"cipher_encode":          {"text": "abc"},
	"cipher_basic_auth":      {"user": "aladdin"},
	"cipher_identify":        {"text": "abc"},
	"botcheck_score":         {"ip": "8.8.8.8"},
	"site_blog":              {},
}

func TestEveryToolAnswersAnObject(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp", nil)
	for _, name := range toolNames(t, cs) {
		args, ok := required[name]
		if !ok {
			if name != "link_short_resolve" { // needs a store: TestShortLinksLive covers it
				t.Errorf("%s has no entry here", name)
			}
			continue
		}
		object(t, call(t, cs, name, args))
	}
}

// softBudget is about 5K tokens, a typical result; the sanitizer's hard cap is 80 KB.
const softBudget = 20 << 10

// twin is a tool call and the request its REST twin answers it for.
type twin struct {
	tool         string
	args         map[string]any
	host, target string
	body         string // makes it a POST
	hdr          map[string]string
	project      func(map[string]any) // the tool's concise projection, restated over the REST body
	credits      []string
	big          bool // the REST body is over softBudget, so the concise result must project it under
}

func TestToolsAnswerAsTheirRESTTwins(t *testing.T) {
	q := url.QueryEscape
	ip2l, walk := []string{"IP2Location LITE"}, []string{"IP2Location LITE", "rdap.org"}
	domain, ipCredits := []string{"crt.sh", "rdap.org"}, []string{"IP2Location LITE", "The Spamhaus Project", "Shodan InternetDB"}
	const amazon = "https://www.amazon.com/dp/B000?tag=site-20&b=2&a=1"
	const cmd = "curl -X POST -H 'Accept: application/json' -H 'Cookie: s=1' --data 'a=1' 'https://api.example.com/v1/items?x=1'"
	letter := newsletter(150)
	const botIP = "203.0.113.50"
	fp := payload(t)
	fpBody, _ := json.Marshal(fp)
	browser, headers := maps.Clone(chrome), map[string]any{}
	browser["CF-Connecting-IP"] = botIP
	for k, v := range chrome {
		headers[strings.ToLower(strings.ReplaceAll(k, "-", "_"))] = v
	}

	for _, tc := range []twin{
		{tool: "ip_lookup", args: map[string]any{"ip": " 8.8.8.8 "}, host: ipHost, target: "/?ip=8.8.8.8", credits: ipCredits},
		{tool: "ip_cidr", args: map[string]any{"cidr": "2001:db8::/32"}, host: ipHost, target: "/cidr?cidr=2001:db8::/32"},

		{tool: "dns_lookup", args: map[string]any{"name": "Example.com"}, host: dnsHost, target: "/?name=Example.com",
			project: func(b map[string]any) { delete(b, "zone"); delete(b, "dig") }, credits: ip2l, big: true},
		{tool: "dns_lookup", args: map[string]any{"name": "example.com", "type": "TXT", "resolver": "quad9", "detailed": true},
			host: dnsHost, target: "/?name=example.com&type=TXT&resolver=quad9", project: zoneLines, credits: ip2l},
		{tool: "dns_consistency", args: map[string]any{"name": "example.com", "type": "TXT"}, host: dnsHost,
			target: "/consistency?name=example.com&type=TXT", project: groupServers, credits: walk, big: true},
		{tool: "dns_consistency", args: map[string]any{"name": "example.com", "detailed": true}, host: dnsHost,
			target: "/consistency?name=example.com", credits: walk},
		{tool: "dns_trace", args: map[string]any{"name": "https://WWW.Example.com/x", "type": "AAAA"}, host: dnsHost,
			target: "/trace?type=AAAA&name=" + q("https://WWW.Example.com/x")},
		{tool: "dns_domain_info", args: map[string]any{"name": "www.example.com"}, host: dnsHost, target: "/domain?name=www.example.com",
			project: firstCertNames, credits: domain, big: true},
		{tool: "dns_domain_info", args: map[string]any{"name": "example.com", "detailed": true}, host: dnsHost,
			target: "/domain?name=example.com", credits: domain},
		{tool: "dns_email_auth", args: map[string]any{"name": "example.com"}, host: dnsHost, target: "/email?name=example.com",
			credits: []string{"The Spamhaus Project"}},

		{tool: "link_inspect", args: map[string]any{"url": "https://Example.com:443/a/../b?utm_source=x&id=7#frag"}, host: linkHost,
			target: "/?u=" + q("https://Example.com:443/a/../b?utm_source=x&id=7#frag")},
		{tool: "link_clean", args: map[string]any{"url": safeLinks}, host: linkHost, target: "/clean?u=" + q(safeLinks)},
		{tool: "link_clean", args: map[string]any{"url": safeLinks, "unwrap": false, "sort": true}, host: linkHost,
			target: "/clean?unwrap=false&sort=true&u=" + q(safeLinks)},
		{tool: "link_clean", args: map[string]any{"url": amazon, "strip_affiliate": true}, host: linkHost,
			target: "/clean?affiliate=true&u=" + q(amazon)},
		{tool: "link_tracking_rules", args: map[string]any{"full": true}, host: linkHost, target: "/clean/rules"},
		{tool: "link_diff", args: map[string]any{"url_a": "https://example.com/?a=1&b=2", "url_b": "https://EXAMPLE.com/?b=2&a=3"},
			host: linkHost, target: "/diff?a=" + q("https://example.com/?a=1&b=2") + "&b=" + q("https://EXAMPLE.com/?b=2&a=3")},
		{tool: "link_redirect_chain", args: map[string]any{"url": "http://127.0.0.1/admin"}, host: linkHost,
			target: "/trace?u=" + q("http://127.0.0.1/admin")},
		{tool: "link_curl_parse", args: map[string]any{"command": cmd}, host: linkHost, target: "/curl", body: "curl=" + q(cmd)},
		{tool: "link_curl_build", args: map[string]any{"url": "https://example.com/?q=a b", "persona": "googlebot", "follow_redirects": true, "show_headers": true},
			host: linkHost, target: "/curl?ua=googlebot&follow=true&headers=true&u=" + q("https://example.com/?q=a b")},
		{tool: "link_extract", args: map[string]any{"text": letter}, host: linkHost, target: "/extract", body: "text=" + q(letter),
			project: extractConcise, big: true},
		{tool: "link_extract", args: map[string]any{"text": letter, "detailed": true}, host: linkHost, target: "/extract", body: "text=" + q(letter)},
		{tool: "link_utm", args: map[string]any{"url": "https://example.com/?utm_source=old", "utm_source": "News", "utm_campaign": "spring"},
			host: linkHost, target: "/utm?utm_source=News&utm_campaign=spring&u=" + q("https://example.com/?utm_source=old")},
		{tool: "link_percent_encode", args: map[string]any{"value": "a b+c/d%2F"}, host: linkHost, target: "/encode?v=" + q("a b+c/d%2F")},

		{tool: "botcheck_score", args: map[string]any{"http": headers, "ip": botIP, "detailed": true}, host: botHost, target: "/",
			hdr: browser, credits: ipCredits},
		{tool: "botcheck_score", args: map[string]any{"fingerprint": fp, "http": headers, "ip": botIP, "detailed": true}, host: botHost,
			target: "/check", body: string(fpBody), hdr: browser, project: corpusSkipped, credits: ipCredits},
		{tool: "botcheck_score", args: map[string]any{"fingerprint": fp, "http": headers, "ip": botIP}, host: botHost,
			target: "/check", body: string(fpBody), hdr: browser, project: func(b map[string]any) { corpusSkipped(b); firedOnly(b) }, credits: ipCredits},
	} {
		// A stack each, or the RDAP client's request budget runs out.
		s := newStack(t, stackOpts{dns: &fakeDNS{heavy: true}, dom: upstream{names: 230}.client(t),
			chk: fakeChecker{lk: iptools.BlockLookup{Sources: []string{"ipsum"}, MaxCount: 3}}})
		res := call(t, s.client(t, "/mcp", nil), tc.tool, tc.args)
		got := object(t, res)
		if diff := cmp.Diff(tc.credits, sources(got)); diff != "" {
			t.Errorf("%s attribution (-want +got):\n%s", tc.tool, diff)
		}
		rec := s.rest(tc.host, tc.target, tc.body, tc.hdr)
		raw := rec.Body.Bytes()
		if rec.Header().Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(rec.Body)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ = io.ReadAll(zr)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("REST %s%s = %d %s", tc.host, tc.target, rec.Code, raw)
		}
		if tc.big && (len(text(t, res)) > softBudget || len(raw) <= softBudget) {
			t.Errorf("%s: concise %d bytes, REST %d; want REST over the %d soft budget and concise under it",
				tc.tool, len(text(t, res)), len(raw), softBudget)
		}
		want := decode(t, raw)
		if tc.project != nil {
			tc.project(want)
		}
		for _, k := range []string{"attribution", "elapsed_ms"} {
			delete(want, k)
			delete(got, k)
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("%s %.80v vs REST %s (-rest +mcp):\n%s", tc.tool, tc.args, tc.target, diff)
		}
	}
}

func TestBadCallsAreRefused(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp", nil)
	injected := payload(t)
	injected["injected"] = "x"
	const nothing = "Nothing to score: pass fingerprint"
	for _, tc := range []struct {
		tool string
		args map[string]any
		want string
	}{
		{"ip_lookup", map[string]any{"ip": ""}, "minLength"},
		{"dns_lookup", map[string]any{"name": "example.com", "type": "ANY"}, "type"},
		{"cipher_jwt_decode", map[string]any{}, "token"},
		{"cipher_identify", map[string]any{"text": "abc", "nope": 1}, "nope"},
		{"cipher_hash", map[string]any{"text": "abc", "enc": "rot13"}, "enc"},
		{"cipher_random", map[string]any{"kind": "password", "sets": []any{"emoji"}}, "sets"},
		{"cipher_totp", map[string]any{"secret": "JBSWY3DPEHPK3PXP", "digits": 9}, "digits"},
		{"cipher_totp", map[string]any{"secret": "JBSWY3DPEHPK3PXP", "mode": "hotp", "counter": 1 << 53}, "counter"},
		// Signed as written, so a JSON field takes a string, not an object it would reorder.
		{"cipher_jwt_sign", map[string]any{"key": signKey, "payload": map[string]any{"sub": "42"}}, "payload"},

		{"botcheck_score", map[string]any{}, nothing},
		{"botcheck_score", map[string]any{"ip": "  "}, nothing},
		{"botcheck_score", map[string]any{"ip": "not-an-ip"}, `"not-an-ip" is not an IP address`},
		{"botcheck_score", map[string]any{"fingerprint": "v=4"}, "fingerprint"},
		{"botcheck_score", map[string]any{"fingerprint": map[string]any{"webdriver": true}}, "no v version stamp"},
		{"botcheck_score", map[string]any{"fingerprint": injected}, `unknown field "injected"`},

		{"link_inspect", map[string]any{"url": "curl -H 'X: y' https://example.com/"}, "link_curl_parse"},
		{"link_clean", map[string]any{"url": "see https://a.example/ and https://b.example/"}, "link_extract"},
		{"link_short_resolve", map[string]any{"code": "https://bit.ly/abc"}, "link_redirect_chain"},
		{"site_blog", map[string]any{"slug": "unfinished"}, "Call site_blog without a slug"},
	} {
		failsWith(t, call(t, cs, tc.tool, tc.args), tc.want)
	}
	// The largest counter every JSON parser reads exactly.
	object(t, call(t, cs, "cipher_totp", map[string]any{"secret": "JBSWY3DPEHPK3PXP", "mode": "hotp", "counter": 1<<53 - 1}))
}

func TestResultsAreSanitized(t *testing.T) {
	r := richResult
	r.ASName = "Evil\u202eCorp\U000E0041" + strings.Repeat("x", 10<<10)
	cs := newStack(t, stackOpts{geo: &fakeGeo{res: r}}).client(t, "/mcp", nil)
	as := object(t, call(t, cs, "ip_lookup", required["ip_lookup"]))["as_name"].(string)
	if !strings.HasPrefix(as, `Evil\u{202E}Corp\u{E0041}`) || !strings.HasSuffix(as, " bytes]") || len(as) > 2100 {
		t.Errorf("as_name = %.60q…(%d bytes), want visible escapes and a cap with its marker", as, len(as))
	}

	state := strings.Repeat("a", 2500)
	long := "https://example.com/p?state=" + state + "&utm_source=x"
	// These return only the caller's own input, reworked, so nothing in them is cut.
	for tool, args := range map[string]map[string]any{
		"link_clean":          {"url": long},
		"link_utm":            {"url": long, "utm_campaign": "c"},
		"link_curl_build":     {"url": long},
		"link_percent_encode": {"value": state},
		"link_diff":           {"url_a": long, "url_b": "https://example.com/p?state=b"},
		"link_curl_parse":     {"command": "curl '" + long + "'"},
		"cipher_encode":       {"text": state},
	} {
		if txt := text(t, call(t, cs, tool, args)); strings.Contains(txt, "[truncated") || !strings.Contains(txt, state) {
			t.Errorf("%s cut the caller's own %d-byte value: %.120s", tool, len(state), txt)
		}
	}
	for tool, args := range map[string]map[string]any{
		"link_inspect": {"url": long},
		"link_extract": {"text": "see " + long},
	} {
		if txt := text(t, call(t, cs, tool, args)); !strings.Contains(txt, "…[truncated") {
			t.Errorf("%s returned a %d-byte value uncut", tool, len(state))
		}
	}
	res := call(t, cs, "cipher_encode", map[string]any{"text": strings.Repeat("a", 16<<10)})
	failsWith(t, res, "Result too large")
	failsWith(t, res, "Pass less input.")
}
