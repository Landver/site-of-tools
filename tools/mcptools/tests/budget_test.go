package tests

import (
	"net/http"
	"net/url"
	"testing"
)

// softBudget is a typical result, about 5K tokens; the sanitizer's hard cap is 80 KB.
const softBudget = 20 << 10

// TestConciseResultsFitTheBudget: where the REST body is over the soft budget, concise is not.
func TestConciseResultsFitTheBudget(t *testing.T) {
	s := newStack(t, stackOpts{dns: &fakeDNS{heavy: true}, dom: upstream{names: 230}.client(t)})
	cs := s.client(t, "/mcp", nil, nil)
	letter := newsletter(150)
	for _, tc := range []struct {
		tool                       string
		args                       map[string]any
		host, method, target, form string
	}{
		{"dns_lookup", map[string]any{"name": "example.com"}, dnsHost, http.MethodGet, "/?name=example.com", ""},
		{"dns_consistency", map[string]any{"name": "example.com", "type": "TXT"}, dnsHost, http.MethodGet, "/consistency?name=example.com&type=TXT", ""},
		{"dns_domain_info", map[string]any{"name": "example.com"}, dnsHost, http.MethodGet, "/domain?name=example.com", ""},
		{"link_extract", map[string]any{"text": letter}, linkHost, http.MethodPost, "/extract", "text=" + url.QueryEscape(letter)},
	} {
		res := call(t, cs, tc.tool, tc.args)
		object(t, res)
		hdr := map[string]string{"Host": tc.host, "Accept": "application/json"}
		if tc.form != "" {
			hdr["Content-Type"] = "application/x-www-form-urlencoded"
		}
		concise, rest := len(text(t, res)), s.do(tc.method, tc.target, tc.form, hdr).Body.Len()
		t.Logf("%s: concise %d bytes, REST %d", tc.tool, concise, rest)
		if concise > softBudget {
			t.Errorf("%s concise is %d bytes, over the %d soft budget", tc.tool, concise, softBudget)
		}
		if rest <= softBudget {
			t.Errorf("%s REST body is %d bytes: the fixture is too small to need its projection", tc.tool, rest)
		}
	}
}
