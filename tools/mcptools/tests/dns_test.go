package tests

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/google/go-cmp/cmp"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Landver/site-of-tools/tools/dnstools"
)

// failsWith checks an isError result whose text holds want.
func failsWith(t *testing.T, res *mcp.CallToolResult, want string) {
	t.Helper()
	if !res.IsError || res.StructuredContent != nil || !strings.Contains(text(t, res), want) {
		t.Errorf("result = isError %v %.300q, want an error saying %q", res.IsError, text(t, res), want)
	}
}

// rows is the JSON array at key, as objects.
func rows(t *testing.T, obj map[string]any, key string) []map[string]any {
	t.Helper()
	list, ok := obj[key].([]any)
	if !ok {
		t.Fatalf("%s = %T, want an array", key, obj[key])
	}
	out := make([]map[string]any, len(list))
	for i, e := range list {
		if out[i], ok = e.(map[string]any); !ok {
			t.Fatalf("%s[%d] = %T, want an object", key, i, e)
		}
	}
	return out
}

func num(n int) json.Number { return json.Number(strconv.Itoa(n)) }

func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	var names []string
	for _, tool := range listTools(t, cs).Tools {
		names = append(names, tool.Name)
	}
	return names
}

func TestDNSLookup(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/dns", nil, nil)

	// type and resolver omitted: every fan-out type, through the default resolver.
	got := object(t, call(t, cs, "dns_lookup", map[string]any{"name": "https://Example.COM/pricing"}))
	if got["name"] != "example.com" || got["resolver"] != "cloudflare" || got["asked"] != num(len(dnstools.FanoutTypes)) {
		t.Errorf("lookup = %v %v asked %v, want example.com through cloudflare, every fan-out type", got["name"], got["resolver"], got["asked"])
	}
	for _, k := range []string{"zone", "dig"} {
		if _, ok := got[k]; ok {
			t.Errorf("concise result kept %s", k)
		}
	}
	if a := rows(t, got, "found")[0]; a["type"] != "A" || rows(t, a, "records")[0]["as_name"] != "Example Net" {
		t.Errorf("first answer = %v, want A records labelled with their network", a)
	}
	if diff := cmp.Diff([]string{"IP2Location LITE"}, sources(t, got)); diff != "" {
		t.Errorf("attribution (-want +got):\n%s", diff)
	}

	full := object(t, call(t, cs, "dns_lookup", map[string]any{"name": "example.com", "type": "MX", "resolver": "google", "detailed": true}))
	if full["resolver"] != "google" || full["asked"] != num(1) || full["zone"] == nil || len(rows(t, full, "found")) != 1 {
		t.Errorf("detailed MX lookup = %v, want one type through google with its zone text", full)
	}
	if dig, _ := full["dig"].([]any); len(dig) != 1 || !strings.HasSuffix(dig[0].(string), " MX") {
		t.Errorf("dig = %v, want the one MX command", full["dig"])
	}
	if ptr := object(t, call(t, cs, "dns_lookup", map[string]any{"name": "192.0.2.10"})); ptr["reversed"] != true {
		t.Errorf("an IP = %v, want its reverse lookup", ptr)
	}

	failsWith(t, call(t, cs, "dns_lookup", map[string]any{"name": "example.com", "type": "ANY"}), "type")
	failsWith(t, call(t, cs, "dns_lookup", map[string]any{"name": "example.com", "resolver": "8.8.4.4"}), "resolver")
	bad := newStack(t, stackOpts{dns: &fakeDNS{err: dnstools.ErrBadName}}).client(t, "/mcp/dns", nil, nil)
	failsWith(t, call(t, bad, "dns_lookup", map[string]any{"name": "a..b"}), dnstools.ErrBadName.Error())
}

func TestDNSConsistency(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/dns", nil, nil)

	got := object(t, call(t, cs, "dns_consistency", map[string]any{"name": "example.com"}))
	if got["type"] != "A" || len(rows(t, got, "groups")) != 2 || got["ecs"] == nil {
		t.Errorf("type omitted = %v, %d groups, ecs %v; want A, two groups and the steering card", got["type"], len(rows(t, got, "groups")), got["ecs"])
	}
	// Each answering server names its group instead of repeating its values.
	want := map[string]any{"ns1.example.com": num(0), "ns2.example.com": num(0), "ns3.example.com": nil,
		"Cloudflare (1.1.1.1)": num(0), "Google (8.8.8.8)": num(0), "Quad9 (9.9.9.9)": num(1)}
	for _, side := range []string{"authoritative", "resolvers"} {
		for _, srv := range rows(t, got, side) {
			if _, has := srv["values"]; has && srv["group"] != nil {
				t.Errorf("%s carries both its values and a group", srv["label"])
			}
			if srv["group"] != want[srv["label"].(string)] {
				t.Errorf("%s group = %v, want %v", srv["label"], srv["group"], want[srv["label"].(string)])
			}
		}
	}
	if timedOut := rows(t, got, "authoritative")[2]; timedOut["error"] != "i/o timeout" {
		t.Errorf("the server that timed out = %v, want its error kept", timedOut)
	}
	if diff := cmp.Diff([]string{"IP2Location LITE", "rdap.org"}, sources(t, got)); diff != "" {
		t.Errorf("attribution (-want +got):\n%s", diff)
	}

	full := object(t, call(t, cs, "dns_consistency", map[string]any{"name": "example.com", "type": "TXT", "detailed": true}))
	for _, srv := range rows(t, full, "resolvers") {
		if srv["group"] != nil || srv["values"] == nil {
			t.Errorf("detailed %s = %v, want its values and no group", srv["label"], srv)
		}
	}
	if full["ecs"] != nil {
		t.Errorf("TXT got a steering card: %v", full["ecs"])
	}

	failsWith(t, call(t, cs, "dns_consistency", map[string]any{"name": "192.0.2.1"}), dnstools.ErrNeedDomain.Error())
}

func TestDNSTrace(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/dns", nil, nil)
	got := object(t, call(t, cs, "dns_trace", map[string]any{"name": "https://WWW.Example.com/x"}))
	if got["name"] != "www.example.com" || got["type"] != "A" || got["dnssec"] != "insecure" || len(rows(t, got, "hops")) != 2 {
		t.Errorf("trace = %v, want the walk for www.example.com A", got)
	}
	if got["attribution"] != nil {
		t.Errorf("trace credits %v; it reads no licensed data", got["attribution"])
	}
	if aaaa := object(t, call(t, cs, "dns_trace", map[string]any{"name": "example.com", "type": "AAAA"})); aaaa["type"] != "AAAA" {
		t.Errorf("type AAAA = %v", aaaa["type"])
	}
	failsWith(t, call(t, cs, "dns_trace", map[string]any{"name": "192.0.2.1"}), dnstools.ErrNeedDomain.Error())
}

func TestDNSDomainInfo(t *testing.T) {
	cs := newStack(t, stackOpts{dom: upstream{names: 230}.client(t)}).client(t, "/mcp/dns", nil, nil)

	got := object(t, call(t, cs, "dns_domain_info", map[string]any{"name": "www.example.com"}))
	ct := got["certificate_names"].(map[string]any)
	names, _ := ct["names"].([]any)
	if len(names) != 50 || names[0] != "host-000.dev.www.example.com" || ct["total"] != num(230) || ct["truncated"] != true {
		t.Errorf("concise CT = %d names from %v, total %v, truncated %v; want the first 50 names of 230", len(names), names[:1], ct["total"], ct["truncated"])
	}
	if reg := got["registration"].(map[string]any); reg["registrar"] != "Example Registrar, Inc." || got["registrable_domain"] != "example.com" {
		t.Errorf("registration = %v for %v", reg, got["registrable_domain"])
	}
	if diff := cmp.Diff([]string{"crt.sh", "rdap.org"}, sources(t, got)); diff != "" {
		t.Errorf("attribution (-want +got):\n%s", diff)
	}

	full := object(t, call(t, cs, "dns_domain_info", map[string]any{"name": "example.com", "detailed": true}))
	if rows := rows(t, full["certificate_names"].(map[string]any), "names"); len(rows) != 200 || rows[0]["certs"] != num(1) {
		t.Errorf("detailed CT = %d rows, first %v; want 200 with their certificates", len(rows), rows[0])
	}

	// One upstream down still answers; both down is an error, as REST's 502.
	half := newStack(t, stackOpts{dom: upstream{names: 3, ctDown: true}.client(t)}).client(t, "/mcp/dns", nil, nil)
	if got := object(t, call(t, half, "dns_domain_info", map[string]any{"name": "example.com"})); got["registration"] == nil || got["certificate_names_error"] == nil {
		t.Errorf("CT down = %v, want the registration and CT's error", got)
	}
	both := newStack(t, stackOpts{dom: upstream{rdapDown: true, ctDown: true}.client(t)}).client(t, "/mcp/dns", nil, nil)
	failsWith(t, call(t, both, "dns_domain_info", map[string]any{"name": "example.com"}), "certificate transparency")

	failsWith(t, call(t, cs, "dns_domain_info", map[string]any{"name": "1.1.1.1"}), dnstools.ErrNeedDomain.Error())
}

func TestDNSEmailAuth(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/dns", nil, nil)
	got := object(t, call(t, cs, "dns_email_auth", map[string]any{"name": "postmaster@Example.com"}))
	if got["domain"] != "example.com" || got["mx_reputation"] == nil || got["spf"] == nil {
		t.Errorf("email = %v, want example.com with SPF and the mail servers' reputation", got)
	}
	if diff := cmp.Diff([]string{"The Spamhaus Project"}, sources(t, got)); diff != "" {
		t.Errorf("attribution (-want +got):\n%s", diff)
	}
	failsWith(t, call(t, cs, "dns_email_auth", map[string]any{"name": "192.0.2.1"}), dnstools.ErrNeedDomain.Error())
}

// TestDNSToolsNeedTheirDependencies: a check whose dependency is off at boot
// is left out, not served to fail.
func TestDNSToolsNeedTheirDependencies(t *testing.T) {
	s := newStack(t, stackOpts{bare: true, dns: lookOnly{&fakeDNS{}}})
	if diff := cmp.Diff([]string{"dns_lookup"}, toolNames(t, s.client(t, "/mcp/dns", nil, nil))); diff != "" {
		t.Errorf("a Looker without the walk, trace or mail checks and no RDAP/CT client (-want +got):\n%s", diff)
	}
}

// groupServers is dns_consistency's concise projection, restated over the
// REST body: a server whose values are one of groups carries its index.
func groupServers(body map[string]any) {
	groups, _ := body["groups"].([]any)
	for _, side := range []string{"authoritative", "resolvers"} {
		servers, _ := body[side].([]any)
		for _, s := range servers {
			srv := s.(map[string]any)
			vals, _ := srv["values"].([]any)
			i := slices.IndexFunc(groups, func(g any) bool { return cmp.Equal(g.(map[string]any)["values"], srv["values"]) })
			if i >= 0 && len(vals) > 0 {
				delete(srv, "values")
				srv["group"] = num(i)
			}
		}
	}
}

// firstCertNames is dns_domain_info's: the first 50 CT names, names only.
func firstCertNames(body map[string]any) {
	ct := body["certificate_names"].(map[string]any)
	all := ct["names"].([]any)
	names := []any{}
	for _, r := range all[:min(50, len(all))] {
		names = append(names, r.(map[string]any)["name"])
	}
	ct["names"] = names
	delete(ct, "truncated")
	if total, _ := ct["total"].(json.Number).Int64(); int(total) > len(names) {
		ct["truncated"] = true
	}
}

// capped is v as the sanitizer leaves it, for fixtures without invisible
// characters: every string over 2 KB cut on a rune boundary, with a marker.
func capped(v any) any {
	const limit = 2 << 10
	switch t := v.(type) {
	case string:
		if len(t) <= limit {
			return t
		}
		cut := limit
		for !utf8.RuneStart(t[cut]) {
			cut--
		}
		return fmt.Sprintf("%s…[truncated %d bytes]", t[:cut], len(t)-cut)
	case map[string]any:
		for k, e := range t {
			t[k] = capped(e)
		}
	case []any:
		for i, e := range t {
			t[i] = capped(e)
		}
	}
	return v
}

func drop(keys ...string) func(map[string]any) {
	return func(body map[string]any) {
		for _, k := range keys {
			delete(body, k)
		}
	}
}

// TestDNSParity: concise is the REST body through its declared projection,
// detailed is the REST body; both add only attribution.
func TestDNSParity(t *testing.T) {
	s := newStack(t, stackOpts{dns: &fakeDNS{heavy: true}, dom: upstream{names: 230}.client(t)})
	cs := s.client(t, "/mcp", nil, nil)
	cases := []struct {
		tool    string
		args    map[string]any
		rest    string
		project func(map[string]any)
	}{
		{"dns_lookup", map[string]any{"name": "Example.com"}, "/?name=Example.com", drop("zone", "dig")},
		{"dns_lookup", map[string]any{"name": "example.com", "type": "TXT", "resolver": "quad9", "detailed": true}, "/?name=example.com&type=TXT&resolver=quad9", nil},
		{"dns_consistency", map[string]any{"name": "example.com", "type": "TXT"}, "/consistency?name=example.com&type=TXT", groupServers},
		{"dns_consistency", map[string]any{"name": "example.com", "detailed": true}, "/consistency?name=example.com", nil},
		{"dns_trace", map[string]any{"name": "www.example.com", "type": "AAAA"}, "/trace?name=www.example.com&type=AAAA", nil},
		{"dns_domain_info", map[string]any{"name": "www.example.com"}, "/domain?name=www.example.com", firstCertNames},
		{"dns_domain_info", map[string]any{"name": "example.com", "detailed": true}, "/domain?name=example.com", nil},
		{"dns_email_auth", map[string]any{"name": "example.com"}, "/email?name=example.com", nil},
	}
	for _, tc := range cases {
		got := object(t, call(t, cs, tc.tool, tc.args))
		delete(got, "attribution")
		want := s.rest(t, dnsHost, http.MethodGet, tc.rest, "")
		if tc.project != nil {
			tc.project(want)
		}
		if diff := cmp.Diff(capped(want), got); diff != "" {
			t.Errorf("%s %v vs REST %s (-rest +mcp):\n%s", tc.tool, tc.args, tc.rest, diff)
		}
	}
}
