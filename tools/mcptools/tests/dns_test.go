package tests

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestDNSDomainInfoFailsOnlyWhenBothUpstreamsDo(t *testing.T) {
	half := newStack(t, stackOpts{dom: upstream{names: 3, ctDown: true}.client(t)}).client(t, "/mcp/dns", nil)
	if got := object(t, call(t, half, "dns_domain_info", required["dns_domain_info"])); got["registration"] == nil || got["certificate_names_error"] == nil {
		t.Errorf("CT down = %v, want the registration and CT's error", got)
	}
	both := newStack(t, stackOpts{dom: upstream{rdapDown: true, ctDown: true}.client(t)}).client(t, "/mcp/dns", nil)
	failsWith(t, call(t, both, "dns_domain_info", required["dns_domain_info"]), "certificate transparency")
}

// groupServers: concise dns_consistency names a server's group instead of repeating its values.
func groupServers(body map[string]any) {
	groups, _ := body["groups"].([]any)
	for _, side := range []string{"authoritative", "resolvers"} {
		servers, _ := body[side].([]any)
		for _, s := range servers {
			srv := s.(map[string]any)
			if i := slices.IndexFunc(groups, func(g any) bool { return cmp.Equal(g.(map[string]any)["values"], srv["values"]) }); i >= 0 {
				delete(srv, "values")
				srv["group"] = num(i)
			}
		}
	}
}

func zoneLines(body map[string]any) {
	lines := []any{}
	for _, l := range strings.Split(strings.TrimSuffix(body["zone"].(string), "\n"), "\n") {
		lines = append(lines, l)
	}
	body["zone"] = lines
}

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
