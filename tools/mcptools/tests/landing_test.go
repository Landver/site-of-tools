package tests

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestLandingJSON(t *testing.T) {
	s := newStack(t, stackOpts{owner: offlineOwner(t)})
	rec := s.do(http.MethodGet, "/", "", map[string]string{"Accept": "application/json"})
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d", rec.Code)
	}
	got := decode(t, rec.Body.Bytes())
	if got["name"] != "corpberry" || got["version"] == "" {
		t.Errorf("catalog = %v, want name and version", got)
	}
	var paths []string
	tools := map[string][]string{}
	for _, e := range got["endpoints"].([]any) {
		ep := e.(map[string]any)
		p := ep["path"].(string)
		paths = append(paths, p)
		if ep["url"] != base+p {
			t.Errorf("%s url = %v", p, ep["url"])
		}
		for _, tl := range ep["tools"].([]any) {
			tm := tl.(map[string]any)
			tools[p] = append(tools[p], tm["name"].(string))
			if tm["annotations"] == nil || tm["description"] == "" {
				t.Errorf("%s lacks annotations or a description", tm["name"])
			}
		}
	}
	// The owner's endpoint exists here, but is not advertised.
	if diff := cmp.Diff([]string{"/mcp", "/mcp/ip"}, paths); diff != "" {
		t.Errorf("endpoints (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"ip_cidr", "ip_lookup"}, tools["/mcp/ip"]); diff != "" {
		t.Errorf("/mcp/ip tools (-want +got):\n%s", diff)
	}
}

func TestLandingPage(t *testing.T) {
	s := newStack(t, stackOpts{})
	rec := s.do(http.MethodGet, "/", "", map[string]string{"Accept": "text/html"})
	body := rec.Body.String()
	for _, want := range []string{
		`data-copy="http://mcp.test/mcp"`, `data-copy="http://mcp.test/mcp/ip"`,
		"claude mcp add --scope user --transport http corpberry http://mcp.test/mcp",
		"ip_lookup", "ip_cidr", "IP Tools", `href="http://ip.test"`,
		"IP2Location LITE", "DROP list", "InternetDB", // the footer's credits
	} {
		if !strings.Contains(body, want) {
			t.Errorf("landing page lacks %q", want)
		}
	}
	if rec.Code != http.StatusOK || strings.Contains(body, "/mcp/owner") || strings.Contains(body, "crt.sh") {
		t.Errorf("landing page = %d; it must not advertise the owner endpoint or credit unserved data", rec.Code)
	}
}
