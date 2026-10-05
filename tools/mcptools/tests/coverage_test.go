package tests

import (
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/tools/mcptools"
)

func TestEveryRouteHasAnMCPDecision(t *testing.T) {
	s := newStack(t, stackOpts{owner: offlineOwner(t)})
	routes := map[mcptools.Route]bool{}
	for host, e := range s.hosts {
		sub := strings.TrimSuffix(host, ".test")
		switch host {
		case mcpHost:
			continue
		case apexHost:
			sub = ""
		}
		for _, r := range e.Router().Routes() {
			if !strings.HasPrefix(r.Path, "/static") && r.Path != "/sitemap.xml" && r.Path != "/robots.txt" {
				routes[mcptools.Route{Host: sub, Method: r.Method, Path: r.Path}] = true
			}
		}
	}
	coverage := mcptools.Coverage()
	for r := range routes {
		if _, ok := coverage[r]; !ok {
			t.Errorf("%q %s %s has no MCP decision in mcptools.Coverage", r.Host, r.Method, r.Path)
		}
	}

	listed := map[string]bool{}
	for _, path := range []string{"/mcp", "/mcp/owner"} {
		for _, name := range toolNames(t, s.client(t, path, map[string]string{"CF-Connecting-IP": clientIP, "X-Api-Key": ownerKey})) {
			listed[name] = true
		}
	}
	mapped := 0
	covered := map[string]bool{}
	for r, d := range coverage {
		if !routes[r] {
			t.Errorf("Coverage has %q %s %s, which no Register serves", r.Host, r.Method, r.Path)
		}
		if (len(d.Tools) > 0) == (d.Reason != "") {
			t.Errorf("%s %s: an entry names its tools or its reason, not both", r.Method, r.Path)
		}
		if len(d.Tools) > 0 {
			mapped++
		}
		for _, name := range d.Tools {
			covered[name] = true
			if !listed[name] {
				t.Errorf("%s %s: %s is not served", r.Method, r.Path, name)
			}
		}
	}
	for name := range listed {
		if !covered[name] {
			t.Errorf("%s is served but no REST route maps to it", name)
		}
	}
	if mapped != 41 {
		t.Errorf("%d routes map to tools, want 41", mapped)
	}
}
