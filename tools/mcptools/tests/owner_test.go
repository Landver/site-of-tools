package tests

import (
	"context"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/linktools"
)

var ownerTools = []string{"link_short_create", "link_short_list", "link_short_revoke"}

func ownerClient(t *testing.T, s *stack, ip string) *mcp.ClientSession {
	t.Helper()
	return s.client(t, "/mcp/owner", map[string]string{"CF-Connecting-IP": ip, "X-Api-Key": ownerKey}, nil)
}

func TestOwnerToolsOnlyWithTheKey(t *testing.T) {
	without := newStack(t, stackOpts{})
	if code := without.do(http.MethodPost, "/mcp/owner", listBody, mcpHeaders(map[string]string{"X-Api-Key": ownerKey})).Code; code != http.StatusNotFound {
		t.Errorf("/mcp/owner without a configured key = %d, want 404", code)
	}

	with := newStack(t, stackOpts{owner: offlineOwner(t)})
	if diff := cmp.Diff(ownerTools, toolNames(t, ownerClient(t, with, clientIP))); diff != "" {
		t.Errorf("/mcp/owner tools (-want +got):\n%s", diff)
	}
	for _, s := range []*stack{without, with} {
		for _, path := range []string{"/mcp", "/mcp/link"} {
			for _, name := range toolNames(t, s.client(t, path, nil, nil)) {
				if slices.Contains(ownerTools, name) {
					t.Errorf("%s serves the owner tool %s", path, name)
				}
			}
		}
	}
}

// TestOwnerToolErrorsOffline: refusals are REST's; a store failure's detail is only logged.
func TestOwnerToolErrorsOffline(t *testing.T) {
	var log syncBuffer
	cs := ownerClient(t, newStack(t, stackOpts{owner: offlineOwner(t), log: &log}), clientIP)
	for _, tc := range []struct {
		tool string
		args map[string]any
		want string
	}{
		{"link_short_create", map[string]any{"url": "javascript:alert(1)"}, "destination URL not allowed"},
		{"link_short_create", map[string]any{"url": "http://192.168.1.1/setup.cgi"}, "not publicly routable"},
		{"link_short_create", map[string]any{"url": "https://example.com/", "ttl": "5s"}, "ttl must be at least 1m"},
		{"link_short_create", map[string]any{"url": "https://example.com/", "ttl": "soon"}, "ttl is not a duration"},
		{"link_short_create", map[string]any{"url": "https://example.com/", "slug": "admin"}, "reserved"},
		{"link_short_create", map[string]any{"slug": "x"}, "url"},
		{"link_short_list", map[string]any{"limit": 51}, "limit"},
		{"link_short_list", map[string]any{"limit": 0}, "limit"},
		{"link_short_revoke", map[string]any{"code": "no such!"}, "No such short link."},
	} {
		failsWith(t, call(t, cs, tc.tool, tc.args), tc.want)
	}

	// Optional arguments omitted get as far as the store, which is down.
	for tool, args := range map[string]map[string]any{
		"link_short_create": {"url": "https://example.com/"},
		"link_short_list":   {},
		"link_short_revoke": {"code": "abc-def"},
	} {
		res := call(t, cs, tool, args)
		failsWith(t, res, "Something went wrong on our side")
		if strings.Contains(text(t, res), "127.0.0.1") {
			t.Errorf("%s answered with the driver's detail: %q", tool, text(t, res))
		}
	}
	if got := log.String(); strings.Count(got, "mcp: link storage error") != 3 {
		t.Errorf("log = %s, want each storage failure logged with its detail", got)
	}
}

var liveMongo = sync.OnceValues(func() (*platform.Mongo, error) {
	return platform.OpenMongo(context.Background(), os.Getenv("MONGODB_TEST_URI"), "site-of-tools-test-mcp")
})

// liveStore is a throwaway database of its own, so it can't race linktools' live tests.
func liveStore(t *testing.T) *linktools.LinkStore {
	t.Helper()
	if os.Getenv("MONGODB_TEST_URI") == "" {
		t.Skip("MONGODB_TEST_URI not set; skipping the live short-link round trip")
	}
	m, err := liveMongo()
	if err != nil {
		t.Fatalf("open mongo: %v", err)
	}
	ctx := context.Background()
	coll := m.DB().Collection("links")
	if err := coll.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = coll.Drop(ctx) })
	store := linktools.NewLinkStore(ctx, m.DB())
	if err := store.IndexError(); err != nil {
		t.Fatalf("unique code index: %v", err)
	}
	return store
}

// TestShortLinksLive: resolving records no hit, following the link over REST
// does; the creator's raw address is stored, never shown.
func TestShortLinksLive(t *testing.T) {
	store := liveStore(t)
	svc := linktools.NewService()
	owner := linktools.NewShortener(store, ownerKey, linkBase)
	owner.CleanTarget = linktools.CleanTargetFunc(svc)
	const restKey, creator = "rest-key", "2001:db8:7:8::42"
	s := newStack(t, stackOpts{owner: owner, short: linktools.NewShortener(store, restKey, linkBase)})
	oc, pub := ownerClient(t, s, creator), s.client(t, "/mcp/link", nil, nil)

	made := object(t, call(t, oc, "link_short_create", map[string]any{"url": "https://example.com/a?utm_source=x&id=1", "clean": true, "note": "mcp"}))
	code, _ := made["code"].(string)
	if made["target"] != "https://example.com/a?id=1" || made["short"] != linkBase+"/s/"+code || made["original"] == nil {
		t.Fatalf("create = %v, want the cleaned target under %s/s/", made, linkBase)
	}
	want := map[string]any{"code": code, "short": made["short"], "target": made["target"]}
	for _, arg := range []string{code, made["short"].(string)} {
		if diff := cmp.Diff(want, object(t, call(t, pub, "link_short_resolve", map[string]any{"code": arg}))); diff != "" {
			t.Errorf("resolve %s (-want +got):\n%s", arg, diff)
		}
	}

	listed := object(t, call(t, oc, "link_short_list", map[string]any{}))
	if rest := s.rest(t, linkHost, http.MethodGet, "/short", ""); rest["links"] != nil {
		t.Errorf("the REST list without its key = %v", rest)
	}
	rec := s.do(http.MethodGet, "/short", "", map[string]string{"Host": linkHost, "Accept": "application/json", "X-Api-Key": restKey})
	if diff := cmp.Diff(decode(t, rec.Body.Bytes())["links"], listed["links"]); diff != "" {
		t.Errorf("link_short_list vs REST GET /short (-rest +mcp):\n%s", diff)
	}
	if txt := text(t, call(t, oc, "link_short_list", map[string]any{"limit": 1})); strings.Contains(txt, creator) || strings.Contains(txt, "created_ip") {
		t.Errorf("the list shows the creator's address: %s", txt)
	}

	if got := s.do(http.MethodGet, "/s/"+code, "", map[string]string{"Host": linkHost}); got.Code != http.StatusFound {
		t.Fatalf("REST redirect = %d", got.Code)
	}
	if diff := cmp.Diff(map[string]any{"status": "revoked", "code": code}, object(t, call(t, oc, "link_short_revoke", map[string]any{"code": code}))); diff != "" {
		t.Errorf("revoke (-want +got):\n%s", diff)
	}
	failsWith(t, call(t, pub, "link_short_resolve", map[string]any{"code": code}), "no such link")

	store.Close() // flushes the hit counter
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	links, err := store.Recent(ctx, 5)
	if err != nil || len(links) != 1 {
		t.Fatalf("recent = %v %v", links, err)
	}
	if links[0].Hits != 1 || links[0].CreatedIP != creator {
		t.Errorf("stored hits %d from %q, want 1 (the REST redirect, not the resolves) from %s", links[0].Hits, links[0].CreatedIP, creator)
	}
}
