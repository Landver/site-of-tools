package tests

import (
	"context"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/linktools"
)

func ownerClient(t *testing.T, s *stack, ip string) *mcp.ClientSession {
	t.Helper()
	return s.client(t, "/mcp/owner", map[string]string{"CF-Connecting-IP": ip, "X-Api-Key": ownerKey})
}

// A store failure's detail can name hosts, so it is logged and never answered.
func TestShortLinkToolsOffline(t *testing.T) {
	var log syncBuffer
	s := newStack(t, stackOpts{owner: offlineOwner(t), log: &log})
	owner, public := ownerClient(t, s, clientIP), s.client(t, "/mcp/link", nil)
	const down = "Something went wrong on our side"
	for _, tc := range []struct {
		cs   *mcp.ClientSession
		tool string
		args map[string]any
		want string
	}{
		{owner, "link_short_create", map[string]any{"url": "javascript:alert(1)"}, "destination URL not allowed"},
		{owner, "link_short_list", map[string]any{"limit": 51}, "limit"},
		{owner, "link_short_revoke", map[string]any{"code": "no such!"}, "No such short link."},
		{public, "link_short_resolve", map[string]any{"code": "no such!"}, "no such link"},
		{owner, "link_short_create", map[string]any{"url": "https://example.com/"}, down},
		{owner, "link_short_list", map[string]any{}, down},
		{owner, "link_short_revoke", map[string]any{"code": "abc-def"}, down},
		{public, "link_short_resolve", map[string]any{"code": "http://link.test/s/abc-def"}, down},
	} {
		res := call(t, tc.cs, tc.tool, tc.args)
		failsWith(t, res, tc.want)
		if strings.Contains(text(t, res), "127.0.0.1") {
			t.Errorf("%s answered with the driver's detail: %q", tc.tool, text(t, res))
		}
	}
	if n := strings.Count(log.String(), "mcp: link storage error"); n != 4 {
		t.Errorf("%d storage errors logged, want 4:\n%s", n, log.String())
	}
}

var liveMongo = sync.OnceValues(func() (*platform.Mongo, error) {
	return platform.OpenMongo(context.Background(), os.Getenv("MONGODB_TEST_URI"), "site-of-tools-test-mcp")
})

// liveDB is a throwaway database of its own, so it can't race the tool packages' live tests.
func liveDB(t *testing.T, coll string) *mongo.Database {
	t.Helper()
	if os.Getenv("MONGODB_TEST_URI") == "" {
		t.Skip("MONGODB_TEST_URI not set")
	}
	m, err := liveMongo()
	if err != nil {
		t.Fatalf("open mongo: %v", err)
	}
	c := m.DB().Collection(coll)
	if err := c.Drop(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Drop(context.Background()) })
	return m.DB()
}

func TestShortLinksLive(t *testing.T) {
	store := linktools.NewLinkStore(context.Background(), liveDB(t, "links"))
	if err := store.IndexError(); err != nil {
		t.Fatalf("unique code index: %v", err)
	}
	owner := linktools.NewShortener(store, ownerKey, linkBase)
	owner.CleanTarget = linktools.CleanTargetFunc(linktools.NewService())
	const restKey, creator = "rest-key", "2001:db8:7:8::42"
	s := newStack(t, stackOpts{owner: owner, short: linktools.NewShortener(store, restKey, linkBase)})
	oc, pub := ownerClient(t, s, creator), s.client(t, "/mcp/link", nil)

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
	rest := decode(t, s.rest(linkHost, "/short", "", map[string]string{"X-Api-Key": restKey}).Body.Bytes())
	if diff := cmp.Diff(rest["links"], listed["links"]); diff != "" {
		t.Errorf("link_short_list vs REST GET /short (-rest +mcp):\n%s", diff)
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
