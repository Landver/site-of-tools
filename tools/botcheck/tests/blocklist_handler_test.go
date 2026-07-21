package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/shared"
	"github.com/Landver/site-of-tools/tools/botcheck"
	"github.com/Landver/site-of-tools/tools/iptools"
)

// blocklist_handler_test.go covers the ONE seam the domain-rule tests can't
// reach: addServerSignals' BlockLookup→Signals mapping, especially the
// "any non-ipsum source ⇒ IPBlocklistDeliberate" loop that bypasses the ipsum
// confidence floor. blocklist is a concrete *iptools.BlockList (not a fakeable
// interface like Looker), so this drives a live corpus end-to-end through the
// real handler — gated on MONGODB_TEST_URI, mirroring TestCorpusLiveViaHandler.

func liveBlockList(t *testing.T, ctx context.Context) *iptools.BlockList {
	t.Helper()
	uri := os.Getenv("MONGODB_TEST_URI")
	if uri == "" {
		t.Skip("MONGODB_TEST_URI not set; skipping live blocklist handler test")
	}
	// Distinct DB from iptools/tests' "site-of-tools-test": the ip_blocklist
	// collection is now exercised by both packages, and `go test ./...` runs
	// package binaries in parallel — a shared DB would let them drop/seed each
	// other's rows mid-test. Own DB = no cross-package collision.
	m, err := platform.OpenMongo(ctx, uri, "site-of-tools-test-botcheck")
	if err != nil {
		t.Fatalf("open mongo: %v", err)
	}
	db := m.DB()
	if err := db.Collection("ip_blocklist").Drop(ctx); err != nil {
		t.Fatalf("pre-clean: %v", err)
	}
	t.Cleanup(func() { _ = db.Collection("ip_blocklist").Drop(ctx); _ = m.Close(ctx) })
	bl := iptools.NewBlockList(db)
	if err := bl.EnsureIndexes(ctx); err != nil {
		t.Fatalf("ensure indexes: %v", err)
	}
	return bl
}

// TestBlocklistLiveViaHandler proves the handler mapping end-to-end: an
// ipsum-only IP at the floor fires ip_blocklisted (floor path), a deliberate
// non-ipsum ban fires regardless of count (the Deliberate loop bypassing the
// floor), and an unlisted IP stays silent.
func TestBlocklistLiveViaHandler(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	bl := liveBlockList(t, ctx)

	const ipsumIP, deliberateIP, cleanIP = "203.0.113.77", "203.0.113.78", "198.51.100.200"
	// ipsum-only at the floor (count 3 == ipsumBlocklistFloor).
	if err := bl.Upsert(ctx, iptools.BlockEntry{IP: ipsumIP, Source: iptools.BlocklistSourceIPsum, Count: 3}); err != nil {
		t.Fatalf("seed ipsum: %v", err)
	}
	// A deliberate, non-ipsum ban with NO count — fires only if the Deliberate
	// mapping set the bypass; a floor check alone would keep it silent.
	if err := bl.Upsert(ctx, iptools.BlockEntry{IP: deliberateIP, Source: "rate-limiter", Reason: "too many requests"}); err != nil {
		t.Fatalf("seed deliberate: %v", err)
	}

	r := platform.NewRenderer(false, nil,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: botcheck.Templates, DevDir: "tools/botcheck/templates"},
	)
	e := echo.New()
	e.Renderer = r
	botcheck.Register(e, fakeLooker{}, nil, bl)

	fired := func(remoteIP string) bool {
		req := httptest.NewRequest(http.MethodPost, "/check", strings.NewReader(cleanClientBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", chromeMacUA)
		req.RemoteAddr = remoteIP + ":1234"
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST %s: code = %d, want 200", remoteIP, rec.Code)
		}
		var rep botcheck.Report
		if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
			t.Fatalf("POST %s: decode: %v", remoteIP, err)
		}
		return check(t, rep, "ip_blocklisted").Triggered
	}

	if !fired(ipsumIP) {
		t.Errorf("ip_blocklisted should fire for an ipsum-only IP at the floor (count 3)")
	}
	if !fired(deliberateIP) {
		t.Errorf("ip_blocklisted should fire for a deliberate non-ipsum ban regardless of count (Deliberate mapping)")
	}
	if fired(cleanIP) {
		t.Errorf("ip_blocklisted should stay silent for an unlisted IP")
	}
}
