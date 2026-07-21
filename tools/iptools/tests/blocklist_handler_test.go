package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/shared"
	"github.com/Landver/site-of-tools/tools/iptools"
)

// blocklist_handler_test.go covers the IP tool's G37 enrichment: the "proxy /
// blocklist / network" card + the JSON blocklist field, and the handler wiring
// that queries the shared corpus for the LOOKED-UP ip.

// TestHandlerShowsBlocklistSection is offline: a fakeLooker returns a Result
// with Blocklist pre-set (the handler leaves it untouched when bl is nil, as
// newTestApp registers), so this exercises the template + JSON marshal without
// Mongo — the main risk surface.
func TestHandlerShowsBlocklistSection(t *testing.T) {
	res := &iptools.Result{
		IP:        "1.2.3.4",
		Blocklist: &iptools.BlockLookup{Sources: []string{"ipsum", "rate-limiter"}, MaxCount: 8},
	}

	// HTML: renamed card + a blocklist row naming the sources and count.
	rec := do(newTestApp(fakeLooker{res: res}), "/?ip=1.2.3.4", map[string]string{"Accept": "text/html"})
	body := rec.Body.String()
	for _, want := range []string{"proxy / blocklist / network", "Blocklist", "ipsum, rate-limiter", "8 lists"} {
		if !strings.Contains(body, want) {
			t.Errorf("blocklist card missing %q in:\n%s", want, body)
		}
	}

	// JSON: nested blocklist object.
	recj := do(newTestApp(fakeLooker{res: res}), "/?ip=1.2.3.4", map[string]string{"Accept": "application/json"})
	jb := strings.ReplaceAll(recj.Body.String(), " ", "")
	if !strings.Contains(jb, `"blocklist":{`) || !strings.Contains(jb, `"max_count":8`) {
		t.Errorf("json missing blocklist object: %s", recj.Body.String())
	}
}

// TestHandlerCleanIPShowsBlocklistNo: a Result with a checked-but-empty
// Blocklist (non-nil, no sources) renders the card with a "No" row — the
// "we checked, it's clean" state, distinct from "not checked" (nil → no row).
func TestHandlerCleanIPShowsBlocklistNo(t *testing.T) {
	res := &iptools.Result{IP: "8.8.8.8", Blocklist: &iptools.BlockLookup{}}
	rec := do(newTestApp(fakeLooker{res: res}), "/?ip=8.8.8.8", map[string]string{"Accept": "text/html"})
	body := rec.Body.String()
	if !strings.Contains(body, "proxy / blocklist / network") ||
		!strings.Contains(body, "not on any threat / abuse blocklist") {
		t.Errorf("clean-IP blocklist card should render a No row, got:\n%s", body)
	}
}

// TestHandlerEnrichesBlocklistLive drives the real handler against real Mongo:
// a seeded IP flows through addServerSignals-equivalent enrichment (Check on the
// looked-up ip) into Result.Blocklist. Gated on MONGODB_TEST_URI. Reuses
// liveBlockListDB from blocklist_test.go (same package).
func TestHandlerEnrichesBlocklistLive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	bl, _ := liveBlockListDB(t, ctx)

	const ip = "203.0.113.90"
	if err := bl.Upsert(ctx, iptools.BlockEntry{IP: ip, Source: iptools.BlocklistSourceIPsum, Count: 6}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	r := platform.NewRenderer(false, nil,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: iptools.Templates, DevDir: "tools/iptools/templates"},
	)
	e := echo.New()
	e.Renderer = r
	// fakeLooker returns a bare Result for ip; the handler enriches Blocklist
	// from the live corpus, keyed on that same ip.
	iptools.Register(e, fakeLooker{res: &iptools.Result{IP: ip}}, nil, bl)

	rec := do(e, "/?ip="+ip, map[string]string{"Accept": "application/json"})
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	var got iptools.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Blocklist == nil || !got.Blocklist.Listed() || got.Blocklist.MaxCount != 6 {
		t.Errorf("handler should enrich Blocklist from the corpus for the looked-up IP, got %+v", got.Blocklist)
	}

	// An unlisted IP is checked and comes back clean (non-nil, not listed).
	rec = do(e, "/?ip=198.51.100.222", map[string]string{"Accept": "application/json"})
	var clean iptools.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &clean); err != nil {
		t.Fatalf("decode clean: %v", err)
	}
	if clean.Blocklist == nil || clean.Blocklist.Listed() {
		t.Errorf("unlisted IP should be checked-but-clean, got %+v", clean.Blocklist)
	}
}
