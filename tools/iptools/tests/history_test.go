package tests

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/shared"
	"github.com/Landver/site-of-tools/tools/iptools"
)

// TestHistoryTemplateWithEntries renders the populated ip/history branch directly
// (the Renderer ignores the context arg), so a template error in the {{range}}
// block — which the disabled-state tests never reach and which has no data locally
// without the BINs — is caught here rather than first in prod.
func TestHistoryTemplateWithEntries(t *testing.T) {
	r := platform.NewRenderer(false, nil,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: iptools.Templates, DevDir: "tools/iptools/templates"},
	)
	vm := map[string]any{
		"Title": "Lookup history", "Active": "history", "Enabled": true, "Attribution": true,
		"Entries": []iptools.HistoryEntry{
			{IP: "8.8.8.8", CountryCode: "US", Country: "United States", City: "Mountain View", ASN: "15169", ASName: "Google LLC", CreatedAt: time.Date(2026, 7, 17, 9, 30, 0, 0, time.UTC)},
		},
	}
	var buf bytes.Buffer
	if err := r.Render(nil, &buf, "ip/history", vm); err != nil {
		t.Fatalf("render ip/history with entries: %v", err)
	}
	body := buf.String()
	for _, want := range []string{"8.8.8.8", "Mountain View", "Google LLC", "2026-07-17 09:30", `href="/?ip=8.8.8.8"`} {
		if !strings.Contains(body, want) {
			t.Errorf("populated history page missing %q in:\n%s", want, body)
		}
	}
}

// liveHistoryDB opens the dedicated test database and returns a fresh History
// repo, registering cleanup so the collection never lingers. Skips the test when
// MONGODB_TEST_URI is unset (keeps `make test`/CI hermetic).
func liveHistoryDB(t *testing.T, ctx context.Context) (*iptools.History, *platform.Mongo) {
	t.Helper()
	uri := os.Getenv("MONGODB_TEST_URI")
	if uri == "" {
		t.Skip("MONGODB_TEST_URI not set; skipping live history integration test")
	}
	m, err := platform.OpenMongo(ctx, uri, "site-of-tools-test")
	if err != nil {
		t.Fatalf("open mongo: %v", err)
	}
	db := m.DB()
	if err := db.Collection("ip_lookups").Drop(ctx); err != nil {
		t.Fatalf("pre-clean: %v", err)
	}
	t.Cleanup(func() { _ = db.Collection("ip_lookups").Drop(ctx); _ = m.Close(ctx) })
	return iptools.NewHistory(ctx, db), m
}

// waitForRecent polls Recent (Record is async) until at least one entry lands.
func waitForRecent(t *testing.T, ctx context.Context, h *iptools.History) []iptools.HistoryEntry {
	t.Helper()
	for range 40 {
		got, err := h.Recent(ctx, 10)
		if err != nil {
			t.Fatalf("Recent: %v", err)
		}
		if len(got) > 0 {
			return got
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}

// TestNewHistoryDisabled: a nil db (Mongo off) yields a nil repo — the nil-safe
// disabled store, so the handler needs no Mongo guards.
func TestNewHistoryDisabled(t *testing.T) {
	if h := iptools.NewHistory(context.Background(), nil); h != nil {
		t.Fatalf("NewHistory(nil db) = %v, want nil (disabled)", h)
	}
}

// TestNilHistoryIsSafe: Record no-ops and Recent returns empty on a nil repo.
func TestNilHistoryIsSafe(t *testing.T) {
	var h *iptools.History
	h.Record(&iptools.Result{IP: "8.8.8.8"}) // must not panic
	got, err := h.Recent(context.Background(), 10)
	if err != nil {
		t.Errorf("nil History Recent() err = %v, want nil", err)
	}
	if len(got) != 0 {
		t.Errorf("nil History Recent() = %v, want empty", got)
	}
}

// TestHistoryPageDisabled: with history off the page renders the "off" state and,
// because it still displays geo/ASN data, carries the required IP2Location credit.
func TestHistoryPageDisabled(t *testing.T) {
	rec := do(newTestApp(fakeLooker{}), "/history", map[string]string{"Accept": "text/html"})
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "History is off") {
		t.Errorf("disabled history page should say it's off, got:\n%s", body)
	}
	if !strings.Contains(body, "uses the IP2Location LITE database") {
		t.Errorf("history page must carry the IP2Location LITE credit")
	}
}

// TestHistoryJSONDisabled: JSON callers get an empty lookups array (not null).
func TestHistoryJSONDisabled(t *testing.T) {
	rec := do(newTestApp(fakeLooker{}), "/history", map[string]string{"Accept": "application/json"})
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	if body := strings.ReplaceAll(rec.Body.String(), " ", ""); !strings.Contains(body, `"lookups":[]`) {
		t.Errorf("disabled history JSON should have an empty lookups array, got: %s", rec.Body.String())
	}
}

// TestHistoryLiveRoundTrip is an integration test: it runs only when
// MONGODB_TEST_URI is set and skips otherwise, so `make test`, CI, and fresh
// clones stay green (mirrors platform's TestOpenMongoLive). It uses a dedicated
// "site-of-tools-test" database (see liveHistoryDB), so it never touches the app's
// real history and reruns are deterministic.
func TestHistoryLiveRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	h, _ := liveHistoryDB(t, ctx)
	h.Record(&iptools.Result{IP: "203.0.113.9", Country: "Testland", ASN: "64500", ASName: "Example AS"})

	got := waitForRecent(t, ctx, h)
	if len(got) != 1 || got[0].IP != "203.0.113.9" {
		t.Fatalf("Recent = %+v, want exactly one entry for 203.0.113.9", got)
	}
	if got[0].ASName != "Example AS" || got[0].CreatedAt.IsZero() {
		t.Errorf("entry not fully persisted: %+v", got[0])
	}
}

// TestHistoryLiveViaHandler drives the real handler against real Mongo to prove
// the end-to-end recording gate: a browser lookup (text/html, explicit ?ip) is
// persisted, while a JSON/CLI lookup is not. The fake Looker returns the same
// result for any IP, so exactly one recorded entry (from the HTML call) proves the
// JSON path was skipped.
func TestHistoryLiveViaHandler(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	hist, _ := liveHistoryDB(t, ctx)

	r := platform.NewRenderer(false, nil,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: iptools.Templates, DevDir: "tools/iptools/templates"},
	)
	e := echo.New()
	e.Renderer = r
	iptools.Register(e, fakeLooker{res: &iptools.Result{IP: "198.51.100.23", Country: "United States", ASN: "64500"}}, hist)

	do(e, "/?ip=198.51.100.23", map[string]string{"Accept": "text/html"})  // recorded
	do(e, "/?ip=8.8.8.8", map[string]string{"Accept": "application/json"}) // NOT recorded (JSON)

	got := waitForRecent(t, ctx, hist)
	if len(got) != 1 || got[0].IP != "198.51.100.23" {
		t.Fatalf("history via handler = %+v, want only the browser lookup (198.51.100.23)", got)
	}
}
