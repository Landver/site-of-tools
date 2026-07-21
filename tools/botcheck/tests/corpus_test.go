package tests

import (
	"context"
	"encoding/json"
	"fmt"
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
)

// corpus_test.go covers G41/G42 fingerprint corpus: FingerprintHash identity,
// fingerprint_reuse rule (floor + good-bot suppression), nil-safe repo
// contract, + — w/ MONGODB_TEST_URI set — live Mongo round-trip + end-to-end
// handler wiring (mirrors iptools history tests).

func TestFingerprintHashDeterministic(t *testing.T) {
	s := cleanChrome()
	h := s.FingerprintHash()
	if h == "" || h != s.FingerprintHash() {
		t.Fatalf("hash not deterministic: %q then %q", h, s.FingerprintHash())
	}
	// Server-observed fields must NOT change hash → corpus tracks browser's
	// identity; IPs it appears from = corpus's half.
	s2 := s
	s2.HTTPUserAgent = "curl/8.7.1"
	s2.IPTimezone = "+03:00"
	s2.IsDatacenter = true
	if got := s2.FingerprintHash(); got != h {
		t.Errorf("server-observed fields leaked into the hash: %q ≠ %q", got, h)
	}
	// Any stable client field change must change hash.
	for name, mod := range map[string]func(*botcheck.Signals){
		"UA":         func(s *botcheck.Signals) { s.NavMainUA = "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0" },
		"languages":  func(s *botcheck.Signals) { s.Languages = []string{"fr-FR", "fr"} },
		"cores":      func(s *botcheck.Signals) { s.HardwareCores = 4 },
		"renderer":   func(s *botcheck.Signals) { s.WebGLRenderer = "ANGLE (NVIDIA, GeForce RTX 3080)" },
		"timezone":   func(s *botcheck.Signals) { s.BrowserTZ = "Europe/Paris" },
		"font count": func(s *botcheck.Signals) { s.FontCount = 12 },
	} {
		s3 := s
		mod(&s3)
		if got := s3.FingerprintHash(); got == h {
			t.Errorf("hash unchanged after changing %s — the corpus would collapse distinct browsers", name)
		}
	}
}

func TestFingerprintReuseRule(t *testing.T) {
	// Fires at 5-IP floor: one 25-pt consistency deduction.
	s := cleanChrome()
	s.FingerprintIPs = 5
	r := botcheck.Evaluate(s)
	c := check(t, r, "fingerprint_reuse")
	if !c.Triggered || c.Tier != "consistency" {
		t.Fatalf("fingerprint_reuse at 5 IPs = %+v, want a triggered consistency check", c)
	}
	if r.Score != 75 || r.FingerprintIPs != 5 {
		t.Errorf("score=%d FingerprintIPs=%d, want 75/5 (one 25-point deduction, count carried through)", r.Score, r.FingerprintIPs)
	}

	// Silent below floor: 0 (no corpus data) and 4 alike.
	for _, n := range []int{0, 4} {
		s = cleanChrome()
		s.FingerprintIPs = n
		r = botcheck.Evaluate(s)
		if c := check(t, r, "fingerprint_reuse"); c.Triggered {
			t.Errorf("fingerprint_reuse fired at %d IPs (below the floor)", n)
		}
		if r.Score != 100 {
			t.Errorf("score = %d at %d IPs, want 100", r.Score, n)
		}
	}

	// Server-only request never consulted corpus → rule reads "not collected",
	// never pass or fire — even w/ a count somehow present.
	s = cleanChrome()
	s.ClientCollected = false
	s.FingerprintIPs = 9
	r = botcheck.Evaluate(s)
	if c := check(t, r, "fingerprint_reuse"); !c.Skipped || c.Triggered {
		t.Errorf("server-only request: fingerprint_reuse = %+v, want skipped and untriggered", c)
	}
	if r.Score != 100 {
		t.Errorf("server-only score = %d, want 100 (corpus rule skipped)", r.Score)
	}
}

func TestFingerprintReuseSuppressedForGoodBot(t *testing.T) {
	// A verified crawler fleet legitimately shares one fingerprint across many
	// IPs → reuse deduction recorded as "expected", not counted. Otherwise-clean
	// fingerprint isolates the suppression (score stays 100).
	const applebot = "Mozilla/5.0 (Applebot/0.1; +http://www.apple.com/go/applebot)"
	s := cleanChrome()
	s.NavMainUA, s.NavWorkerUA, s.NavIframeUA, s.SWUA = applebot, applebot, applebot, applebot
	s.HTTPUserAgent = applebot
	s.AppVersion = strings.TrimPrefix(applebot, "Mozilla/")
	s.ASN = "714" // Apple's own ASN — verified
	s.FingerprintIPs = 9
	r := botcheck.Evaluate(s)
	c := check(t, r, "fingerprint_reuse")
	if !c.Triggered || !c.Suppressed {
		t.Errorf("verified good bot: fingerprint_reuse = %+v, want triggered but suppressed", c)
	}
	if r.Verdict != "good-bot" || r.Score != 100 {
		t.Errorf("verdict=%q score=%d, want good-bot/100 (reuse recorded as expected)", r.Verdict, r.Score)
	}
}

// TestNewCorpusDisabled: nil db (Mongo off) yields nil repo — nil-safe
// disabled store → handler needs no Mongo guards.
func TestNewCorpusDisabled(t *testing.T) {
	if c := botcheck.NewCorpus(nil); c != nil {
		t.Fatalf("NewCorpus(nil db) = %v, want nil (disabled)", c)
	}
}

// TestNilCorpusIsSafe: every method no-ops on nil repo.
func TestNilCorpusIsSafe(t *testing.T) {
	var c *botcheck.Corpus
	ctx := context.Background()
	if err := c.EnsureIndexes(ctx); err != nil {
		t.Errorf("nil Corpus EnsureIndexes err = %v, want nil", err)
	}
	if err := c.Record(ctx, "hash", "203.0.113.1"); err != nil { // mustn't panic
		t.Errorf("nil Corpus Record err = %v, want nil", err)
	}
	if n, err := c.DistinctIPs(ctx, "hash"); err != nil || n != 0 {
		t.Errorf("nil Corpus DistinctIPs = %d, %v; want 0, nil", n, err)
	}
	if n, err := c.DistinctHashesByIP(ctx, "203.0.113.1", time.Hour); err != nil || n != 0 {
		t.Errorf("nil Corpus DistinctHashesByIP = %d, %v; want 0, nil", n, err)
	}
	// Empty IP counts nothing even on a live store (guarded before the query).
	if n, err := c.DistinctHashesByIP(ctx, "", time.Hour); err != nil || n != 0 {
		t.Errorf("nil Corpus DistinctHashesByIP(empty ip) = %d, %v; want 0, nil", n, err)
	}
}

// TestFingerprintChurnRule covers G43: ip_fingerprint_churn soft rule fires at
// its distinct-fingerprint floor, stays silent below it, never docks score on
// its own (soft, cluster-only), carries count into report, skips a
// server-only request that never consulted corpus.
func TestFingerprintChurnRule(t *testing.T) {
	// Fires at 8-distinct-fingerprint floor — soft signal, so alone forms no
	// cluster, leaves score at 100.
	s := cleanChrome()
	s.FingerprintChurn = 8
	r := botcheck.Evaluate(s)
	c := check(t, r, "ip_fingerprint_churn")
	if !c.Triggered || c.Tier != "soft" {
		t.Fatalf("ip_fingerprint_churn at 8 = %+v, want a triggered soft check", c)
	}
	if r.Score != 100 || r.FingerprintChurn != 8 {
		t.Errorf("score=%d FingerprintChurn=%d, want 100/8 (a lone soft signal never docks; count carried through)", r.Score, r.FingerprintChurn)
	}

	// Silent below floor: 0 (no corpus data) and 7 alike.
	for _, n := range []int{0, 7} {
		s = cleanChrome()
		s.FingerprintChurn = n
		if c := check(t, botcheck.Evaluate(s), "ip_fingerprint_churn"); c.Triggered {
			t.Errorf("ip_fingerprint_churn fired at %d (below the floor)", n)
		}
	}

	// Server-only request never consulted corpus: skipped, not pass or fire.
	s = cleanChrome()
	s.ClientCollected = false
	s.FingerprintChurn = 20
	if c := check(t, botcheck.Evaluate(s), "ip_fingerprint_churn"); !c.Skipped || c.Triggered {
		t.Errorf("server-only request: ip_fingerprint_churn = %+v, want skipped and untriggered", c)
	}
}

// TestCheckNilCorpusLeavesRuleSilent: w/ Mongo off handler still scores,
// corpus rule has no data (0 IPs never evidence), JSON carries no
// fingerprintIPs key.
func TestCheckNilCorpusLeavesRuleSilent(t *testing.T) {
	rec := post(newTestApp(fakeLooker{}), "/check", cleanClientBody, map[string]string{
		"Accept": "application/json", "User-Agent": chromeMacUA,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	var rep botcheck.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rep.FingerprintIPs != 0 || rep.FingerprintChurn != 0 {
		t.Errorf("FingerprintIPs=%d FingerprintChurn=%d, want 0/0 with a nil corpus", rep.FingerprintIPs, rep.FingerprintChurn)
	}
	for _, c := range rep.Checks {
		if (c.ID == "fingerprint_reuse" || c.ID == "ip_fingerprint_churn") && c.Triggered {
			t.Errorf("%s fired with a nil corpus:\n%s", c.ID, rec.Body.String())
		}
	}
	for _, key := range []string{"fingerprintIPs", "fingerprintChurn"} {
		if strings.Contains(rec.Body.String(), key) {
			t.Errorf("a zero corpus count (%s) must stay out of the JSON (omitempty):\n%s", key, rec.Body.String())
		}
	}
}

// liveCorpusDB opens dedicated test database, returns fresh Corpus,
// registers cleanup so collection never lingers. Skips test when
// MONGODB_TEST_URI unset (keeps `make test`/CI hermetic) — iptools
// history pattern.
func liveCorpusDB(t *testing.T, ctx context.Context) *botcheck.Corpus {
	t.Helper()
	uri := os.Getenv("MONGODB_TEST_URI")
	if uri == "" {
		t.Skip("MONGODB_TEST_URI not set; skipping live corpus integration test")
	}
	m, err := platform.OpenMongo(ctx, uri, "site-of-tools-test")
	if err != nil {
		t.Fatalf("open mongo: %v", err)
	}
	db := m.DB()
	if err := db.Collection("botcheck_fingerprints").Drop(ctx); err != nil {
		t.Fatalf("pre-clean: %v", err)
	}
	t.Cleanup(func() { _ = db.Collection("botcheck_fingerprints").Drop(ctx); _ = m.Close(ctx) })
	c := botcheck.NewCorpus(db)
	if err := c.EnsureIndexes(ctx); err != nil {
		t.Fatalf("ensure indexes: %v", err)
	}
	return c
}

// TestCorpusLiveRoundTrip is an integration test (MONGODB_TEST_URI only):
// distinct-IP counting per hash, duplicate sightings not double-counted,
// hashes isolated from each other.
func TestCorpusLiveRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := liveCorpusDB(t, ctx)

	distinct := func(hash string) int {
		t.Helper()
		n, err := c.DistinctIPs(ctx, hash)
		if err != nil {
			t.Fatalf("DistinctIPs: %v", err)
		}
		return n
	}
	for i := 1; i <= 4; i++ {
		if err := c.Record(ctx, "hash-a", fmt.Sprintf("203.0.113.%d", i)); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	if n := distinct("hash-a"); n != 4 {
		t.Fatalf("DistinctIPs = %d, want 4", n)
	}
	// Repeat sighting from same IP doesn't double-count; another hash starts
	// its own count.
	if err := c.Record(ctx, "hash-a", "203.0.113.4"); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := c.Record(ctx, "hash-b", "203.0.113.9"); err != nil {
		t.Fatalf("record: %v", err)
	}
	if n := distinct("hash-a"); n != 4 {
		t.Errorf("DistinctIPs = %d after a duplicate IP, want 4", n)
	}
	// Fifth distinct IP crosses rule's floor.
	if err := c.Record(ctx, "hash-a", "203.0.113.5"); err != nil {
		t.Fatalf("record: %v", err)
	}
	if n := distinct("hash-a"); n != 5 {
		t.Errorf("DistinctIPs = %d, want 5", n)
	}
	if n := distinct("hash-b"); n != 1 {
		t.Errorf("DistinctIPs(hash-b) = %d, want 1 (hashes are isolated)", n)
	}
}

// TestCorpusLiveViaHandler drives real handler against real Mongo to prove
// end-to-end wiring: same client fingerprint POSTed from 5 distinct egress
// IPs crosses fingerprint_reuse floor, count carried into report. RemoteAddr
// stands in for RealIP (bare test app configures no XFF trust).
func TestCorpusLiveViaHandler(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	corpus := liveCorpusDB(t, ctx)

	r := platform.NewRenderer(false, nil,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: botcheck.Templates, DevDir: "tools/botcheck/templates"},
	)
	e := echo.New()
	e.Renderer = r
	botcheck.Register(e, fakeLooker{}, corpus)

	for i := 1; i <= 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/check", strings.NewReader(cleanClientBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", chromeMacUA)
		req.RemoteAddr = fmt.Sprintf("203.0.113.%d:1234", i)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST %d: code = %d, want 200", i, rec.Code)
		}
		var rep botcheck.Report
		if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
			t.Fatalf("POST %d: decode: %v", i, err)
		}
		// Each request records before it counts → count includes itself.
		if rep.FingerprintIPs != i {
			t.Errorf("POST %d: FingerprintIPs = %d, want %d", i, rep.FingerprintIPs, i)
		}
		var fired bool
		for _, c := range rep.Checks {
			if c.ID == "fingerprint_reuse" {
				fired = c.Triggered
			}
		}
		if want := i >= 5; fired != want {
			t.Errorf("POST %d: fingerprint_reuse triggered = %v, want %v", i, fired, want)
		}
	}
}

// TestCorpusChurnLiveRoundTrip is an integration test (MONGODB_TEST_URI only)
// for DistinctHashesByIP: distinct-fingerprint counting per IP, IPs isolated
// from each other, repeat sightings not double-counted, rolling window
// enforced (window shorter than sightings' age excludes them all).
func TestCorpusChurnLiveRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := liveCorpusDB(t, ctx)

	churn := func(ip string, window time.Duration) int {
		t.Helper()
		n, err := c.DistinctHashesByIP(ctx, ip, window)
		if err != nil {
			t.Fatalf("DistinctHashesByIP: %v", err)
		}
		return n
	}
	// One IP presents 3 distinct fingerprints; repeat of one doesn't add.
	for i := 1; i <= 3; i++ {
		if err := c.Record(ctx, fmt.Sprintf("fp-%d", i), "198.51.100.7"); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	if err := c.Record(ctx, "fp-1", "198.51.100.7"); err != nil { // repeat FP
		t.Fatalf("record: %v", err)
	}
	// Second IP is isolated.
	if err := c.Record(ctx, "fp-9", "198.51.100.8"); err != nil {
		t.Fatalf("record: %v", err)
	}
	if n := churn("198.51.100.7", time.Hour); n != 3 {
		t.Errorf("churn(A, 1h) = %d, want 3 distinct fingerprints", n)
	}
	if n := churn("198.51.100.8", time.Hour); n != 1 {
		t.Errorf("churn(B, 1h) = %d, want 1 (IPs are isolated)", n)
	}
	// Window is enforced: window shorter than sightings' age (recorded a moment
	// ago) excludes them all.
	if n := churn("198.51.100.7", time.Nanosecond); n != 0 {
		t.Errorf("churn(A, 1ns) = %d, want 0 (all sightings older than the window)", n)
	}
}

// TestCorpusChurnLiveViaHandler drives real handler against real Mongo: 8
// DISTINCT fingerprints POSTed from ONE egress IP cross ip_fingerprint_churn
// floor, count carried into report. Distinct fingerprints produced by varying
// one stable field (screenW), which changes fingerprint hash.
func TestCorpusChurnLiveViaHandler(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	corpus := liveCorpusDB(t, ctx)

	r := platform.NewRenderer(false, nil,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: botcheck.Templates, DevDir: "tools/botcheck/templates"},
	)
	e := echo.New()
	e.Renderer = r
	botcheck.Register(e, fakeLooker{}, corpus)

	const floor = 8 // fingerprintChurnMinHashes (unexported); keep in sync
	var last botcheck.Report
	for i := 1; i <= floor; i++ {
		body := fmt.Sprintf(`{"v":4,"navMainUA":%q,"screenW":%d}`, chromeMacUA, 1000+i)
		req := httptest.NewRequest(http.MethodPost, "/check", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", chromeMacUA)
		req.RemoteAddr = "198.51.100.42:5555" // 1 IP, many fingerprints
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST %d: code = %d, want 200", i, rec.Code)
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &last); err != nil {
			t.Fatalf("POST %d: decode: %v", i, err)
		}
		// Each request records before it counts → count includes itself.
		if last.FingerprintChurn != i {
			t.Errorf("POST %d: FingerprintChurn = %d, want %d", i, last.FingerprintChurn, i)
		}
	}
	var fired bool
	for _, c := range last.Checks {
		if c.ID == "ip_fingerprint_churn" {
			fired = c.Triggered
		}
	}
	if !fired {
		t.Errorf("ip_fingerprint_churn should fire at %d distinct fingerprints from one IP", floor)
	}
}
