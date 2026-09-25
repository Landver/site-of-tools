package tests

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/linktools"
)

// Short links are the one stateful, abusable feature in this suite
// (docs/04-short-links.md §1), so these tests are weighted towards the refusals
// rather than the happy path: a public shortener is found by scanners within
// days, and a phishing link served from this domain gets the portfolio, the blog
// and all four tools blocklisted together, not the offending path.
//
// Two harnesses. Validation happens entirely on strings before anything reaches
// a Mongo filter (§3), so those tests run everywhere against offlineStore below.
// The round-trip, collision and expiry tests need a real server and are gated on
// MONGODB_TEST_URI, skipping when it is absent so CI and fresh clones stay green
// (docs/07-testing.md §5, same gate as iptools' history tests).

// --- harnesses -------------------------------------------------------------

// offlineStore is a non-nil *LinkStore pointed at a port nothing listens on.
//
// NewShortener refuses to build without a store, so a store is needed even to
// reach the validators — and every refusal this file asserts happens before a
// single byte goes to the database. Built once: the constructor spends its
// server-selection budget discovering that the unique index cannot be created,
// and paying that per test would be the slowest thing in the package.
var offlineStore = sync.OnceValue(func() *linktools.LinkStore {
	client, err := mongo.Connect(options.Client().
		ApplyURI("mongodb://127.0.0.1:1/"). // port 1: reserved, never listening
		SetServerSelectionTimeout(200 * time.Millisecond).
		SetConnectTimeout(200 * time.Millisecond))
	if err != nil {
		return nil
	}
	return linktools.NewLinkStore(context.Background(), client.Database("site-of-tools-offline"))
})

const testAPIKey = "test-api-key"

// offlineShortener: creation is wired but storage is unreachable. Anything that
// gets as far as an insert fails, which is exactly what makes it a clean probe
// for "did validation refuse this, or did it let it through?".
func offlineShortener(t *testing.T) *linktools.Shortener {
	t.Helper()
	store := offlineStore()
	if store == nil {
		t.Fatal("could not build an offline LinkStore")
	}
	s := linktools.NewShortener(store, testAPIKey, "https://link.example")
	if s == nil {
		t.Fatal("NewShortener returned nil with a store and a key; the feature would be off")
	}
	return s
}

// liveMongo holds one connection for the whole live run.
//
// One client, not one per test: platform.OpenMongo dials and pings, and against
// a remote server a handful of open/close cycles inside a few seconds is enough
// connection churn to make the ping itself time out. The driver's client is safe
// for concurrent use and pools internally, which is why the app opens it once in
// main.go too. It is never closed — the test binary exiting drains it, and a
// Cleanup that closed it would have to guess which test was last.
var liveMongo = sync.OnceValue(func() struct {
	m   *platform.Mongo
	err error
} {
	uri := os.Getenv("MONGODB_TEST_URI")
	if uri == "" {
		return struct {
			m   *platform.Mongo
			err error
		}{}
	}
	m, err := platform.OpenMongo(context.Background(), uri, "site-of-tools-test")
	return struct {
		m   *platform.Mongo
		err error
	}{m, err}
})

// liveShortener hands back a shortener over the dedicated test database, having
// dropped the collection so reruns are deterministic. Skips when
// MONGODB_TEST_URI is unset.
//
// The store comes back too, because the two most important tests here have to
// write a row the domain service deliberately cannot produce — an already-expired
// one — and to revoke, which lives on the repository below the service per
// CLAUDE.md rule #5.
func liveShortener(t *testing.T, ctx context.Context) (*linktools.Shortener, *linktools.LinkStore) {
	t.Helper()
	if os.Getenv("MONGODB_TEST_URI") == "" {
		t.Skip("MONGODB_TEST_URI not set; skipping live short-link integration test")
	}
	live := liveMongo()
	if live.err != nil {
		t.Fatalf("open mongo: %v", live.err)
	}
	db := live.m.DB()
	if err := db.Collection("links").Drop(ctx); err != nil {
		t.Fatalf("pre-clean: %v", err)
	}
	t.Cleanup(func() { _ = db.Collection("links").Drop(ctx) })
	store := linktools.NewLinkStore(ctx, db)
	if err := store.IndexError(); err != nil {
		// Not swallowed, per docs/04-short-links.md §4: without the unique index
		// the insert-and-retry collision strategy is not correct, so a test
		// suite that ran anyway would be asserting nothing.
		t.Fatalf("unique index on links.code was not created: %v", err)
	}
	s := linktools.NewShortener(store, testAPIKey, "https://link.example")
	if s == nil {
		t.Fatal("NewShortener returned nil against a live store")
	}
	return s, store
}

// insertExpired writes a row whose expires_at is already in the past.
//
// It goes through the repository rather than Create on purpose: CreateOptions.TTL
// treats <= 0 as "permanent", so the domain service cannot mint an expired link
// and there is nothing to sleep for. This is exactly the row Mongo's TTL monitor
// has not swept yet.
func insertExpired(t *testing.T, ctx context.Context, store *linktools.LinkStore, code, target string) *linktools.Link {
	t.Helper()
	past := time.Now().Add(-time.Hour)
	l := &linktools.Link{
		Code:      code,
		Target:    target,
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: &past,
	}
	if err := store.Insert(ctx, l); err != nil {
		t.Fatalf("Insert expired link: %v", err)
	}
	return l
}

// --- fail-closed wiring ----------------------------------------------------

// TestNewShortenerFailsClosed is the property that keeps corpberry.com off a
// blocklist. An unset LINK_API_KEY means nobody can create, never that anybody
// can (docs/04-short-links.md §5), and the same goes for an absent MONGODB_URI:
// both are wiring mistakes, and a wiring mistake must not open the write path.
func TestNewShortenerFailsClosed(t *testing.T) {
	t.Parallel()
	if s := linktools.NewShortener(nil, "k", "https://link.example"); s != nil {
		t.Error("a shortener was built with no store; with Mongo off, creation must be off too")
	}
	if s := linktools.NewShortener(offlineStore(), "", "https://link.example"); s != nil {
		t.Error("a shortener was built with an EMPTY API key. An unset LINK_API_KEY means nobody can create, never that anybody can: that is a public shortener, and a public shortener gets the whole domain blocklisted.")
	}
	if s := linktools.NewShortener(nil, "", ""); s != nil {
		t.Error("a shortener was built with neither a store nor a key")
	}
}

// TestNilShortenerIsSafeAndDisabled: nil means the feature is off, and every
// method says so rather than panicking, so the handler answers 503 without a
// single nil check of its own (short.go's type comment).
func TestNilShortenerIsSafeAndDisabled(t *testing.T) {
	t.Parallel()
	var s *linktools.Shortener
	ctx := context.Background()

	if _, err := s.Create(ctx, "https://example.com/", linktools.CreateOptions{}); !errors.Is(err, linktools.ErrDisabled) {
		t.Errorf("Create on a nil *Shortener = %v, want ErrDisabled", err)
	}
	if _, err := s.Resolve(ctx, "abc1234"); !errors.Is(err, linktools.ErrDisabled) {
		t.Errorf("Resolve on a nil *Shortener = %v, want ErrDisabled", err)
	}
	if _, err := s.Recent(ctx, 10); !errors.Is(err, linktools.ErrDisabled) {
		t.Errorf("Recent on a nil *Shortener = %v, want ErrDisabled", err)
	}
	// The two that report no error still have to be safe to call: the handler
	// reaches them on the same paths.
	if got := s.ShortURL("abc1234"); got != "" {
		t.Errorf("ShortURL on a nil *Shortener = %q, want the empty string", got)
	}
	if s.Authorized(testAPIKey) {
		t.Error("a nil *Shortener authorised a caller; a disabled feature authorises nobody")
	}
	s.RecordHit("abc1234") // must not panic
}

// --- the key ---------------------------------------------------------------

// TestAuthorizedOnlyForTheConfiguredKey.
//
// Both sides are SHA-256'd before the constant-time compare precisely so a
// wrong-LENGTH key takes the same path as a wrong one: subtle.ConstantTimeCompare
// returns 0 immediately on a length mismatch, so comparing raw strings would leak
// the key's length (docs/04-short-links.md §5). The short and long cases below
// are what that guard exists for.
func TestAuthorizedOnlyForTheConfiguredKey(t *testing.T) {
	t.Parallel()
	s := offlineShortener(t)

	for _, key := range []string{
		"",                                  // no header at all
		"wrong-api-key",                     // same length, wrong bytes
		"x",                                 // far too short
		testAPIKey + "x",                    // right prefix, one byte longer
		strings.ToUpper(testAPIKey),         // case must matter
		strings.TrimSuffix(testAPIKey, "y"), // one byte shorter
		strings.Repeat("k", 4096),           // absurdly long
	} {
		if s.Authorized(key) {
			t.Errorf("Authorized(%q) = true; only the configured key may create links", key)
		}
	}
	if !s.Authorized(testAPIKey) {
		t.Error("the configured key was rejected; creation would be impossible for its owner too")
	}
}

// --- target validation -----------------------------------------------------

// createErr runs a create and returns only the error. Against the offline store
// a target that PASSES validation fails later, at the insert, so these tests
// check for ErrInvalidTarget specifically rather than for "an error".
func createErr(t *testing.T, s *linktools.Shortener, target string, opt linktools.CreateOptions) error {
	t.Helper()
	_, err := s.Create(context.Background(), target, opt)
	return err
}

// TestTargetSchemeAllowlist. The redirect handler sends a stranger's browser to
// whatever is stored, so only the two schemes that are fetched over the wire are
// ever acceptable; the rest are executed or resolved locally by the browser.
func TestTargetSchemeAllowlist(t *testing.T) {
	t.Parallel()
	s := offlineShortener(t)
	for _, target := range []string{
		"javascript:alert(document.domain)",
		"data:text/html,<script>alert(1)</script>",
		"file:///etc/passwd",
		"ftp://example.com/x",
		"vbscript:msgbox(1)",
	} {
		if err := createErr(t, s, target, linktools.CreateOptions{}); !errors.Is(err, linktools.ErrInvalidTarget) {
			t.Errorf("Create(%q) = %v, want ErrInvalidTarget — /s/<code> would hand this to a browser", target, err)
		}
	}
}

// TestTargetMustBePubliclyRoutable.
//
// Without the literal check, /s/aB3xY9k → http://192.168.1.1/setup.cgi is a
// router-CSRF launcher: the victim's own browser, on their own LAN, with their
// cookies, and a scheme-only allowlist waves it through (validateTarget's note).
// 169.254.169.254 is the cloud metadata address, and localhost is refused by
// NAME as well as by address because a hostile resolver need not agree about
// where it points.
func TestTargetMustBePubliclyRoutable(t *testing.T) {
	t.Parallel()
	s := offlineShortener(t)
	for _, target := range []string{
		"http://127.0.0.1/",
		"http://192.168.1.1/setup.cgi",
		"http://10.0.0.1/",
		"http://172.16.0.1/",
		"http://169.254.169.254/latest/meta-data/",
		"http://localhost/",
		"http://api.localhost/",
		"http://[::1]/",
		"http://[fc00::1]/",
		"http://0.0.0.0/",
		"http://router/",     // single-label LAN name
		"http://2130706433/", // integer form of 127.0.0.1
		"http://0x7f000001/", // hex form of the same
	} {
		if err := createErr(t, s, target, linktools.CreateOptions{}); !errors.Is(err, linktools.ErrInvalidTarget) {
			t.Errorf("Create(%q) = %v, want ErrInvalidTarget — this alias would point a stranger's browser at their own network", target, err)
		}
	}
}

// TestTargetPortAndSizeBounds, plus the credentials case: userinfo before the
// host is how a destination is disguised, and the Inspect page flags it for the
// same reason the shortener refuses to store it.
func TestTargetPortAndSizeBounds(t *testing.T) {
	t.Parallel()
	s := offlineShortener(t)
	for _, target := range []string{
		"https://example.com:8443/",
		"http://example.com:3000/",
		"https://example.com:22/",
		"https://example.com:0/",
		"https://paypal.com@evil.tld/login",
		"",
		"   ",
		"https://example.com/?x=" + strings.Repeat("a", 2100), // maxTargetLen is 2048
	} {
		label := target
		if len(label) > 60 {
			label = label[:60] + "…"
		}
		if err := createErr(t, s, target, linktools.CreateOptions{}); !errors.Is(err, linktools.ErrInvalidTarget) {
			t.Errorf("Create(%q) = %v, want ErrInvalidTarget", label, err)
		}
	}
}

// TestOrdinaryTargetsPassValidation. The refusals above are only meaningful if
// the ordinary case gets through: a validator that rejects everything is not a
// validator. Against the offline store the create still fails at the insert, so
// the assertion is specifically that it was not refused as a bad TARGET.
func TestOrdinaryTargetsPassValidation(t *testing.T) {
	t.Parallel()
	s := offlineShortener(t)
	for _, target := range []string{
		"https://example.com/",
		"https://example.com:443/a/b?c=1#d",
		"http://example.com:80/",
		"https://sub.domain.example.co.uk/a%20b?q=a+b",
		"https://93.184.216.34/",
	} {
		if err := createErr(t, s, target, linktools.CreateOptions{}); errors.Is(err, linktools.ErrInvalidTarget) {
			t.Errorf("Create(%q) was refused as an unacceptable target: %v", target, err)
		}
	}
}

// --- slug validation -------------------------------------------------------

// TestSlugValidation covers docs/04-short-links.md §3 verbatim.
//
// Lowercase only, so /s/Foo and /s/foo can never be different links. Reserved
// page names are refused because a slug that shadows a page name is a link that
// breaks retroactively the day the page ships. And a slug shaped like a
// generated code is refused so a custom slug can never collide with the space
// newCode draws from.
func TestSlugValidation(t *testing.T) {
	t.Parallel()
	s := offlineShortener(t)
	for _, tc := range []struct{ slug, why string }{
		{"Foo", "uppercase: /s/Foo and /s/foo must not be two different links"},
		{"fOo", "uppercase anywhere is still uppercase"},
		{"-foo", "a leading hyphen"},
		{"a", "one character, below the minimum of two"},
		{"", "empty is not a slug (it is the generated-code path, tested separately)"},
		{strings.Repeat("a", 65), "65 characters, over the 64 limit"},
		{"my slug", "a space"},
		{"my_slug", "an underscore is outside the alphabet"},
		{"café", "non-ASCII"},
		{"s", "reserved: the /s/ prefix itself"},
		{"clean", "reserved: the Clean page"},
		{"api", "reserved"},
		{"short", "reserved: the console"},
		{"trace", "reserved: the Trace page"},
		{"diff", "reserved"},
		{"encode", "reserved"},
		{"rules", "reserved"},
		{"admin", "reserved"},
		{"abc1234", "exactly 7 base58 characters: the shape newCode produces"},
		{"zzzzzzz", "exactly 7 base58 characters"},
	} {
		if tc.slug == "" {
			continue // an empty slug means "generate one"; see the codes tests
		}
		err := createErr(t, s, "https://example.com/", linktools.CreateOptions{Slug: tc.slug})
		if !errors.Is(err, linktools.ErrInvalidSlug) {
			t.Errorf("slug %q was not refused (%s); got %v", tc.slug, tc.why, err)
		}
	}
}

// TestOrdinarySlugsPassValidation, for the same reason as the target case above.
func TestOrdinarySlugsPassValidation(t *testing.T) {
	t.Parallel()
	s := offlineShortener(t)
	for _, slug := range []string{"q4-report", "ab", "launch2026", "a-b-c", "abc123", "abc12345"} {
		err := createErr(t, s, "https://example.com/", linktools.CreateOptions{Slug: slug})
		if errors.Is(err, linktools.ErrInvalidSlug) {
			t.Errorf("slug %q was refused: %v", slug, err)
		}
	}
}

// TestNoteIsBounded: the note is rendered on the operator console (§7/§8).
func TestNoteIsBounded(t *testing.T) {
	t.Parallel()
	err := createErr(t, offlineShortener(t), "https://example.com/",
		linktools.CreateOptions{Note: strings.Repeat("n", 300)})
	if !errors.Is(err, linktools.ErrInvalidNote) {
		t.Errorf("a 300-byte note was accepted; the cap is 256 (got %v)", err)
	}
}

// TestCleanRequestedWithoutACleanerFailsClosed. §9 fixes the order
// parse → validate → clean → re-parse and re-validate → store. With no cleaner
// wired, the only alternative to refusing is storing an UNCLEANED target while
// reporting a cleaned one, which is a lie about what the link points at.
func TestCleanRequestedWithoutACleanerFailsClosed(t *testing.T) {
	t.Parallel()
	s := offlineShortener(t) // CleanTarget deliberately left nil
	err := createErr(t, s, "https://example.com/?utm_source=x", linktools.CreateOptions{Clean: true})
	if !errors.Is(err, linktools.ErrDisabled) {
		t.Errorf("Create with Clean and no cleaner = %v, want ErrDisabled; storing an uncleaned target while reporting a cleaned one is the failure this guards", err)
	}
}

// --- live Mongo ------------------------------------------------------------

// TestCreateResolveRoundTrip: the happy path, end to end.
func TestCreateResolveRoundTrip(t *testing.T) {
	ctx := context.Background()
	s, _ := liveShortener(t, ctx)

	link, err := s.Create(ctx, "https://example.com/a?b=1", linktools.CreateOptions{Note: "round trip"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if link.Code == "" {
		t.Fatal("created link has no code")
	}
	got, err := s.Resolve(ctx, link.Code)
	if err != nil {
		t.Fatalf("Resolve(%q): %v", link.Code, err)
	}
	if got.Target != "https://example.com/a?b=1" {
		t.Errorf("target = %q; a short link that quietly changes destination is indistinguishable from an attack", got.Target)
	}
	if want := "https://link.example/s/" + link.Code; s.ShortURL(link.Code) != want {
		t.Errorf("ShortURL = %q, want %q — the /s/ prefix is owned here, not by the caller", s.ShortURL(link.Code), want)
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt not set")
	}
}

// TestCustomSlugTakenIsAConflictNotASuffix. A caller who asked for /s/q4-report
// and got /s/q4-report-2 will paste the one they asked for (docs/04-short-links.md §3).
func TestCustomSlugTakenIsAConflictNotASuffix(t *testing.T) {
	ctx := context.Background()
	s, _ := liveShortener(t, ctx)

	first, err := s.Create(ctx, "https://example.com/first", linktools.CreateOptions{Slug: "q4-report"})
	if err != nil {
		t.Fatalf("first Create: %v", err)
	}
	second, err := s.Create(ctx, "https://example.com/second", linktools.CreateOptions{Slug: "q4-report"})
	if !errors.Is(err, linktools.ErrSlugTaken) {
		t.Fatalf("second Create with the same slug = (%+v, %v), want ErrSlugTaken", second, err)
	}
	if second != nil {
		t.Errorf("a link was returned alongside the conflict: %+v", second)
	}
	// And the first link is untouched: a failed create must not repoint it.
	got, err := s.Resolve(ctx, first.Code)
	if err != nil {
		t.Fatalf("Resolve after the conflict: %v", err)
	}
	if got.Target != "https://example.com/first" {
		t.Errorf("the existing alias now points at %q; a rejected create overwrote it", got.Target)
	}
}

// TestExpiryIsEnforcedInCodeNotByTheReaper is the important one.
//
// Mongo's TTL monitor sweeps roughly every 60 seconds and lags under load, so a
// resolver that treated document-absence as expiry would keep serving a revoked
// link for a minute or more, silently (docs/04-short-links.md §4). This test
// therefore asserts the document is STILL PRESENT and still refuses to resolve:
// the index is garbage collection, never the enforcement point. Waiting on the
// reaper instead would be both wrong and a flake generator.
func TestExpiryIsEnforcedInCodeNotByTheReaper(t *testing.T) {
	ctx := context.Background()
	s, store := liveShortener(t, ctx)

	link := insertExpired(t, ctx, store, "already-expired", "https://example.com/expired")

	// The document is still THERE — that is the whole premise, so assert it
	// rather than assume it. If the reaper had already swept the row, the check
	// below would pass for the wrong reason and the test would be worthless.
	recent, err := s.Recent(ctx, 50)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	var present bool
	for _, l := range recent {
		if l.Code == link.Code {
			present = true
		}
	}
	if !present {
		t.Fatal("the expired document is already gone, so this test proves nothing about Resolve")
	}

	if got, err := s.Resolve(ctx, link.Code); err == nil {
		t.Fatalf("an expired link that is still in the collection resolved to %q. Expiry must be compared against time.Now() in Resolve; Mongo's TTL monitor sweeps roughly every 60 seconds and lags under load, so leaving it to the index serves a dead link for a minute or more, silently.", got.Target)
	} else if !errors.Is(err, linktools.ErrLinkNotFound) {
		t.Errorf("expired link = %v, want ErrLinkNotFound", err)
	}

	// The other half of the same rule: a TTL in the future must still resolve,
	// or "enforced in code" would just mean "broken".
	live, err := s.Create(ctx, "https://example.com/live", linktools.CreateOptions{TTL: time.Hour})
	if err != nil {
		t.Fatalf("Create with a future TTL: %v", err)
	}
	if live.ExpiresAt == nil || !live.ExpiresAt.After(time.Now()) {
		t.Fatalf("ExpiresAt = %v, want an hour from now", live.ExpiresAt)
	}
	if _, err := s.Resolve(ctx, live.Code); err != nil {
		t.Errorf("an unexpired link did not resolve: %v", err)
	}
}

// TestRevokedLinkDoesNotResolve, and the document survives: a hard delete frees
// the slug, and a freed slug re-registered to a new target is alias takeover —
// every copy of the old link in somebody's notes silently changes destination.
func TestRevokedLinkDoesNotResolve(t *testing.T) {
	ctx := context.Background()
	s, store := liveShortener(t, ctx)

	link, err := s.Create(ctx, "https://example.com/revoked", linktools.CreateOptions{Slug: "to-revoke"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Revoke lives on the store, below the domain service, per rule #5.
	if err := store.Revoke(ctx, link.Code, time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if got, err := s.Resolve(ctx, link.Code); err == nil {
		t.Fatalf("a revoked link still resolved to %q", got.Target)
	} else if !errors.Is(err, linktools.ErrLinkNotFound) {
		t.Errorf("revoked link = %v, want ErrLinkNotFound", err)
	}
	// The slug is NOT free again: re-registering it would be alias takeover.
	if _, err := s.Create(ctx, "https://evil.tld/", linktools.CreateOptions{Slug: "to-revoke"}); !errors.Is(err, linktools.ErrSlugTaken) {
		t.Errorf("a revoked slug was reissuable (%v); every copy of the old link would silently change destination", err)
	}
}

// TestNoExistenceOracle: expired, revoked and never-existed all answer with the
// same sentinel.
//
// Telling them apart would be an existence oracle over the guessable custom-slug
// namespace (docs/04-short-links.md §7) — "this slug is expired" confirms the
// slug was used, which is exactly the fact the entropy argument does not cover
// for dictionary-shaped slugs. Resolve appends a one-word reason for the server
// operator; handler.redirect discards it and answers a constant 404 for all
// three, so the classification a caller can observe is identical.
func TestNoExistenceOracle(t *testing.T) {
	ctx := context.Background()
	s, store := liveShortener(t, ctx)

	expired := insertExpired(t, ctx, store, "gone-expired", "https://example.com/e")
	revoked, err := s.Create(ctx, "https://example.com/r", linktools.CreateOptions{Slug: "gone-revoked"})
	if err != nil {
		t.Fatalf("Create revoked: %v", err)
	}
	if err := store.Revoke(ctx, revoked.Code, time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	for _, tc := range []struct{ name, code string }{
		{"expired", expired.Code},
		{"revoked", revoked.Code},
		{"never existed", "never-existed-here"},
		{"malformed", "not a slug at all"}, // refused by shape, answered as a miss
	} {
		_, err := s.Resolve(ctx, tc.code)
		if !errors.Is(err, linktools.ErrLinkNotFound) {
			t.Errorf("%s: Resolve = %v, want ErrLinkNotFound — the three cases must be indistinguishable to a caller", tc.name, err)
		}
	}
}

// base58Alphabet mirrors docs/04-short-links.md §3: digits and letters MINUS 0,
// O, I and l. Spelled out here rather than imported, so the test fails if the
// implementation's table is edited rather than following it.
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// TestGeneratedCodes: the shape and the entropy claim of docs/04-short-links.md §3.
//
// Distinctness across a thousand draws is not a test of the birthday bound — at
// 58^7 a collision would be a once-in-a-universe event — it is a test that the
// generator draws from crypto/rand rather than from a seeded or sequential
// source, which is what "not math/rand, not a hash of the target" means in
// practice. A sequential or low-entropy generator fails here immediately.
//
// A code is only observable through a successful insert, so the thousand draws
// are a thousand round trips; they run through a small pool because against a
// remote database serially they are the slowest thing in the repo by an order of
// magnitude. The concurrency is a bonus rather than the point: it also puts the
// insert-and-retry collision path under real contention, which is the one thing
// the unique index exists to arbitrate.
func TestGeneratedCodes(t *testing.T) {
	ctx := context.Background()
	s, _ := liveShortener(t, ctx)

	const (
		draws   = 1000
		workers = 20
	)
	var (
		mu    sync.Mutex
		seen  = make(map[string]bool, draws)
		fails []string
		wg    sync.WaitGroup
	)
	jobs := make(chan int, draws)
	for i := 0; i < draws; i++ {
		jobs <- i
	}
	close(jobs)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				link, err := s.Create(ctx, "https://example.com/gen", linktools.CreateOptions{})
				mu.Lock()
				switch {
				case err != nil:
					fails = append(fails, "Create: "+err.Error())
				case len(link.Code) != 7:
					fails = append(fails, "code "+link.Code+" is not 7 characters")
				case strings.IndexAny(link.Code, "0OIl") >= 0:
					fails = append(fails, "code "+link.Code+" contains one of 0, O, I or l, which base58 drops precisely because these codes are read aloud and typed by hand")
				case strings.Trim(link.Code, base58Alphabet) != "":
					fails = append(fails, "code "+link.Code+" contains a character outside the base58 alphabet")
				case seen[link.Code]:
					fails = append(fails, "code "+link.Code+" was generated twice; the unique index caught nothing, so the source is not crypto/rand")
				default:
					seen[link.Code] = true
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	for _, f := range fails {
		t.Error(f)
	}
	if len(seen) != draws {
		t.Errorf("got %d distinct codes from %d draws", len(seen), draws)
	}
}

// TestRecentListsNewestFirst, the list the console is key-gated to protect: it
// defeats §3's entropy argument outright and turns hits/last_hit_at into a
// read-receipt oracle, which is why it is never public.
func TestRecentListsNewestFirst(t *testing.T) {
	ctx := context.Background()
	s, _ := liveShortener(t, ctx)

	for _, slug := range []string{"first-one", "second-one", "third-one"} {
		if _, err := s.Create(ctx, "https://example.com/"+slug, linktools.CreateOptions{Slug: slug}); err != nil {
			t.Fatalf("Create %s: %v", slug, err)
		}
		time.Sleep(2 * time.Millisecond) // distinct created_at values
	}
	got, err := s.Recent(ctx, 50)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("Recent returned %d links, want 3", len(got))
	}
	if got[0].Code != "third-one" {
		t.Errorf("Recent[0] = %q, want the newest (third-one)", got[0].Code)
	}
	if got[0].CreatedIP != "" {
		// The json tag hides this from the API, but a template sees the struct
		// field regardless (docs/04-short-links.md §4), so nothing should be
		// putting an address here in the first place unless a create supplied one.
		t.Logf("CreatedIP is populated (%q); the console's view model must omit it explicitly", got[0].CreatedIP)
	}
}
