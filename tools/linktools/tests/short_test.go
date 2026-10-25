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

// Validation runs everywhere on offlineStore; round trips need MONGODB_TEST_URI and skip without it.

// offlineStore points at a dead port; built once, as its constructor burns the server-selection budget.
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

// Storage unreachable: anything reaching the insert fails, so it shows whether validation refused.
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

// keylessShortener is what main.go builds when MONGODB_URI is set and LINK_API_KEY is not.
func keylessShortener(t *testing.T, store *linktools.LinkStore) *linktools.Shortener {
	t.Helper()
	if store == nil {
		t.Fatal("no LinkStore to build on")
	}
	s := linktools.NewShortener(store, "", "https://link.example")
	if s == nil {
		t.Fatal("NewShortener returned nil with a store and no key; links already handed out would stop resolving")
	}
	return s
}

// One client for the live run: open/close churn against a remote server makes the ping time out.
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

// Skips without MONGODB_TEST_URI; returns the store too, to write expired rows and Revoke.
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
		// Without the unique index, insert-and-retry is unsafe and these tests would assert nothing.
		t.Fatalf("unique index on links.code was not created: %v", err)
	}
	s := linktools.NewShortener(store, testAPIKey, "https://link.example")
	if s == nil {
		t.Fatal("NewShortener returned nil against a live store")
	}
	return s, store
}

// Through the store: the service treats TTL <= 0 as permanent, so it cannot mint an expired link.
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

// No store, no shortener; the keyless case builds one (see TestKeylessShortenerAuthorizesNobody).
func TestNewShortenerFailsClosed(t *testing.T) {
	t.Parallel()
	if s := linktools.NewShortener(nil, "k", "https://link.example"); s != nil {
		t.Error("a shortener was built with no store; with Mongo off, short links must be off too")
	}
	if s := linktools.NewShortener(nil, "", ""); s != nil {
		t.Error("a shortener was built with neither a store nor a key")
	}
}

// An unset LINK_API_KEY means nobody can create, never anybody. The empty presented key matters most:
// "" against an unset key is what a careless compare lets through.
func TestKeylessShortenerAuthorizesNobody(t *testing.T) {
	t.Parallel()
	s := keylessShortener(t, offlineStore())

	if s.HasKey() {
		t.Error("HasKey() = true with an empty LINK_API_KEY")
	}
	for _, key := range []string{"", testAPIKey, "anything"} {
		if s.Authorized(key) {
			t.Errorf("Authorized(%q) = true with no key configured; that is a public shortener", key)
		}
	}
	// The domain refuses by itself too, so a caller that skips Authorized still cannot write.
	ctx := context.Background()
	if _, err := s.Create(ctx, linktools.CreateRequest{URL: "https://example.com/"}, ""); !errors.Is(err, linktools.ErrDisabled) {
		t.Errorf("Create with no key configured = %v, want ErrDisabled", err)
	}
	if _, err := s.Recent(ctx, 10); !errors.Is(err, linktools.ErrDisabled) {
		t.Errorf("Recent with no key configured = %v, want ErrDisabled", err)
	}
	if err := s.Revoke(ctx, "abc1234"); !errors.Is(err, linktools.ErrDisabled) {
		t.Errorf("Revoke with no key configured = %v, want ErrDisabled", err)
	}
}

// nil means off: every method says so rather than panicking, so the handler answers 503.
func TestNilShortenerIsSafeAndDisabled(t *testing.T) {
	t.Parallel()
	var s *linktools.Shortener
	ctx := context.Background()

	if _, err := s.Create(ctx, linktools.CreateRequest{URL: "https://example.com/"}, ""); !errors.Is(err, linktools.ErrDisabled) {
		t.Errorf("Create on a nil *Shortener = %v, want ErrDisabled", err)
	}
	if _, err := s.Resolve(ctx, "abc1234"); !errors.Is(err, linktools.ErrDisabled) {
		t.Errorf("Resolve on a nil *Shortener = %v, want ErrDisabled", err)
	}
	if _, err := s.Recent(ctx, 10); !errors.Is(err, linktools.ErrDisabled) {
		t.Errorf("Recent on a nil *Shortener = %v, want ErrDisabled", err)
	}
	// The two that report no error must still be safe: the handler reaches them on the same paths.
	if got := s.ShortURL("abc1234"); got != "" {
		t.Errorf("ShortURL on a nil *Shortener = %q, want the empty string", got)
	}
	if s.Authorized(testAPIKey) {
		t.Error("a nil *Shortener authorised a caller; a disabled feature authorises nobody")
	}
	if s.HasKey() {
		t.Error("HasKey() on a nil *Shortener = true")
	}
	s.RecordHit("abc1234") // must not panic
}

// Both sides are SHA-256'd before the constant-time compare, which returns at once on a length
// mismatch: raw strings would leak the key's length. The short and long cases test exactly that.
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

// A valid target fails later at the offline insert, so check for ErrInvalidTarget, not any error.
func createErr(t *testing.T, s *linktools.Shortener, req linktools.CreateRequest) error {
	t.Helper()
	_, err := s.Create(context.Background(), req, "")
	return err
}

// Redirects send a stranger's browser to the target, so only schemes fetched over the wire are allowed.
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
		if err := createErr(t, s, linktools.CreateRequest{URL: target}); !errors.Is(err, linktools.ErrInvalidTarget) {
			t.Errorf("Create(%q) = %v, want ErrInvalidTarget — /s/<code> would hand this to a browser", target, err)
		}
	}
}

// Without this check, /s/x → http://192.168.1.1/setup.cgi is a router-CSRF launcher on the victim's LAN.
// localhost is refused by NAME too: a hostile resolver need not agree where it points.
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
		if err := createErr(t, s, linktools.CreateRequest{URL: target}); !errors.Is(err, linktools.ErrInvalidTarget) {
			t.Errorf("Create(%q) = %v, want ErrInvalidTarget — this alias would point a stranger's browser at their own network", target, err)
		}
	}
}

// Plus credentials: userinfo before the host disguises a destination, so it is never stored.
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
		if err := createErr(t, s, linktools.CreateRequest{URL: target}); !errors.Is(err, linktools.ErrInvalidTarget) {
			t.Errorf("Create(%q) = %v, want ErrInvalidTarget", label, err)
		}
	}
}

// A validator that rejects everything is not one: the offline create fails, but not as a bad TARGET.
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
		if err := createErr(t, s, linktools.CreateRequest{URL: target}); errors.Is(err, linktools.ErrInvalidTarget) {
			t.Errorf("Create(%q) was refused as an unacceptable target: %v", target, err)
		}
	}
}

// Lowercase only, so /s/Foo and /s/foo never differ. Reserved page names are refused, or a slug breaks
// the day that page ships; code-shaped slugs are refused so they never collide with generated codes.
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
		err := createErr(t, s, linktools.CreateRequest{URL: "https://example.com/", Slug: tc.slug})
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
		err := createErr(t, s, linktools.CreateRequest{URL: "https://example.com/", Slug: slug})
		if errors.Is(err, linktools.ErrInvalidSlug) {
			t.Errorf("slug %q was refused: %v", slug, err)
		}
	}
}

// TestNoteIsBounded: the note is rendered on the operator console (§7/§8).
func TestNoteIsBounded(t *testing.T) {
	t.Parallel()
	err := createErr(t, offlineShortener(t), linktools.CreateRequest{URL: "https://example.com/", Note: strings.Repeat("n", 300)})
	if !errors.Is(err, linktools.ErrInvalidNote) {
		t.Errorf("a 300-byte note was accepted; the cap is 256 (got %v)", err)
	}
}

// With no cleaner, refuse: storing the raw target while reporting a cleaned one lies about the link.
func TestCleanRequestedWithoutACleanerFailsClosed(t *testing.T) {
	t.Parallel()
	s := offlineShortener(t) // CleanTarget deliberately left nil
	err := createErr(t, s, linktools.CreateRequest{URL: "https://example.com/?utm_source=x", Clean: true})
	if !errors.Is(err, linktools.ErrDisabled) {
		t.Errorf("Create with Clean and no cleaner = %v, want ErrDisabled; storing an uncleaned target while reporting a cleaned one is the failure this guards", err)
	}
}

func TestCreateResolveRoundTrip(t *testing.T) {
	ctx := context.Background()
	s, _ := liveShortener(t, ctx)

	link, err := s.Create(ctx, linktools.CreateRequest{URL: "https://example.com/a?b=1", Note: "round trip"}, "")
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

// A caller who asked for /s/q4-report and got /s/q4-report-2 will paste the one they asked for.
func TestCustomSlugTakenIsAConflictNotASuffix(t *testing.T) {
	ctx := context.Background()
	s, _ := liveShortener(t, ctx)

	first, err := s.Create(ctx, linktools.CreateRequest{URL: "https://example.com/first", Slug: "q4-report"}, "")
	if err != nil {
		t.Fatalf("first Create: %v", err)
	}
	second, err := s.Create(ctx, linktools.CreateRequest{URL: "https://example.com/second", Slug: "q4-report"}, "")
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

// Mongo's TTL monitor sweeps about every 60s and lags under load, so expiry is enforced in code:
// the document is still present here, and still refuses to resolve.
func TestExpiryIsEnforcedInCodeNotByTheReaper(t *testing.T) {
	ctx := context.Background()
	s, store := liveShortener(t, ctx)

	link := insertExpired(t, ctx, store, "already-expired", "https://example.com/expired")

	// Assert the row is still there, or a swept row would pass the check below for the wrong reason.
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

	// A future TTL must still resolve, or "enforced in code" would just mean "broken".
	live, err := s.Create(ctx, linktools.CreateRequest{URL: "https://example.com/live", TTL: "1h"}, "")
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

// The document survives: a hard delete frees the slug, and re-registering it is alias takeover.
func TestRevokedLinkDoesNotResolve(t *testing.T) {
	ctx := context.Background()
	s, store := liveShortener(t, ctx)

	link, err := s.Create(ctx, linktools.CreateRequest{URL: "https://example.com/revoked", Slug: "to-revoke"}, "")
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
	if _, err := s.Create(ctx, linktools.CreateRequest{URL: "https://evil.tld/", Slug: "to-revoke"}, ""); !errors.Is(err, linktools.ErrSlugTaken) {
		t.Errorf("a revoked slug was reissuable (%v); every copy of the old link would silently change destination", err)
	}
}

// Telling them apart is an existence oracle over the guessable custom-slug namespace. Resolve's
// one-word reason is for the operator; handler.redirect answers a constant 404 for all three.
func TestNoExistenceOracle(t *testing.T) {
	ctx := context.Background()
	s, store := liveShortener(t, ctx)

	expired := insertExpired(t, ctx, store, "gone-expired", "https://example.com/e")
	revoked, err := s.Create(ctx, linktools.CreateRequest{URL: "https://example.com/r", Slug: "gone-revoked"}, "")
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

// Spelled out, not imported, so editing the implementation's table fails the test (no 0, O, I or l).
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// A thousand distinct draws prove crypto/rand over a seeded or sequential source; a real collision
// at 58^7 is negligible. The pool keeps remote round trips fast and contends insert-and-retry.
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
				link, err := s.Create(ctx, linktools.CreateRequest{URL: "https://example.com/gen"}, "")
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

// The list the console key-gates: public, it would defeat code entropy and make hits a read receipt.
func TestRecentListsNewestFirst(t *testing.T) {
	ctx := context.Background()
	s, _ := liveShortener(t, ctx)

	for _, slug := range []string{"first-one", "second-one", "third-one"} {
		if _, err := s.Create(ctx, linktools.CreateRequest{URL: "https://example.com/" + slug, Slug: slug}, ""); err != nil {
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
		// Templates see the field despite its json tag, so only a create that supplied one may set it.
		t.Logf("CreatedIP is populated (%q); the console's view model must omit it explicitly", got[0].CreatedIP)
	}
}
