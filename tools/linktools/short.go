package linktools

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Landver/site-of-tools/platform"
)

// Shortener is the short-link domain service: the only stateful, abusable
// feature in this suite (docs/04-short-links.md §1). It owns validation,
// code generation and expiry; storage sits below it in LinkStore, per CLAUDE.md
// rule #5, and HTTP sits above it in handler.go.
//
// Nil *Shortener means the feature is off, and every method reports ErrDisabled
// so the handler answers 503 without a single nil check of its own.
type Shortener struct {
	store   *LinkStore
	keyHash [sha256.Size]byte
	baseURL string

	// CleanTarget is the seam to clean.go, injected at wiring time: it takes a
	// URL and returns the cleaned URL plus the names of the parameters it
	// removed (§9's "cleaned" array, which the handler reports so the strip is
	// never silent). Cleaning is not implemented here; this file only enforces
	// the order §9 fixes:
	//
	//	parse → validate → clean → re-parse and re-validate → store
	//
	// Both halves are load-bearing. Rules in this genre conventionally unwrap
	// redirect parameters (?url=, ?redirect=), and the moment a rule can change
	// the host, a validation that ran before cleaning is void. Create therefore
	// re-runs the full target validation on whatever comes back, and keeps the
	// pre-clean URL in Link.Original so a rule bug stays recoverable.
	//
	// Left nil, a create asking for clean fails closed rather than storing an
	// uncleaned target while reporting a clean one.
	CleanTarget func(raw string) (cleaned string, removed []string, err error)
}

// CreateOptions carries everything about a create except the target itself.
// Every field is optional; the zero value makes a permanent, uncleaned alias
// under a generated code.
type CreateOptions struct {
	Slug      string        // custom slug; empty = generate a code
	Note      string        // operator label, rendered on the console
	TTL       time.Duration // <= 0 means permanent
	Clean     bool          // strip trackers before storing (needs CleanTarget)
	CreatedIP string        // forensics only, never rendered or serialised
}

var (
	// ErrInvalidTarget: the destination is not a URL we will ever redirect to.
	// 400 (docs/04-short-links.md §9).
	ErrInvalidTarget = errors.New("target URL is not acceptable")
	// ErrInvalidSlug: the custom slug is malformed, reserved, or shaped like a
	// generated code. 400.
	ErrInvalidSlug = errors.New("custom slug is not acceptable")
	// ErrInvalidNote: note over the cap. 400.
	ErrInvalidNote = errors.New("note is too long")
	// ErrSlugTaken: the slug exists. 409, never a silent suffix — a caller who
	// asked for /s/q4-report and got /s/q4-report-2 will paste the one they
	// asked for.
	ErrSlugTaken = errors.New("that slug is already taken")
)

const (
	// base58Alphabet: digits and letters minus 0, O, I and l. These codes get
	// read aloud and typed by hand (docs/04-short-links.md §3).
	base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	// base58Reject: the smallest byte value that would bias the modulo. 256 is
	// not a multiple of 58, so bytes at or above this are discarded and redrawn
	// rather than folded, which would make 24 of the 58 characters ~1.8% more
	// likely than the rest.
	base58Reject = 256 - 256%len(base58Alphabet)
	// codeLength: 7 → 58^7 ≈ 2.2 × 10^12. The claim covers generated codes
	// only; custom slugs share the namespace and are dictionary-shaped.
	codeLength = 7
	// maxCodeAttempts: insert-and-retry budget for a duplicate key. Five is
	// already absurd at this collision probability; the point is a bound.
	maxCodeAttempts = 5
	// maxTargetLen: above every real browser limit (§7).
	maxTargetLen = 2048
	// maxNoteLen: it is rendered on the console (§7).
	maxNoteLen = 256
	// shortPath: the prefixed path from §2. A prefix means page names and alias
	// names can never collide, and a future page can never retroactively break
	// an alias somebody already pasted into their notes.
	shortPath = "/s/"
)

// slugPattern is docs/04-short-links.md §3 verbatim: lowercase only, so /s/Foo
// and /s/foo cannot be different links.
var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,63}$`)

// codePattern is the shape check every lookup key passes before it is allowed
// near a Mongo filter (§3). It is the union of a generated code and a slug.
var codePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)

// reservedSlugs is the list from docs/03-architecture.md §3: every page name,
// plus the ones a future page might want. Cheap to over-reserve now, impossible
// to reclaim later without breaking a link someone already has. The dotted
// entries can never match slugPattern anyway; they are kept so the two lists
// read the same.
var reservedSlugs = map[string]bool{
	"s": true, "clean": true, "trace": true, "short": true, "preview": true,
	"api": true, "static": true, "extension": true, "diff": true, "curl": true,
	"encoding": true, "encode": true, "utm": true, "extract": true, "qr": true,
	"rules": true, "robots.txt": true, "sitemap.xml": true, "health": true,
	"favicon.ico": true, "admin": true, "login": true,
}

// NewShortener wires the domain service. It returns nil — the feature off —
// when there is no store or no API key.
//
// The empty-key case is the one worth stating: an unset LINK_API_KEY means
// nobody can create, never that anybody can (docs/04-short-links.md §5). A
// public shortener is found by scanners within days, and when one is used for
// phishing the blocklists take the whole domain, not the offending path: the
// portfolio, the blog and all four tools, with an appeal measured in weeks. So
// the write path fails closed on a wiring mistake, exactly as it does on a
// missing MONGODB_URI.
//
// baseURL is the origin aliases are handed out under, config-driven so moving
// to a dedicated short domain stays a one-line change (§2).
func NewShortener(store *LinkStore, apiKey, baseURL string) *Shortener {
	if store == nil || apiKey == "" {
		return nil
	}
	return &Shortener{
		store:   store,
		keyHash: sha256.Sum256([]byte(apiKey)),
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
	}
}

// Authorized reports whether key is the configured API key.
//
// Both sides are SHA-256'd first. subtle.ConstantTimeCompare returns 0
// immediately on a length mismatch, so comparing the raw strings would leak the
// key's length; hashing makes both operands fixed-length (§5). A nil receiver
// authorises nobody.
func (s *Shortener) Authorized(key string) bool {
	if s == nil {
		return false
	}
	got := sha256.Sum256([]byte(key))
	return subtle.ConstantTimeCompare(got[:], s.keyHash[:]) == 1
}

// ShortURL renders the public form of a code. Relative when no base URL is
// configured, which is what dev wants and what a template can still link.
func (s *Shortener) ShortURL(code string) string {
	if s == nil {
		return ""
	}
	return s.baseURL + shortPath + code
}

// Create validates a target and stores one alias.
//
// Order is §9's, and it is fixed: parse → validate → clean → re-parse and
// re-validate → store. Callers get back the stored Link; the response's
// "cleaned" array is the handler's to report from CleanTarget's second return,
// and Link.Original is set whenever cleaning changed the URL.
func (s *Shortener) Create(ctx context.Context, target string, opt CreateOptions) (*Link, error) {
	if s == nil {
		return nil, ErrDisabled
	}
	note := strings.TrimSpace(opt.Note)
	if len(note) > maxNoteLen {
		return nil, fmt.Errorf("%w: %d bytes, the limit is %d", ErrInvalidNote, len(note), maxNoteLen)
	}

	u, err := validateTarget(target)
	if err != nil {
		return nil, err
	}
	final, original := u.String(), ""
	// Names of the parameters cleaning removed. §9 makes this a stated property
	// of the response — "the response names what went, so it is never a silent
	// mutation" — so it is carried back on the Link rather than discarded.
	var strippedNames []string

	if opt.Clean {
		if s.CleanTarget == nil {
			return nil, fmt.Errorf("%w: cleaning was requested but no cleaner is wired", ErrDisabled)
		}
		cleaned, removed, err := s.CleanTarget(final)
		if err != nil {
			return nil, fmt.Errorf("%w: cleaning failed: %v", ErrInvalidTarget, err)
		}
		// Re-validate from scratch. Cleaning is only supposed to delete query
		// parameters, but "supposed to" is not a security boundary: a rule that
		// rewrites scheme, host or port would otherwise inherit a validation
		// that ran against a different URL.
		cu, err := validateTarget(cleaned)
		if err != nil {
			return nil, err
		}
		if cu.String() != final {
			original, final = final, cu.String()
		}
		strippedNames = removed
	}

	now := time.Now()
	l := &Link{
		Target:    final,
		Original:  original,
		Cleaned:   strippedNames,
		Note:      note,
		CreatedAt: now,
		CreatedIP: opt.CreatedIP,
	}
	if opt.TTL > 0 {
		exp := now.Add(opt.TTL)
		l.ExpiresAt = &exp
	}

	if opt.Slug != "" {
		slug, err := validateSlug(opt.Slug)
		if err != nil {
			return nil, err
		}
		l.Code = slug
		if err := s.store.Insert(ctx, l); err != nil {
			if errors.Is(err, ErrCodeTaken) {
				return nil, fmt.Errorf("%w: %s", ErrSlugTaken, slug)
			}
			return nil, err
		}
		return l, nil
	}

	// Generated codes: insert and retry on a duplicate key, never
	// check-then-insert — that is a race, and the unique index is the only
	// thing that can arbitrate it (§3).
	for attempt := 0; attempt < maxCodeAttempts; attempt++ {
		code, err := newCode()
		if err != nil {
			return nil, err
		}
		l.Code = code
		err = s.store.Insert(ctx, l)
		if err == nil {
			return l, nil
		}
		if !errors.Is(err, ErrCodeTaken) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("no free code after %d attempts", maxCodeAttempts)
}

// Resolve returns the link a code points at, or ErrLinkNotFound.
//
// Expiry is enforced here, against time.Now(), regardless of whether the
// document is still present. Mongo's TTL monitor sweeps roughly every 60
// seconds and lags under load, so a resolver that treated document-absence as
// expiry would keep serving a revoked link for a minute or more, silently. The
// index is garbage collection, never the enforcement point (§4).
//
// "Expired", "revoked" and "never existed" all come back as the same error on
// purpose: distinguishing them is an existence oracle over the guessable
// custom-slug namespace (§7).
//
// The stored scheme is checked again on the way out. It was already checked at
// create, and that is the point — a row written by an earlier buggy version, or
// by anyone who ever gets write access to the database, must not turn the
// redirect handler into a javascript: dispenser (§6).
func (s *Shortener) Resolve(ctx context.Context, code string) (*Link, error) {
	if s == nil {
		return nil, ErrDisabled
	}
	code, err := validateCode(code)
	if err != nil {
		return nil, err
	}
	l, err := s.store.ByCode(ctx, code)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if l.RevokedAt != nil && !l.RevokedAt.After(now) {
		return nil, fmt.Errorf("%w: revoked", ErrLinkNotFound)
	}
	if l.ExpiresAt != nil && !l.ExpiresAt.After(now) {
		return nil, fmt.Errorf("%w: expired", ErrLinkNotFound)
	}
	if u, err := url.Parse(l.Target); err != nil || !linkableSchemes[strings.ToLower(u.Scheme)] {
		return nil, fmt.Errorf("%w: stored target is not an http(s) URL", ErrLinkNotFound)
	}
	return l, nil
}

// RecordHit counts one redirect. Deliberately separate from Resolve so the
// routes that resolve without being a redirect — the QR image, the console —
// do not inflate the counter. Asynchronous and nil-safe; see
// LinkStore.RecordHit for why it cannot use the request context.
func (s *Shortener) RecordHit(code string) {
	if s == nil {
		return
	}
	s.store.RecordHit(code)
}

// Recent lists the newest aliases for the key-gated console (§8). The console
// is key-gated precisely because this list defeats §3's entropy argument
// outright and turns hits/last_hit_at into a read-receipt oracle.
func (s *Shortener) Recent(ctx context.Context, n int64) ([]Link, error) {
	if s == nil {
		return nil, ErrDisabled
	}
	return s.store.Recent(ctx, n)
}

// newCode draws codeLength characters of base58 from crypto/rand.
//
// Never math/rand, whose sequences are predictable, and never a hash of the
// target: that is worse than it looks, because it makes the resolver an oracle
// for "has anyone shortened this exact URL" (§3).
func newCode() (string, error) {
	buf := make([]byte, codeLength*2) // slack for rejected draws
	out := make([]byte, 0, codeLength)
	for len(out) < codeLength {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("read random bytes: %w", err)
		}
		for _, b := range buf {
			if int(b) >= base58Reject {
				continue
			}
			out = append(out, base58Alphabet[int(b)%len(base58Alphabet)])
			if len(out) == codeLength {
				break
			}
		}
	}
	return string(out), nil
}

// validateTarget parses and screens a destination. Returns the parsed URL so
// the caller stores a round-tripped form rather than raw caller text.
//
// Scheme, address and port, per §6. Hostnames are deliberately NOT resolved:
// rejecting literals is free, resolving a caller-chosen name is a DNS lookup
// we decline to make. That leaves a hostname that resolves to a private
// address unscreened, which is the accepted residual — the API key already
// closes the population that could exploit it.
func validateTarget(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("%w: no URL given", ErrInvalidTarget)
	}
	if len(raw) > maxTargetLen {
		return nil, fmt.Errorf("%w: %d bytes, the limit is %d", ErrInvalidTarget, len(raw), maxTargetLen)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTarget, err)
	}
	// linkableSchemes is url.go's allowlist, shared so the redirect and the
	// Inspect page can never disagree about what is safe to navigate to.
	if !linkableSchemes[strings.ToLower(u.Scheme)] {
		return nil, fmt.Errorf("%w: scheme %q is not http or https", ErrInvalidTarget, u.Scheme)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: credentials before the host disguise the real destination", ErrInvalidTarget)
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" {
		return nil, fmt.Errorf("%w: no host", ErrInvalidTarget)
	}
	// localhost resolves to loopback on a normal machine, but a hostile
	// resolver need not agree, so it is refused by name as well as by address.
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return nil, fmt.Errorf("%w: %s is not a permitted destination", ErrInvalidTarget, host)
	}
	// Without the literal check, /s/aB3xY9k → http://192.168.1.1/setup.cgi is a
	// router-CSRF launcher: the victim's own browser, on their own LAN, with
	// their cookies, and a scheme-only allowlist waves it through.
	if addr, perr := netip.ParseAddr(host); perr == nil {
		if !platform.PubliclyRoutable(addr) {
			return nil, fmt.Errorf("%w: %s is not publicly routable", ErrInvalidTarget, addr)
		}
	} else if err := publicHostnameShape(host); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTarget, err)
	}
	if p := u.Port(); p != "" && p != "80" && p != "443" {
		return nil, fmt.Errorf("%w: port %s is outside 80 and 443", ErrInvalidTarget, p)
	}
	return u, nil
}

// validateSlug screens a caller-chosen slug, §3.
//
// Runs entirely on the string, before anything reaches a Mongo filter. That
// ordering is the operator-injection guard: combined with a request body that
// decodes into a typed struct with string fields only, a slug arriving as
// {"$ne": null} never becomes a query operator. One line to prevent, expensive
// to retrofit.
func validateSlug(slug string) (string, error) {
	s := strings.TrimSpace(slug)
	if !slugPattern.MatchString(s) {
		return "", fmt.Errorf("%w: must be 2-64 characters of lowercase a-z, 0-9 and -, starting with a letter or digit", ErrInvalidSlug)
	}
	if reservedSlugs[s] {
		return "", fmt.Errorf("%w: %q is reserved for a page name", ErrInvalidSlug, s)
	}
	if isGeneratedShape(s) {
		return "", fmt.Errorf("%w: %q has the shape of a generated code", ErrInvalidSlug, s)
	}
	return s, nil
}

// isGeneratedShape reports whether s could have come out of newCode. A slug
// that could must be refused, so a custom slug can never occupy — or collide
// with — the generated-code space (§3).
func isGeneratedShape(s string) bool {
	if len(s) != codeLength {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune(base58Alphabet, r) {
			return false
		}
	}
	return true
}

// validateCode screens a lookup key before it is used as a filter value. Both
// namespaces pass through here — a generated code is case-sensitive base58, a
// slug is lowercase — so it only enforces the shared shape and the length
// bound. A key that cannot exist is answered as a miss, not as a bad request,
// so probing the validator tells an attacker nothing the resolver would not.
func validateCode(code string) (string, error) {
	code = strings.TrimSpace(code)
	if !codePattern.MatchString(code) {
		return "", ErrLinkNotFound
	}
	return code, nil
}

// publicHostnameShape rejects anything that is not a syntactically valid public
// DNS name. It exists because netip.ParseAddr only accepts CANONICAL dotted-quad,
// while browsers, getaddrinfo and inet_aton are far more liberal — so a
// "does it contain a dot?" test is not an address check at all.
//
// Accepted by a browser and missed by netip: 127.1, 192.168.1, 0x7f.1,
// 0177.0.0.1. Each resolves to a private or loopback address, which makes an
// alias to one a router-CSRF launcher aimed at whoever opens the link
// (docs/04-short-links.md §6).
//
// The discriminator is the last label: a real TLD is never all digits and never
// an octal or hex literal, while every liberal IPv4 form ends in a numeric
// label. That one predicate kills the whole class without needing to enumerate
// the forms.
func publicHostnameShape(host string) error {
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		// A single label is a LAN name (http://router/) or an integer-form IPv4
		// address (http://2130706433/) that a browser resolves to 127.0.0.1.
		return fmt.Errorf("%q is not a public hostname", host)
	}
	for _, l := range labels {
		if l == "" {
			return fmt.Errorf("%q has an empty label", host)
		}
		if strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return fmt.Errorf("%q has a label starting or ending with a hyphen", host)
		}
		for _, r := range l {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r >= 0x80 {
				continue
			}
			return fmt.Errorf("%q contains %q, which is not valid in a hostname", host, r)
		}
	}
	tld := labels[len(labels)-1]
	if allDigits(tld) {
		return fmt.Errorf("%q ends in a numeric label, so it is an address in disguise, not a hostname", host)
	}
	if len(tld) > 1 && (tld[0] == '0' || strings.HasPrefix(tld, "0x")) {
		return fmt.Errorf("%q ends in an octal or hex label, so it is an address in disguise", host)
	}
	return nil
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
