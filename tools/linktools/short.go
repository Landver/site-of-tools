package linktools

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/idna"
	"time"

	"github.com/Landver/site-of-tools/platform"
)

// Shortener owns short-link validation, codes and expiry. A nil one means no storage (routes answer
// 503); without an API key it still resolves, but the key gates every write and the list.
type Shortener struct {
	store   *LinkStore
	keyHash [sha256.Size]byte
	hasKey  bool // false: keyHash is the zero value and must never be compared
	baseURL string

	// CleanTarget is injected at wiring time. A rule may unwrap ?url= and change the host, so Create
	// re-validates whatever it returns; left nil, a create asking for clean fails closed.
	CleanTarget func(raw string) (cleaned string, removed []string, err error)
}

// CreateRequest with only URL set makes a permanent, uncleaned link under a generated code. Its fields
// are scalars, so a decoded {"slug":{"$ne":null}} can't reach Mongo as an operator.
type CreateRequest struct {
	URL   string `json:"url" form:"url" jsonschema:"the destination, an http or https URL on a public host"`
	Slug  string `json:"slug,omitempty" form:"slug" jsonschema:"the code to use, e.g. q4-report"`
	TTL   string `json:"ttl,omitempty" form:"ttl" jsonschema:"how long the link lives, a Go duration such as 720h; left out, it never expires"`
	Note  string `json:"note,omitempty" form:"note" jsonschema:"a label for the list, up to 256 bytes"`
	Clean bool   `json:"clean,omitempty" form:"clean" jsonschema:"strip tracking parameters from url first"`
}

const minTTL = time.Minute

var (
	errTTLFormat = errors.New("ttl is not a duration, e.g. 720h")
	errTTLShort  = errors.New("ttl must be at least 1m; leave it out for a link that never expires")
)

const (
	// storageFailure replaces a driver error's text, which can carry connection strings.
	storageFailure = "Something went wrong on our side. Nothing was changed."
	// linkNotFound is fixed: ErrLinkNotFound's wrapped reason (revoked, expired) would be an oracle.
	linkNotFound = "No such short link."
)

var (
	// ErrInvalidTarget: a destination we will never redirect to. 400.
	ErrInvalidTarget = errors.New("destination URL not allowed")
	// ErrInvalidSlug: malformed, reserved, or shaped like a generated code. 400.
	ErrInvalidSlug = errors.New("custom code not allowed")
	// ErrInvalidNote: note over the cap. 400.
	ErrInvalidNote = errors.New("note is too long")
	// ErrSlugTaken: 409, never a silent suffix; whoever asked for q4-report will paste q4-report.
	ErrSlugTaken = errors.New("that code is already taken")
)

const (
	// base58Alphabet drops 0, O, I and l: codes get read aloud and typed by hand.
	base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	// base58Reject: bytes at or above it are redrawn, since folding them would bias 24 of 58 characters.
	base58Reject = 256 - 256%len(base58Alphabet)
	// codeLength: 58^7 ≈ 2.2 × 10^12, a claim about generated codes only, not custom slugs.
	codeLength = 7
	// maxCodeAttempts bounds duplicate-key retries; five is already absurd at this collision rate.
	maxCodeAttempts = 5
	// maxTargetLen: above every real browser limit (§7).
	maxTargetLen = 2048
	// maxNoteLen: it is rendered on the console (§7).
	maxNoteLen = 256
	// shortPath's prefix keeps page names and aliases from colliding, now or with a future page.
	shortPath = "/s/"
)

// slugPattern is lowercase only, so /s/Foo and /s/foo cannot be different links.
var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,63}$`)

// codePattern screens every lookup key before a Mongo filter: a generated code or a slug.
var codePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)

// reservedSlugs over-reserves on purpose: a taken slug can't be reclaimed without breaking a link.
var reservedSlugs = map[string]bool{
	"s": true, "clean": true, "trace": true, "short": true, "preview": true,
	"api": true, "static": true, "extension": true, "diff": true, "curl": true,
	"encoding": true, "encode": true, "utm": true, "extract": true, "qr": true,
	"rules": true, "robots.txt": true, "sitemap.xml": true, "health": true,
	"favicon.ico": true, "admin": true, "login": true,
}

// NewShortener returns nil without a store. An empty apiKey means nobody can create, never anybody:
// a public shortener gets used for phishing, and blocklists then take the whole domain.
func NewShortener(store *LinkStore, apiKey, baseURL string) *Shortener {
	if store == nil {
		return nil
	}
	s := &Shortener{
		store:   store,
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
	}
	if apiKey != "" {
		s.keyHash, s.hasKey = sha256.Sum256([]byte(apiKey)), true
	}
	return s
}

// HasKey reports whether create, list and revoke can run at all. Nil-safe.
func (s *Shortener) HasKey() bool {
	return s != nil && s.hasKey
}

// Authorized hashes both sides first: ConstantTimeCompare returns early on a length mismatch.
func (s *Shortener) Authorized(key string) bool {
	if !s.HasKey() {
		return false
	}
	got := sha256.Sum256([]byte(key))
	return subtle.ConstantTimeCompare(got[:], s.keyHash[:]) == 1
}

// ShortURL is relative when no base URL is configured, which is what dev wants.
func (s *Shortener) ShortURL(code string) string {
	if s == nil {
		return ""
	}
	return s.baseURL + shortPath + code
}

// Code reads a bare code or one of this shortener's short URLs; false means the input is neither.
func (s *Shortener) Code(input string) (string, bool) {
	input = strings.TrimSpace(input)
	if code, err := validateCode(input); err == nil {
		return code, true
	}
	if !strings.Contains(input, "://") {
		input = "https://" + input
	}
	u, err := url.Parse(input)
	if err != nil || s == nil {
		return "", false
	}
	base, err := url.Parse(s.baseURL)
	if err != nil || !strings.EqualFold(u.Host, base.Host) {
		return "", false
	}
	rest, found := strings.CutPrefix(u.Path, shortPath)
	if !found {
		return "", false
	}
	code, err := validateCode(rest)
	return code, err == nil
}

// Create validates req, re-validates whatever cleaning returns, and stores the link under req.Slug or a
// generated code. ip is stored for forensics and never handed back.
func (s *Shortener) Create(ctx context.Context, req CreateRequest, ip string) (*Link, error) {
	if !s.HasKey() {
		return nil, ErrDisabled
	}
	ttl, err := parseTTL(req.TTL)
	if err != nil {
		return nil, err
	}
	note := strings.TrimSpace(req.Note)
	if len(note) > maxNoteLen {
		return nil, fmt.Errorf("%w: %d bytes, the limit is %d", ErrInvalidNote, len(note), maxNoteLen)
	}
	u, err := validateTarget(req.URL)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	l := &Link{Target: u.String(), Note: note, CreatedAt: now, CreatedIP: ip}
	if req.Clean {
		if s.CleanTarget == nil {
			return nil, fmt.Errorf("%w: cleaning was requested but no cleaner is wired", ErrDisabled)
		}
		cleaned, removed, err := s.CleanTarget(l.Target)
		if err != nil {
			return nil, fmt.Errorf("%w: cleaning failed: %v", ErrInvalidTarget, err)
		}
		// Cleaning should only drop parameters, but "should" is no security boundary.
		cu, err := validateTarget(cleaned)
		if err != nil {
			return nil, err
		}
		if cu.String() != l.Target {
			l.Original, l.Target = l.Target, cu.String()
		}
		l.Cleaned = removed // reported back, so cleaning is never a silent mutation
	}
	if ttl > 0 {
		exp := now.Add(ttl)
		l.ExpiresAt = &exp
	}
	if err := s.insert(ctx, l, req.Slug); err != nil {
		return nil, err
	}
	l.Short, l.CreatedIP = s.ShortURL(l.Code), ""
	return l, nil
}

// parseTTL reads a Go duration; "" is a link that never expires.
func parseTTL(ttl string) (time.Duration, error) {
	if ttl == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(ttl)
	switch {
	case err != nil:
		return 0, errTTLFormat
	case d < minTTL:
		return 0, errTTLShort
	}
	return d, nil
}

// insert stores l under slug, or else under generated codes, inserting and retrying, never
// checking first: only the unique index can arbitrate the race.
func (s *Shortener) insert(ctx context.Context, l *Link, slug string) error {
	if slug != "" {
		code, err := validateSlug(slug)
		if err != nil {
			return err
		}
		l.Code = code
		if err = s.store.Insert(ctx, l); errors.Is(err, ErrCodeTaken) {
			return fmt.Errorf("%w: %s, and codes are never reissued, even after a link is revoked", ErrSlugTaken, code)
		}
		return err
	}
	for range maxCodeAttempts {
		code, err := newCode()
		if err != nil {
			return err
		}
		l.Code = code
		if err := s.store.Insert(ctx, l); !errors.Is(err, ErrCodeTaken) {
			return err
		}
	}
	return fmt.Errorf("no free code after %d attempts", maxCodeAttempts)
}

// PublicError maps a short-link error to a status and a message safe to show.
func PublicError(err error) (status int, msg string) {
	switch {
	case errors.Is(err, ErrLinkNotFound):
		return http.StatusNotFound, linkNotFound
	case errors.Is(err, ErrSlugTaken):
		return http.StatusConflict, err.Error()
	case errors.Is(err, ErrDisabled):
		return http.StatusServiceUnavailable, err.Error()
	case errors.Is(err, ErrInvalidTarget), errors.Is(err, ErrInvalidSlug), errors.Is(err, ErrInvalidNote),
		errors.Is(err, errTTLFormat), errors.Is(err, errTTLShort):
		return http.StatusBadRequest, err.Error()
	}
	return http.StatusInternalServerError, storageFailure
}

// Resolve enforces expiry against time.Now(), as Mongo's TTL sweep lags a minute or more. Expired,
// revoked and missing share one error so slugs give no existence oracle, and the scheme is rechecked
// so a bad stored row can't make the redirect a javascript: dispenser.
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

// RecordHit is separate from Resolve so the QR image and the console don't inflate the count.
func (s *Shortener) RecordHit(code string) {
	if s == nil {
		return
	}
	s.store.RecordHit(code)
}

// Revoke only soft-deletes: a freed custom slug, re-registered elsewhere, would silently redirect
// every copy of the old link already in people's notes.
func (s *Shortener) Revoke(ctx context.Context, code string) error {
	if !s.HasKey() {
		return ErrDisabled
	}
	clean, err := validateCode(code)
	if err != nil {
		return ErrLinkNotFound
	}
	return s.store.Revoke(ctx, clean, time.Now())
}

// Recent is key-gated: the list defeats code entropy and turns hit counts into read receipts.
func (s *Shortener) Recent(ctx context.Context, n int64) ([]Link, error) {
	if !s.HasKey() {
		return nil, ErrDisabled
	}
	links, err := s.store.Recent(ctx, n)
	for i := range links {
		links[i].Short = s.ShortURL(links[i].Code)
	}
	return links, err
}

// newCode uses crypto/rand: math/rand is predictable, and hashing the target would make an oracle.
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

// validateTarget screens scheme, address and port. Hostnames are deliberately not resolved: one
// that resolves privately is the accepted residual, since the API key gates who can create.
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
	// Shared with url.go so the redirect and Inspect never disagree on what is safe to open.
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
	// IDNA-normalise before any check, as the resolver does: "１２７.０.０.１" and "①②⑦.0.0.1"
	// both reach 127.0.0.1, which an ASCII digit test would call a hostname.
	normalised, err := idna.Lookup.ToASCII(host)
	if err != nil {
		// A host the IDNA profile refuses is no redirect target, whatever it resolves to.
		return nil, fmt.Errorf("%w: %q is not a usable hostname (%v)", ErrInvalidTarget, host, err)
	}
	host = normalised
	// Refused by name too: a hostile resolver need not map localhost to loopback.
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return nil, fmt.Errorf("%w: %s is not a permitted destination", ErrInvalidTarget, host)
	}
	// Without this, /s/x → http://192.168.1.1/setup.cgi is a router-CSRF launcher on the victim's LAN.
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

// validateSlug runs on the string alone, before any Mongo filter: the operator-injection guard.
func validateSlug(slug string) (string, error) {
	s := strings.TrimSpace(slug)
	if !slugPattern.MatchString(s) {
		return "", fmt.Errorf("%w: use 2–64 lowercase letters, digits and hyphens, starting with a letter or digit", ErrInvalidSlug)
	}
	if reservedSlugs[s] {
		return "", fmt.Errorf("%w: %q is reserved for a page name", ErrInvalidSlug, s)
	}
	if isGeneratedShape(s) {
		return "", fmt.Errorf("%w: %q looks like a generated code; make it longer or shorter, or add a hyphen", ErrInvalidSlug, s)
	}
	return s, nil
}

// isGeneratedShape flags slugs newCode could produce, keeping the two namespaces apart.
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

// validateCode answers an impossible key as a miss, so probing it tells an attacker nothing new.
func validateCode(code string) (string, error) {
	code = strings.TrimSpace(code)
	if !codePattern.MatchString(code) {
		return "", ErrLinkNotFound
	}
	return code, nil
}

// publicHostnameShape catches what netip.ParseAddr misses but browsers accept (127.1, 0x7f.1,
// 0177.0.0.1): every liberal IPv4 form ends in a numeric label, and no real TLD does.
func publicHostnameShape(host string) error {
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		// A LAN name (http://router/) or integer IPv4 (http://2130706433/ is 127.0.0.1).
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
