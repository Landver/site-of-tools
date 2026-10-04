package ciphertools

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// C8 — TOTP (RFC 6238) and HOTP (RFC 4226), one code path: a TOTP code is the
// HOTP of the time step floor(unix / period). The secret arrives as base32 in
// whatever shape an app printed it (lowercase, grouped by spaces, unpadded) or
// inside an otpauth:// URI, which carries the other settings too.
//
// The form is live. The result's countdown re-runs it when the step ends, by
// dispatching an input event on the form, which the page glue already listens
// for; nothing here keeps time.

func init() {
	register(Op{Name: "totp", Path: "/totp", Page: "totp", Fragment: "cipher/totp-result", Run: runTOTP,
		Fields: []Field{
			{Name: "secret", Kind: KindString, Required: true,
				Description: "The shared secret in base32 (any case; spaces, dashes and padding ignored), e.g. JBSWY3DPEHPK3PXP, or a whole otpauth:// URI, whose settings then replace every field but code and now."},
			{Name: "mode", Kind: KindEnum, Enum: []string{OTPTypeTOTP, OTPTypeHOTP}, Default: OTPTypeTOTP,
				Description: "totp for time-based codes (RFC 6238), hotp for counter-based ones (RFC 4226)."},
			{Name: "algo", Kind: KindEnum, Enum: []string{"SHA1", "SHA256", "SHA512"}, Default: "SHA1",
				Description: "The HMAC behind the codes; nearly every authenticator uses SHA1, and Google Authenticator ignores this setting."},
			otpDigitsField,
			otpPeriodField,
			{Name: "counter", Kind: KindInt, Default: "0", Min: ptr(0), Max: ptr(math.MaxInt64),
				Description: "The HOTP counter (mode hotp); codes come back for counter-1, counter and counter+1."},
			{Name: "code", Kind: KindString,
				Description: "A code to check against the previous, current and next step (or counter)."},
			{Name: "label", Kind: KindString,
				Description: "The account name in the otpauth:// URI the result builds, e.g. alice@example.com."},
			{Name: "issuer", Kind: KindString,
				Description: "The issuer in the otpauth:// URI the result builds, e.g. Example Corp."},
			nowField,
		}})
}

var (
	otpDigitsField = Field{Name: "digits", Kind: KindInt, Default: strconv.Itoa(otpDefaultDigits),
		Min: ptr(otpMinDigits), Max: ptr(otpMaxDigits), Description: "Digits per code; most authenticators show 6."}
	otpPeriodField = Field{Name: "period", Kind: KindInt, Default: strconv.Itoa(otpDefaultPeriod),
		Min: ptr(otpMinPeriod), Max: ptr(otpMaxPeriod), Description: "Seconds per TOTP step (mode totp)."}
)

// OTP types, as the otpauth:// URI names them.
const (
	OTPTypeTOTP = "totp"
	OTPTypeHOTP = "hotp"
)

// otpAlgs are the HMACs RFC 6238 allows, keyed by the otpauth:// spelling.
var otpAlgs = map[string]func() hash.Hash{"SHA1": sha1.New, "SHA256": sha256.New, "SHA512": sha512.New}

// OTP parameter limits. The period cap is the traps doc's; RFC 4226 allows 6
// to 8 digits (9 would no longer fit the 31-bit truncation evenly).
const (
	otpMinDigits, otpMaxDigits, otpDefaultDigits = 6, 8, 6
	otpMinPeriod, otpMaxPeriod, otpDefaultPeriod = 15, 300, 30
)

// OTPSettings is one account: from the form fields, or from an otpauth:// URI.
type OTPSettings struct {
	Type      string
	Account   string
	Issuer    string
	Algorithm string
	Digits    int
	Period    int
	Counter   uint64
	Secret    []byte
}

// TOTPResult is the totp op's answer.
type TOTPResult struct {
	Type      string `json:"type"`
	Algorithm string `json:"algorithm"`
	Digits    int    `json:"digits"`
	Period    int    `json:"period,omitempty"`
	Account   string `json:"account,omitempty"`
	Issuer    string `json:"issuer,omitempty"`
	// Secret is the secret re-encoded: base32, upper case, unpadded.
	Secret      string `json:"secret"`
	SecretBytes int    `json:"secret_bytes"`
	FromURI     bool   `json:"from_uri"`
	// Counter is the current HOTP counter: floor(unix / period) for TOTP.
	Counter uint64 `json:"counter"`
	// Time is the unix second the codes are for (TOTP only).
	Time      int64     `json:"time,omitempty"`
	Remaining int       `json:"seconds_remaining,omitempty"`
	Code      string    `json:"code"`
	Codes     []OTPCode `json:"codes"`
	URI       string    `json:"uri"`
	Check     *OTPCheck `json:"check,omitempty"`
	Warnings  []Warning `json:"warnings,omitempty"`
}

// OTPCode is the code for one step: previous, current or next.
type OTPCode struct {
	Step    string `json:"step"`
	Offset  int    `json:"offset"`
	Counter uint64 `json:"counter"`
	Code    string `json:"code"`
	// From and Until bound a TOTP code's step, in UTC.
	From  string `json:"from,omitempty"`
	Until string `json:"until,omitempty"`
}

// OTPCheck is the answer to "is this code right".
type OTPCheck struct {
	Code  string `json:"code"`
	Match bool   `json:"match"`
	// Step is previous, current or next when the code matched.
	Step    string `json:"step,omitempty"`
	Counter uint64 `json:"counter,omitempty"`
	Detail  string `json:"detail"`
}

func (r *TOTPResult) warn(level, text string) { r.Warnings = append(r.Warnings, Warning{level, text}) }

func runTOTP(in Input) (any, error) {
	now, err := in.now()
	if err != nil {
		return nil, err
	}
	raw := strings.TrimSpace(in.Get("secret"))
	var s *OTPSettings
	var notes []Warning
	fromURI := false
	switch {
	case raw == "":
		return nil, errors.New("no secret given: paste the base32 secret, or the whole otpauth:// URI")
	case hasPrefixFold(raw, "otpauth-migration://"):
		return nil, errors.New("that is a Google Authenticator export (otpauth-migration://), a batch of accounts packed in a protobuf. This page reads one otpauth:// URI at a time")
	case hasPrefixFold(raw, "otpauth:"):
		s, notes, err = ParseOTPURI(raw)
		fromURI = true
	default:
		s, err = otpFromFields(in, raw)
	}
	if err != nil {
		return nil, err
	}
	r, err := OTPCodes(s, now)
	if err != nil {
		return nil, err
	}
	r.FromURI = fromURI
	if fromURI {
		r.warn(LevelInfo, "Settings read from the otpauth:// URI. While a URI is pasted, the mode, algorithm, digits, period, counter, label and issuer fields are ignored.")
	}
	r.Warnings = append(r.Warnings, notes...)
	r.settingWarnings(s)
	if code := in.Get("code"); strings.TrimSpace(code) != "" {
		r.Check = r.check(code)
	}
	return r, nil
}

// otpFromFields reads the settings from the form when the secret is bare base32.
func otpFromFields(in Input, secret string) (*OTPSettings, error) {
	s := &OTPSettings{Account: strings.TrimSpace(in.Get("label")), Issuer: strings.TrimSpace(in.Get("issuer"))}
	var err error
	if s.Secret, err = otpSecret(secret); err != nil {
		return nil, fmt.Errorf("secret: %w", err)
	}
	switch t := strings.ToLower(strings.TrimSpace(in.Get("mode"))); t {
	case "", OTPTypeTOTP:
		s.Type = OTPTypeTOTP
	case OTPTypeHOTP:
		s.Type = OTPTypeHOTP
	default:
		return nil, fmt.Errorf("mode: want totp or hotp, got %q", t)
	}
	if s.Algorithm, err = otpAlgorithm(in.Get("algo")); err != nil {
		return nil, fmt.Errorf("algo: %w", err)
	}
	if s.Digits, err = intField(in, otpDigitsField); err != nil {
		return nil, err
	}
	if s.Period, err = intField(in, otpPeriodField); err != nil {
		return nil, err
	}
	if s.Counter, err = otpCounter(in.Get("counter")); err != nil {
		return nil, fmt.Errorf("counter: %w", err)
	}
	return s, nil
}

// otpSecret decodes a base32 secret. Dashes are blanked rather than cut, so an
// error's offset still points into what was pasted.
func otpSecret(s string) ([]byte, error) {
	b, err := DecodeBytes(strings.ReplaceAll(s, "-", " "), EncBase32)
	if err != nil {
		return nil, fmt.Errorf("%w (base32 uses the letters A to Z and the digits 2 to 7)", err)
	}
	if len(b) == 0 {
		return nil, errors.New("decodes to zero bytes")
	}
	return b, nil
}

func otpAlgorithm(v string) (string, error) {
	a := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(v), "-", ""))
	if a == "" {
		return "SHA1", nil
	}
	if otpAlgs[a] == nil {
		return "", fmt.Errorf("want SHA1, SHA256 or SHA512, got %q", v)
	}
	return a, nil
}

// otpCounter reads a counter up to 2^63-1, so counter+1 can never wrap.
func otpCounter(v string) (uint64, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseUint(v, 10, 63)
	if err != nil {
		return 0, fmt.Errorf("want a whole number from 0 to %d, got %q", uint64(1)<<63-1, v)
	}
	return n, nil
}

// ParseOTPURI reads an otpauth:// URI (Google's Key Uri Format): the type, the
// label as "issuer:account", and the secret, issuer, algorithm, digits, period
// and counter parameters. Missing parameters take the format's defaults; the
// notes say where the URI is out of step with itself.
func ParseOTPURI(raw string) (*OTPSettings, []Warning, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, nil, fmt.Errorf("not a valid otpauth:// URI: %v", unwrapURLError(err))
	}
	if u.Scheme != "otpauth" || u.Opaque != "" {
		return nil, nil, errors.New("not an otpauth:// URI: it should start otpauth://totp/ or otpauth://hotp/")
	}
	var notes []Warning
	note := func(level, text string) { notes = append(notes, Warning{level, text}) }
	s := &OTPSettings{Type: strings.ToLower(u.Host)}
	if s.Type != OTPTypeTOTP && s.Type != OTPTypeHOTP {
		return nil, nil, fmt.Errorf("the URI's type is %q; it should be totp or hotp, as in otpauth://totp/…", u.Host)
	}
	q := u.Query()

	// The label is split before it is unescaped: a literal ':' is the
	// separator, and only when there is none does an encoded one (%3A) count,
	// as the Key Uri Format allows. So an issuer holding an encoded ':' (as
	// BuildOTPURI writes it) reads back whole.
	label := strings.TrimPrefix(u.EscapedPath(), "/")
	rawPrefix, rawAccount, hasPrefix := strings.Cut(label, ":")
	if !hasPrefix {
		if i := indexEncodedColon(label); i >= 0 {
			rawPrefix, rawAccount, hasPrefix = label[:i], label[i+3:], true
		}
	}
	prefix := ""
	if hasPrefix {
		prefix, s.Account = pathUnescape(rawPrefix), strings.TrimLeft(pathUnescape(rawAccount), " ")
	} else {
		s.Account = pathUnescape(label)
	}
	s.Issuer = q.Get("issuer")
	switch {
	case s.Issuer == "" && prefix != "":
		s.Issuer = prefix
		note(LevelInfo, "The URI has no issuer parameter, so the issuer was taken from the label. The Key Uri Format recommends both.")
	case s.Issuer != "" && hasPrefix && prefix != s.Issuer:
		note(LevelWarn, fmt.Sprintf("The label's issuer %q differs from the issuer parameter %q. Apps disagree on which one to show; the parameter is used here.", prefix, s.Issuer))
	}

	secret := q.Get("secret")
	if strings.TrimSpace(secret) == "" {
		return nil, nil, errors.New("the URI has no secret parameter")
	}
	if s.Secret, err = otpSecret(secret); err != nil {
		return nil, nil, fmt.Errorf("the URI's secret: %w", err)
	}
	if s.Algorithm, err = otpAlgorithm(q.Get("algorithm")); err != nil {
		return nil, nil, fmt.Errorf("the URI's algorithm: %w", err)
	}
	s.Digits, s.Period = otpDefaultDigits, otpDefaultPeriod
	if v := q.Get("digits"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < otpMinDigits || n > otpMaxDigits {
			return nil, nil, fmt.Errorf("the URI's digits is %q; want %d to %d", v, otpMinDigits, otpMaxDigits)
		}
		s.Digits = n
	}
	if v := q.Get("period"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < otpMinPeriod || n > otpMaxPeriod {
			return nil, nil, fmt.Errorf("the URI's period is %q; this page takes %d to %d seconds", v, otpMinPeriod, otpMaxPeriod)
		}
		s.Period = n
	}
	if s.Type == OTPTypeHOTP {
		v := q.Get("counter")
		if v == "" {
			note(LevelWarn, "An hotp URI must carry a counter parameter; this one has none, so the counter starts at 0.")
		}
		if s.Counter, err = otpCounter(v); err != nil {
			return nil, nil, fmt.Errorf("the URI's counter: %w", err)
		}
	}
	return s, notes, nil
}

func indexEncodedColon(s string) int {
	i, j := strings.Index(s, "%3A"), strings.Index(s, "%3a")
	if i < 0 || j >= 0 && j < i {
		return j
	}
	return i
}

// pathUnescape decodes one label part; a malformed escape is kept as typed.
func pathUnescape(s string) string {
	if v, err := url.PathUnescape(s); err == nil {
		return v
	}
	return s
}

// unwrapURLError drops net/url's "parse <whole input>:" prefix, which would
// print the secret back into the error.
func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// BuildOTPURI writes s as an otpauth:// URI. The label is "issuer:account",
// each part percent-encoded (a ':' inside either becomes %3A, so the one
// literal ':' is the separator), and spaces are %20 throughout: the Key Uri
// Format asks for that, and some apps show a '+' literally.
func BuildOTPURI(s *OTPSettings) string {
	label := otpEscape(s.Account)
	switch {
	case s.Issuer != "" && s.Account != "":
		label = otpEscape(s.Issuer) + ":" + label
	case s.Issuer != "":
		label = otpEscape(s.Issuer)
	}
	var b strings.Builder
	b.WriteString("otpauth://" + s.Type + "/" + label + "?secret=")
	b.WriteString(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(s.Secret))
	if s.Issuer != "" {
		b.WriteString("&issuer=" + otpEscape(s.Issuer))
	}
	b.WriteString("&algorithm=" + s.Algorithm + "&digits=" + strconv.Itoa(s.Digits))
	if s.Type == OTPTypeHOTP {
		b.WriteString("&counter=" + strconv.FormatUint(s.Counter, 10))
	} else {
		b.WriteString("&period=" + strconv.Itoa(s.Period))
	}
	return b.String()
}

// otpEscape percent-encodes for a path segment or a query value alike: every
// byte but letters, digits and "-._~" (RFC 3986 unreserved).
func otpEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// HOTP is RFC 4226: HMAC over the counter as 8 bytes big-endian, then dynamic
// truncation (the low nibble of the last byte picks 4 bytes, whose top bit is
// masked off) and the last digits of that number.
func HOTP(secret []byte, counter uint64, digits int, algorithm string) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(otpAlgs[algorithm], secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

// OTPCodes computes the previous, current and next codes for s at now.
func OTPCodes(s *OTPSettings, now time.Time) (*TOTPResult, error) {
	if otpAlgs[s.Algorithm] == nil {
		return nil, fmt.Errorf("unknown algorithm %q", s.Algorithm)
	}
	r := &TOTPResult{
		Type: s.Type, Algorithm: s.Algorithm, Digits: s.Digits, Account: s.Account, Issuer: s.Issuer,
		Secret:      base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(s.Secret),
		SecretBytes: len(s.Secret), URI: BuildOTPURI(s),
	}
	base := s.Counter
	if s.Type == OTPTypeTOTP {
		unix := now.Unix()
		if unix < 0 {
			return nil, errors.New("now: the time is before 1970, where TOTP has no steps")
		}
		p := int64(s.Period)
		base = uint64(unix / p)
		r.Period, r.Time, r.Remaining = s.Period, unix, int(p-unix%p)
	}
	r.Counter = base
	for _, off := range []int{-1, 0, 1} {
		if off < 0 && base == 0 {
			continue
		}
		c := base + uint64(off) // wraps to base-1 for off = -1
		code := OTPCode{Step: stepNames[off], Offset: off, Counter: c, Code: HOTP(s.Secret, c, s.Digits, s.Algorithm)}
		if s.Type == OTPTypeTOTP {
			from := int64(c) * int64(s.Period)
			code.From = time.Unix(from, 0).UTC().Format("15:04:05")
			code.Until = time.Unix(from+int64(s.Period), 0).UTC().Format("15:04:05 UTC")
		}
		if off == 0 {
			r.Code = code.Code
		}
		r.Codes = append(r.Codes, code)
	}
	return r, nil
}

var stepNames = map[int]string{-1: "previous", 0: "current", 1: "next"}

// check compares code with every step's code in constant time, then prefers
// the current step when (rarely) two steps share a code.
func (r *TOTPResult) check(input string) *OTPCheck {
	code := strings.Map(func(c rune) rune {
		if c == ' ' || c == '-' || c == '\t' {
			return -1
		}
		return c
	}, strings.TrimSpace(input))
	c := &OTPCheck{Code: code}
	if strings.Trim(code, "0123456789") != "" {
		c.Detail = "A code is digits only."
		return c
	}
	if len(code) != r.Digits {
		c.Detail = fmt.Sprintf("The code has %d digits; these settings make %d-digit codes.", len(code), r.Digits)
		return c
	}
	best := -1
	for i, oc := range r.Codes {
		if subtle.ConstantTimeCompare([]byte(oc.Code), []byte(code)) == 1 &&
			(best < 0 || abs(oc.Offset) < abs(r.Codes[best].Offset)) {
			best = i
		}
	}
	if best < 0 {
		c.Detail = "No match for the previous, current or next step. Check the secret, the algorithm, the digits and the period, and that the device's clock is right."
		if r.Type == OTPTypeHOTP {
			c.Detail = "No match for the previous, current or next counter value. Check the secret, the algorithm and the digits; a device used several times without logging in is more than one ahead."
		}
		return c
	}
	m := r.Codes[best]
	c.Match, c.Step, c.Counter = true, m.Step, m.Counter
	switch {
	case m.Offset == 0 && r.Type == OTPTypeHOTP:
		c.Detail = fmt.Sprintf("Matches counter %d.", m.Counter)
	case m.Offset == 0:
		c.Detail = "Matches the current code."
	case r.Type == OTPTypeHOTP && m.Offset > 0:
		c.Detail = fmt.Sprintf("Matches counter %d, one ahead: the device was used once without the server seeing it. A server resynchronises to it.", m.Counter)
	case r.Type == OTPTypeHOTP:
		c.Detail = fmt.Sprintf("Matches counter %d, one behind: a code the server should already have counted as used.", m.Counter)
	case m.Offset > 0:
		c.Detail = "Matches the next step's code: the device's clock runs ahead. Most servers accept one step either side."
	default:
		c.Detail = "Matches the previous step's code: the device's clock runs behind, or the code was typed as the step changed. Most servers accept one step either side."
	}
	return c
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func (r *TOTPResult) settingWarnings(s *OTPSettings) {
	var odd []string
	if s.Algorithm != "SHA1" {
		odd = append(odd, s.Algorithm)
	}
	if s.Digits != 6 {
		odd = append(odd, fmt.Sprintf("%d digits", s.Digits))
	}
	if s.Type == OTPTypeTOTP && s.Period != 30 {
		odd = append(odd, fmt.Sprintf("a %d-second period", s.Period))
	}
	if len(odd) > 0 {
		r.warn(LevelWarn, fmt.Sprintf("Google Authenticator ignores the algorithm, digits and period, and shows SHA1, 6-digit, 30-second codes whatever the URI says. With %s, check that the app supports it, or its codes won't match these.", joinAnd(odd)))
	}
	if len(s.Secret) < 16 {
		r.warn(LevelWarn, fmt.Sprintf("The secret is %d bytes. RFC 4226 requires at least 16 (128 bits) and recommends 20 (160 bits).", len(s.Secret)))
	}
	if s.Type == OTPTypeHOTP {
		r.warn(LevelInfo, "HOTP codes don't expire. The server moves its counter on after each accepted code, so the next login needs the next counter.")
	}
	if s.Account == "" && s.Issuer == "" {
		r.warn(LevelInfo, "The URI has no label. Authenticator apps show the label (issuer and account) to tell entries apart, so add one before sharing it.")
	}
}
