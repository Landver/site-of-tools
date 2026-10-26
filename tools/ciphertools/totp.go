package ciphertools

import (
	"cmp"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
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

// A TOTP code (RFC 6238) is the HOTP (RFC 4226) of the step floor(unix / period).

func init() {
	register(Op{Name: "totp", Path: "/totp", Page: "totp", Fragment: "cipher/totp-result", Run: runTOTP,
		Fields: []Field{
			{Name: "secret", Kind: KindString, Required: true,
				Description: "The shared secret in base32 (any case; spaces, dashes and padding ignored), e.g. JBSWY3DPEHPK3PXP, or a whole otpauth:// URI, whose settings then replace every field but code and now."},
			otpModeField,
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
	otpModeField = Field{Name: "mode", Kind: KindEnum, Enum: []string{OTPTypeTOTP, OTPTypeHOTP}, Default: OTPTypeTOTP,
		Description: "totp for time-based codes (RFC 6238), hotp for counter-based ones (RFC 4226)."}
	// RFC 4226 allows 6 to 8 digits; the period bounds are this page's.
	otpDigitsField = Field{Name: "digits", Kind: KindInt, Default: "6", Min: ptr(6), Max: ptr(8),
		Description: "Digits per code; most authenticators show 6."}
	otpPeriodField = Field{Name: "period", Kind: KindInt, Default: "30", Min: ptr(15), Max: ptr(300),
		Description: "Seconds per TOTP step (mode totp)."}
)

const (
	OTPTypeTOTP = "totp"
	OTPTypeHOTP = "hotp"
)

var otpAlgs = map[string]func() hash.Hash{"SHA1": sha1.New, "SHA256": sha256.New, "SHA512": sha512.New}

// OTPSettings is one account, from the form fields or an otpauth:// URI.
type OTPSettings struct {
	Type, Account, Issuer, Algorithm string
	Digits, Period                   int
	Counter                          uint64
	Secret                           []byte
}

type TOTPResult struct {
	Type        string    `json:"type"`
	Algorithm   string    `json:"algorithm"`
	Digits      int       `json:"digits"`
	Period      int       `json:"period,omitempty"`
	Account     string    `json:"account,omitempty"`
	Issuer      string    `json:"issuer,omitempty"`
	Secret      string    `json:"secret"` // base32, upper case, unpadded
	SecretBytes int       `json:"secret_bytes"`
	FromURI     bool      `json:"from_uri"`
	Counter     uint64    `json:"counter"` // floor(unix / period) for TOTP
	Time        int64     `json:"time,omitempty"`
	Remaining   int       `json:"seconds_remaining,omitempty"`
	Code        string    `json:"code"`
	Codes       []OTPCode `json:"codes"`
	URI         string    `json:"uri"`
	Check       *OTPCheck `json:"check,omitempty"`
	Warnings    Warnings  `json:"warnings,omitempty"`
}

type OTPCode struct {
	Step    string `json:"step"`
	Offset  int    `json:"offset"`
	Counter uint64 `json:"counter"`
	Code    string `json:"code"`
	From    string `json:"from,omitempty"` // TOTP only, UTC
	Until   string `json:"until,omitempty"`
}

type OTPCheck struct {
	Code    string `json:"code"`
	Match   bool   `json:"match"`
	Step    string `json:"step,omitempty"`
	Counter uint64 `json:"counter,omitempty"`
	Detail  string `json:"detail"`
}

func runTOTP(in Input) (any, error) {
	now, err := in.now()
	if err != nil {
		return nil, err
	}
	raw := strings.TrimSpace(in.Get("secret"))
	fromURI := hasPrefixFold(raw, "otpauth:")
	var s *OTPSettings
	var notes []Warning
	switch {
	case raw == "":
		return nil, errors.New("no secret given: paste the base32 secret, or the whole otpauth:// URI")
	case hasPrefixFold(raw, "otpauth-migration://"):
		return nil, errors.New("that is a Google Authenticator export (otpauth-migration://), a batch of accounts packed in a protobuf. This page reads one otpauth:// URI at a time")
	case fromURI:
		s, notes, err = ParseOTPURI(raw)
		notes = append([]Warning{{LevelInfo, "Settings read from the otpauth:// URI. While a URI is pasted, the mode, algorithm, digits, period, counter, label and issuer fields are ignored."}}, notes...)
	default:
		s = &OTPSettings{Account: strings.TrimSpace(in.Get("label")), Issuer: strings.TrimSpace(in.Get("issuer"))}
		if s.Secret, err = otpSecret(raw); err != nil {
			return nil, fmt.Errorf("secret: %w", err)
		}
		if s.Type, err = enumField(in.Get("mode"), otpModeField); err == nil {
			err = s.otpParams(in, "algo", in.Get("algo"))
		}
	}
	if err != nil {
		return nil, err
	}
	r := &TOTPResult{Type: s.Type, Algorithm: s.Algorithm, Digits: s.Digits, Account: s.Account, Issuer: s.Issuer,
		Secret: b32raw.EncodeToString(s.Secret), SecretBytes: len(s.Secret), FromURI: fromURI, Counter: s.Counter,
		URI: BuildOTPURI(s), Warnings: notes}
	if s.Type == OTPTypeTOTP {
		unix, p := now.Unix(), int64(s.Period)
		if unix < 0 {
			return nil, errors.New("now: the time is before 1970, where TOTP has no steps")
		}
		r.Counter, r.Period, r.Time, r.Remaining = uint64(unix/p), s.Period, unix, int(p-unix%p)
	}
	r.Code = HOTP(s.Secret, r.Counter, s.Digits, s.Algorithm)
	for off := -int(min(r.Counter, 1)); off <= 1; off++ { // counter 0 has no previous
		c := r.Counter + uint64(off) // off -1 wraps round to Counter-1
		code := OTPCode{Step: [3]string{"previous", "current", "next"}[off+1], Offset: off, Counter: c, Code: HOTP(s.Secret, c, s.Digits, s.Algorithm)}
		if r.Period > 0 {
			from := time.Unix(int64(c)*int64(r.Period), 0).UTC()
			code.From, code.Until = from.Format("15:04:05"), from.Add(time.Duration(r.Period)*time.Second).Format("15:04:05 UTC")
		}
		r.Codes = append(r.Codes, code)
	}

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
		r.Warnings.add(LevelWarn, fmt.Sprintf("Google Authenticator ignores the algorithm, digits and period, and shows SHA1, 6-digit, 30-second codes whatever the URI says. With %s, check that the app supports it, or its codes won't match these.", joinAnd(odd)))
	}
	if len(s.Secret) < 16 {
		r.Warnings.add(LevelWarn, fmt.Sprintf("The secret is %d bytes. RFC 4226 requires at least 16 (128 bits) and recommends 20 (160 bits).", len(s.Secret)))
	}
	if s.Type == OTPTypeHOTP {
		r.Warnings.add(LevelInfo, "HOTP codes don't expire. The server moves its counter on after each accepted code, so the next login needs the next counter.")
	}
	if s.Account == "" && s.Issuer == "" {
		r.Warnings.add(LevelInfo, "The URI has no label. Authenticator apps show the label (issuer and account) to tell entries apart, so add one before sharing it.")
	}
	if code := in.Get("code"); strings.TrimSpace(code) != "" {
		r.Check = r.check(code)
	}
	return r, nil
}

// otpParams reads what a form and a URI share; the algorithm is algo in one, algorithm in the other.
// The Key Uri Format makes period TOTP's alone and counter HOTP's, so s.Type picks which is read.
func (s *OTPSettings) otpParams(in Input, algoName, algo string) (err error) {
	a := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(algo), "-", ""))
	if s.Algorithm = cmp.Or(a, "SHA1"); otpAlgs[s.Algorithm] == nil {
		return fmt.Errorf("%s: want SHA1, SHA256 or SHA512, got %q", algoName, algo)
	}
	if s.Digits, err = intField(in, otpDigitsField); err != nil {
		return err
	}
	if s.Type == OTPTypeTOTP {
		s.Period, err = intField(in, otpPeriodField)
		return err
	}
	// Up to 2^63-1, so counter+1 can never wrap.
	if v := strings.TrimSpace(in.Get("counter")); v != "" {
		if s.Counter, err = strconv.ParseUint(v, 10, 63); err != nil {
			return fmt.Errorf("counter: want a whole number from 0 to %d, got %q", int64(math.MaxInt64), v)
		}
	}
	return nil
}

// otpSecret blanks dashes rather than cutting them, so an error's offset points into what was pasted.
func otpSecret(s string) ([]byte, error) {
	b, err := decodeBase32(strings.ReplaceAll(s, "-", " "))
	if err != nil {
		return nil, fmt.Errorf("%w (base32 uses the letters A to Z and the digits 2 to 7)", err)
	}
	if len(b) == 0 {
		return nil, errors.New("decodes to zero bytes")
	}
	return b, nil
}

// ParseOTPURI reads Google's Key Uri Format; the notes say where the URI disagrees with itself.
func ParseOTPURI(raw string) (*OTPSettings, []Warning, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		// Unwrapped: net/url's "parse <whole input>:" prefix would print the secret back.
		return nil, nil, fmt.Errorf("not a valid otpauth:// URI: %v", errors.Unwrap(err))
	}
	if u.Scheme != "otpauth" || u.Opaque != "" {
		return nil, nil, errors.New("not an otpauth:// URI: it should start otpauth://totp/ or otpauth://hotp/")
	}
	s := &OTPSettings{Type: strings.ToLower(u.Host)}
	if s.Type != OTPTypeTOTP && s.Type != OTPTypeHOTP {
		return nil, nil, fmt.Errorf("the URI's type is %q; it should be totp or hotp, as in otpauth://totp/…", u.Host)
	}
	q := u.Query()

	// The label "issuer:account" splits before unescaping: an encoded ':' only
	// separates when there is no literal one, so BuildOTPURI's %3A reads back whole.
	label := strings.TrimPrefix(u.EscapedPath(), "/")
	if i := strings.Index(strings.ToUpper(label), "%3A"); i >= 0 && !strings.Contains(label, ":") {
		label = label[:i] + ":" + label[i+3:]
	}
	prefix, account, hasPrefix := strings.Cut(label, ":")
	prefix, _ = url.PathUnescape(prefix) // EscapedPath's escapes are all valid
	account, _ = url.PathUnescape(account)
	s.Account = strings.TrimLeft(account, " ")
	if !hasPrefix { // the whole label is the account
		prefix, s.Account = "", prefix
	}
	var notes Warnings
	s.Issuer = q.Get("issuer")
	switch {
	case s.Issuer == "" && prefix != "":
		s.Issuer = prefix
		notes.add(LevelInfo, "The URI has no issuer parameter, so the issuer was taken from the label. The Key Uri Format recommends both.")
	case s.Issuer != "" && hasPrefix && prefix != s.Issuer:
		notes.add(LevelWarn, fmt.Sprintf("The label's issuer %q differs from the issuer parameter %q. Apps disagree on which one to show; the parameter is used here.", prefix, s.Issuer))
	}

	if strings.TrimSpace(q.Get("secret")) == "" {
		return nil, nil, errors.New("the URI has no secret parameter")
	}
	if s.Secret, err = otpSecret(q.Get("secret")); err != nil {
		return nil, nil, fmt.Errorf("the URI's secret: %w", err)
	}
	if err = s.otpParams(Input{Fields: q}, "algorithm", q.Get("algorithm")); err != nil {
		return nil, nil, fmt.Errorf("the URI's %w", err)
	}
	if s.Type == OTPTypeHOTP && q.Get("counter") == "" {
		notes.add(LevelWarn, "An hotp URI must carry a counter parameter; this one has none, so the counter starts at 0.")
	}
	return s, notes, nil
}

// BuildOTPURI writes "issuer:account" with only that ':' literal and spaces as %20; some apps show '+' as is.
func BuildOTPURI(s *OTPSettings) string {
	label := strings.Trim(otpEscape(s.Issuer)+":"+otpEscape(s.Account), ":") // the escaped parts hold no ':'
	uri := "otpauth://" + s.Type + "/" + label + "?secret=" + b32raw.EncodeToString(s.Secret)
	if s.Issuer != "" {
		uri += "&issuer=" + otpEscape(s.Issuer)
	}
	uri += "&algorithm=" + s.Algorithm + "&digits=" + strconv.Itoa(s.Digits)
	if s.Type == OTPTypeHOTP {
		return uri + "&counter=" + strconv.FormatUint(s.Counter, 10)
	}
	return uri + "&period=" + strconv.Itoa(s.Period)
}

// otpEscape escapes every byte but RFC 3986's unreserved ones, for a path or a query alike.
func otpEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// HOTP is RFC 4226: HMAC of the 8-byte big-endian counter, then dynamic truncation to 31 bits.
func HOTP(secret []byte, counter uint64, digits int, algorithm string) string {
	m := hmac.New(otpAlgs[algorithm], secret)
	m.Write(binary.BigEndian.AppendUint64(nil, counter))
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:]) & 0x7fffffff
	return fmt.Sprintf("%0*d", digits, bin%uint32(math.Pow10(digits)))
}

// otpCheckDetails per type: one behind, current, one ahead, no match.
var otpCheckDetails = map[string][4]string{
	OTPTypeTOTP: {
		"Matches the previous step's code: the device's clock runs behind, or the code was typed as the step changed. Most servers accept one step either side.",
		"Matches the current code.",
		"Matches the next step's code: the device's clock runs ahead. Most servers accept one step either side.",
		"No match for the previous, current or next step. Check the secret, the algorithm, the digits and the period, and that the device's clock is right.",
	},
	OTPTypeHOTP: {
		"Matches counter {counter}, one behind: a code the server should already have counted as used.",
		"Matches counter {counter}.",
		"Matches counter {counter}, one ahead: the device was used once without the server seeing it. A server resynchronises to it.",
		"No match for the previous, current or next counter value. Check the secret, the algorithm and the digits; a device used several times without logging in is more than one ahead.",
	},
}

// check compares in constant time; when two steps share a code, the current one wins.
func (r *TOTPResult) check(input string) *OTPCheck {
	code := strings.NewReplacer(" ", "", "-", "", "\t", "").Replace(strings.TrimSpace(input))
	var m *OTPCode
	for i, oc := range r.Codes {
		if subtle.ConstantTimeCompare([]byte(oc.Code), []byte(code)) == 1 && (m == nil || oc.Offset == 0) {
			m = &r.Codes[i]
		}
	}
	c := &OTPCheck{Code: code}
	switch details := otpCheckDetails[r.Type]; {
	case strings.Trim(code, "0123456789") != "":
		c.Detail = "A code is digits only."
	case len(code) != r.Digits:
		c.Detail = fmt.Sprintf("The code has %d digits; these settings make %d-digit codes.", len(code), r.Digits)
	case m == nil:
		c.Detail = details[3]
	default:
		detail := strings.ReplaceAll(details[m.Offset+1], "{counter}", strconv.FormatUint(m.Counter, 10))
		c.Match, c.Step, c.Counter, c.Detail = true, m.Step, m.Counter, detail
	}
	return c
}
