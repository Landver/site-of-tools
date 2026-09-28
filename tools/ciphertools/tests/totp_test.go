package tests

import (
	"encoding/base32"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

func b32(s string) string { return base32.StdEncoding.EncodeToString([]byte(s)) }

func totpOf(t *testing.T, fields url.Values) *ciphertools.TOTPResult {
	t.Helper()
	res, err := runOp(t, "totp", fields, nil)
	if err != nil {
		t.Fatalf("totp %v: %v", fields, err)
	}
	return res.(*ciphertools.TOTPResult)
}

// RFC 6238 Appendix B: 8-digit codes, with the RFC's seeds (the ASCII digits
// "1234567890" repeated to 20, 32 and 64 bytes for SHA1, SHA256 and SHA512).
func TestTOTPRFC6238Vectors(t *testing.T) {
	seeds := map[string]string{
		"SHA1":   "12345678901234567890",
		"SHA256": "12345678901234567890123456789012",
		"SHA512": "1234567890123456789012345678901234567890123456789012345678901234",
	}
	for _, v := range []struct {
		time                 int64
		sha1, sha256, sha512 string
	}{
		{59, "94287082", "46119246", "90693936"},
		{1111111109, "07081804", "68084774", "25091201"},
		{1111111111, "14050471", "67062674", "99943326"},
		{1234567890, "89005924", "91819424", "93441116"},
		{2000000000, "69279037", "90698825", "38618901"},
		{20000000000, "65353130", "77737706", "47863826"},
	} {
		for algo, want := range map[string]string{"SHA1": v.sha1, "SHA256": v.sha256, "SHA512": v.sha512} {
			r := totpOf(t, url.Values{
				"secret": {b32(seeds[algo])}, "algo": {algo}, "digits": {"8"}, "now": {strconv.FormatInt(v.time, 10)},
			})
			if r.Code != want {
				t.Errorf("T=%d %s: code %s, want %s", v.time, algo, r.Code, want)
			}
			if r.Counter != uint64(v.time/30) || r.Remaining != int(30-v.time%30) {
				t.Errorf("T=%d: counter %d remaining %d", v.time, r.Counter, r.Remaining)
			}
		}
	}
}

// RFC 4226 Appendix D: HOTP of the 20-byte ASCII secret, counters 0 to 9.
func TestHOTPRFC4226Vectors(t *testing.T) {
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	secret := []byte("12345678901234567890")
	for c, code := range want {
		if got := ciphertools.HOTP(secret, uint64(c), 6, "SHA1"); got != code {
			t.Errorf("HOTP(%d) = %s, want %s", c, got, code)
		}
		r := totpOf(t, url.Values{"secret": {b32(string(secret))}, "mode": {"hotp"}, "counter": {strconv.Itoa(c)}})
		if r.Type != "hotp" || r.Code != code || r.Counter != uint64(c) {
			t.Errorf("op counter %d: %+v", c, r)
		}
		if r.Remaining != 0 || r.Period != 0 {
			t.Errorf("HOTP has a countdown: %+v", r)
		}
	}
	// Previous and next are the counter either side; counter 0 has no previous.
	r := totpOf(t, url.Values{"secret": {b32(string(secret))}, "mode": {"hotp"}, "counter": {"0"}})
	if len(r.Codes) != 2 || r.Codes[0].Step != "current" || r.Codes[1].Code != want[1] {
		t.Errorf("counter 0 steps: %+v", r.Codes)
	}
	r = totpOf(t, url.Values{"secret": {b32(string(secret))}, "mode": {"hotp"}, "counter": {"5"}})
	if len(r.Codes) != 3 || r.Codes[0].Code != want[4] || r.Codes[2].Code != want[6] {
		t.Errorf("counter 5 steps: %+v", r.Codes)
	}
}

// Base32 secrets arrive lower case, grouped by spaces or dashes, with or
// without padding (docs/03-correctness-traps.md, TOTP).
func TestTOTPSecretNormalised(t *testing.T) {
	const now = "1700000000"
	want := totpOf(t, url.Values{"secret": {"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}, "now": {now}})
	for _, s := range []string{
		"gezdgnbvgy3tqojqgezdgnbvgy3tqojq",
		"gezd gnbv gy3t qojq gezd gnbv gy3t qojq",
		"GEZD-GNBV-GY3T-QOJQ-GEZD-GNBV-GY3T-QOJQ",
		"  GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n",
	} {
		if got := totpOf(t, url.Values{"secret": {s}, "now": {now}}); got.Code != want.Code || got.Secret != want.Secret {
			t.Errorf("%q: code %s secret %s, want %s %s", s, got.Code, got.Secret, want.Code, want.Secret)
		}
	}
	// A 10-byte secret is 16 characters, no padding; padded forms read the same.
	a := totpOf(t, url.Values{"secret": {"JBSWY3DPEHPK3PXP"}, "now": {now}})
	b := totpOf(t, url.Values{"secret": {"jbswy3dpehpk3pxp===="}, "now": {now}})
	if a.Code != b.Code || a.SecretBytes != 10 {
		t.Errorf("padding changed the code: %s vs %s (%d bytes)", a.Code, b.Code, a.SecretBytes)
	}
}

func TestTOTPInputErrors(t *testing.T) {
	const sec = "JBSWY3DPEHPK3PXP"
	for _, c := range []struct {
		fields url.Values
		want   string
	}{
		{url.Values{"secret": {"JBSW Y3DP 1HPK"}}, "at offset 10"},
		{url.Values{}, "no secret given"},
		{url.Values{"secret": {"otpauth-migration://offline?data=CjEKCkhlbGxv"}}, "otpauth-migration"},
		{url.Values{"secret": {sec}, "digits": {"9"}}, "digits: 9 is above the limit of 8"},
		{url.Values{"secret": {sec}, "period": {"10"}}, "period: 10 is below the minimum of 15"},
		{url.Values{"secret": {sec}, "period": {"301"}}, "period: 301 is above the limit of 300"},
		{url.Values{"secret": {sec}, "algo": {"MD5"}}, "want SHA1, SHA256 or SHA512"},
		{url.Values{"secret": {sec}, "mode": {"motp"}}, "want totp or hotp"},
		{url.Values{"secret": {sec}, "mode": {"hotp"}, "counter": {"-1"}}, "counter: want a whole number"},
		{url.Values{"secret": {"otpauth://totp/x?secret=" + sec + "&digits=10"}}, "the URI's digits"},
		{url.Values{"secret": {"otpauth://totp/x?secret=" + sec + "&period=5"}}, "the URI's period"},
		{url.Values{"secret": {"otpauth://totp/x?issuer=Example"}}, "no secret parameter"},
		{url.Values{"secret": {"otpauth://motp/x?secret=" + sec}}, "should be totp or hotp"},
		{url.Values{"secret": {"otpauth://totp/x?secret=0189"}}, "the URI's secret"},
	} {
		_, err := runOp(t, "totp", c.fields, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: err = %v, want %q", c.fields, err, c.want)
		}
	}
}

// The Key Uri Format example, and every parameter read back.
func TestParseOTPURI(t *testing.T) {
	s, notes, err := ciphertools.ParseOTPURI("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example")
	if err != nil {
		t.Fatal(err)
	}
	if s.Type != "totp" || s.Account != "alice@google.com" || s.Issuer != "Example" || s.Algorithm != "SHA1" ||
		s.Digits != 6 || s.Period != 30 || string(s.Secret) != "Hello!\xde\xad\xbe\xef" || len(notes) != 0 {
		t.Errorf("parsed %+v, notes %v", s, notes)
	}

	s, _, err = ciphertools.ParseOTPURI("otpauth://hotp/ACME%20Co%3Ajohn.doe@email.com?secret=jbswy3dpehpk3pxp&issuer=ACME%20Co&algorithm=SHA512&digits=8&counter=42")
	if err != nil {
		t.Fatal(err)
	}
	if s.Type != "hotp" || s.Issuer != "ACME Co" || s.Account != "john.doe@email.com" || s.Algorithm != "SHA512" ||
		s.Digits != 8 || s.Counter != 42 {
		t.Errorf("encoded colon label: %+v", s)
	}

	// Issuer only in the label: taken from there, and noted.
	s, notes, _ = ciphertools.ParseOTPURI("otpauth://totp/Example:%20alice?secret=JBSWY3DPEHPK3PXP&period=60")
	if s.Issuer != "Example" || s.Account != "alice" || s.Period != 60 || !noted(notes, "no issuer parameter") {
		t.Errorf("label issuer: %+v %v", s, notes)
	}
	// Label and parameter disagree: the parameter wins, with a warning.
	s, notes, _ = ciphertools.ParseOTPURI("otpauth://totp/Old:alice?secret=JBSWY3DPEHPK3PXP&issuer=New")
	if s.Issuer != "New" || !noted(notes, "differs") {
		t.Errorf("issuer mismatch: %+v %v", s, notes)
	}
}

// BuildOTPURI -> ParseOTPURI gives the same settings back, awkward labels
// included, and every part is percent-encoded with %20 for a space.
func TestOTPURIRoundTrip(t *testing.T) {
	for _, s := range []*ciphertools.OTPSettings{
		{Type: "totp", Account: "alice@example.com", Issuer: "Example", Algorithm: "SHA1", Digits: 6, Period: 30, Secret: []byte("12345678901234567890")},
		{Type: "totp", Account: "bob smith+tag@example.com", Issuer: "ACME: Co & Sons", Algorithm: "SHA256", Digits: 8, Period: 60, Secret: []byte("0123456789abcdef")},
		{Type: "hotp", Account: "ünïcode ☃", Issuer: "Café/Bar?", Algorithm: "SHA512", Digits: 7, Counter: 1 << 40, Secret: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}},
		{Type: "totp", Account: "no-issuer", Algorithm: "SHA1", Digits: 6, Period: 30, Secret: []byte("abcdefghij")},
	} {
		uri := ciphertools.BuildOTPURI(s)
		if strings.ContainsAny(uri, " +") || strings.Count(uri, "?") != 1 {
			t.Errorf("%s: not properly encoded", uri)
		}
		got, _, err := ciphertools.ParseOTPURI(uri)
		if err != nil {
			t.Fatalf("%s: %v", uri, err)
		}
		want := *s
		if want.Type == "hotp" {
			got.Period = 0
		}
		if diff := cmp.Diff(want, *got); diff != "" {
			t.Errorf("%s round trip (-want +got):\n%s", uri, diff)
		}
	}
	// Through the op: the fields build the URI, and pasting it back reproduces the codes.
	r := totpOf(t, url.Values{"secret": {"JBSWY3DPEHPK3PXP"}, "label": {"alice@example.com"}, "issuer": {"My Co"}, "now": {"1700000000"}})
	if r.URI != "otpauth://totp/My%20Co:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=My%20Co&algorithm=SHA1&digits=6&period=30" {
		t.Errorf("URI = %s", r.URI)
	}
	back := totpOf(t, url.Values{"secret": {r.URI}, "now": {"1700000000"}, "digits": {"8"}})
	if back.Code != r.Code || !back.FromURI || back.Digits != 6 || !noted(back.Warnings, "fields are ignored") {
		t.Errorf("pasted URI: %+v", back)
	}
}

// A code one step either side matches and says which; two away doesn't.
func TestTOTPCheckWindow(t *testing.T) {
	secret := []byte("12345678901234567890")
	const now = 1111111111
	step := uint64(now / 30)
	check := func(code string) *ciphertools.OTPCheck {
		t.Helper()
		r := totpOf(t, url.Values{"secret": {b32(string(secret))}, "code": {code}, "now": {strconv.Itoa(now)}})
		if r.Check == nil {
			t.Fatal("no check for a given code")
		}
		return r.Check
	}
	for off, want := range map[int]string{-1: "previous", 0: "current", 1: "next"} {
		c := check(ciphertools.HOTP(secret, step+uint64(off), 6, "SHA1"))
		if !c.Match || c.Step != want || c.Counter != step+uint64(off) {
			t.Errorf("offset %d: %+v", off, c)
		}
	}
	for _, off := range []int{-2, 2} {
		if c := check(ciphertools.HOTP(secret, uint64(int(step)+off), 6, "SHA1")); c.Match {
			t.Errorf("offset %d matched: %+v", off, c)
		}
	}
	// Spaces and dashes in a typed code are ignored; the wrong length and
	// letters are named, not just "no match".
	cur := ciphertools.HOTP(secret, step, 6, "SHA1")
	if c := check(cur[:3] + " " + cur[3:]); !c.Match {
		t.Errorf("spaced code: %+v", c)
	}
	if c := check("12345"); c.Match || !strings.Contains(c.Detail, "5 digits") {
		t.Errorf("short code: %+v", c)
	}
	if c := check("12a456"); c.Match || !strings.Contains(c.Detail, "digits only") {
		t.Errorf("letters: %+v", c)
	}
	if r := totpOf(t, url.Values{"secret": {b32(string(secret))}, "now": {strconv.Itoa(now)}}); r.Check != nil {
		t.Error("check without a code")
	}
}

func TestTOTPWarnings(t *testing.T) {
	r := totpOf(t, url.Values{"secret": {"JBSWY3DPEHPK3PXP"}, "algo": {"SHA256"}, "digits": {"8"}, "period": {"60"}})
	if !noted(r.Warnings, "Google Authenticator ignores") || !noted(r.Warnings, "SHA256, 8 digits and a 60-second period") {
		t.Errorf("Google Authenticator: %+v", r.Warnings)
	}
	if !noted(r.Warnings, "The secret is 10 bytes") {
		t.Errorf("short secret: %+v", r.Warnings)
	}
	r = totpOf(t, url.Values{"secret": {b32("12345678901234567890")}, "label": {"a"}})
	if noted(r.Warnings, "Google Authenticator") || noted(r.Warnings, "The secret is") {
		t.Errorf("defaults warned: %+v", r.Warnings)
	}
}

// The countdown: seconds left in the step, and a fragment that re-runs the
// live form when it reaches zero.
func TestTOTPCountdownAndRender(t *testing.T) {
	r := totpOf(t, url.Values{"secret": {"JBSWY3DPEHPK3PXP"}, "now": {"1700000021"}})
	if r.Remaining != 19 || r.Period != 30 || len(r.Codes) != 3 || r.Codes[1].Until == "" {
		t.Errorf("remaining %d: %+v", r.Remaining, r)
	}
	html := render(t, "totp", url.Values{"secret": {"JBSWY3DPEHPK3PXP"}, "now": {"1700000021"}, "issuer": {"<b>x</b>"}})
	for _, want := range []string{r.Code, "left: 19,", "dispatchEvent(new Event('input', { bubbles: true }))",
		"form[data-cipher=totp]", "destroy()", "otpauth://totp/"} {
		if !strings.Contains(html, want) {
			t.Errorf("fragment lacks %q", want)
		}
	}
	if strings.Contains(html, "<b>x</b>") {
		t.Error("issuer reached the fragment unescaped")
	}
	if html := render(t, "totp", url.Values{"secret": {"JBSWY3DPEHPK3PXP"}, "mode": {"hotp"}}); strings.Contains(html, "x-data") {
		t.Error("HOTP result has a countdown")
	}
}

func TestTOTPPageAndAPI(t *testing.T) {
	e := newCipherApp(t)
	body := url.Values{"secret": {b32("12345678901234567890")}, "algo": {"SHA1"}, "digits": {"8"}, "now": {"59"}}.Encode()
	rec := do(t, e, http.MethodPost, "/totp", body, form, asAPI)
	var got struct {
		Code      string `json:"code"`
		Remaining int    `json:"seconds_remaining"`
		URI       string `json:"uri"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.Code != "94287082" || got.Remaining != 1 {
		t.Fatalf("code %d: %s", rec.Code, rec.Body)
	}
	rec = do(t, e, http.MethodPost, "/totp", body, form, asBrowser)
	if html := rec.Body.String(); rec.Code != http.StatusOK || !strings.Contains(html, "94287082") || !strings.Contains(html, "<!DOCTYPE html>") {
		t.Fatalf("no-JS page: code %d", rec.Code)
	}
	page := do(t, e, http.MethodGet, "/totp", "", "", asBrowser).Body.String()
	if !strings.Contains(page, `data-cipher="totp" data-live`) {
		t.Error("TOTP form isn't live")
	}
}
