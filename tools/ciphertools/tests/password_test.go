package tests

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

// hexB64 re-encodes a published hex vector as a PHC string's base64.
func hexB64(h string) string {
	b, _ := hex.DecodeString(h)
	return base64.RawStdEncoding.EncodeToString(b)
}

// Minimum parameters for every algorithm, so the round trips stay fast.
var cheapParams = map[string]url.Values{
	"bcrypt":        {"bcrypt_cost": {"4"}},
	"argon2id":      {"argon2_m": {"8"}, "argon2_t": {"1"}, "argon2_p": {"1"}},
	"scrypt":        {"scrypt_n": {"1024"}, "scrypt_r": {"1"}, "scrypt_p": {"1"}},
	"pbkdf2-sha256": {"pbkdf2_iterations": {"1000"}},
	"pbkdf2-sha512": {"pbkdf2_iterations": {"1000"}},
}

func pwFields(algo, password string) url.Values {
	f := url.Values{"algo": {algo}, "password": {password}}
	for k, v := range cheapParams[algo] {
		f[k] = v
	}
	return f
}

func pwHash(t *testing.T, fields url.Values) *ciphertools.PasswordHashResult {
	t.Helper()
	res, err := runOp(t, "password-hash", fields, nil)
	if err != nil {
		t.Fatalf("password-hash %v: %v", fields.Get("algo"), err)
	}
	return res.(*ciphertools.PasswordHashResult)
}

func pwVerify(t *testing.T, hash, password string) *ciphertools.PasswordVerifyResult {
	t.Helper()
	res, err := runOp(t, "password-verify", url.Values{"hash": {hash}, "password": {password}}, nil)
	if err != nil {
		t.Fatalf("password-verify %q: %v", hash, err)
	}
	return res.(*ciphertools.PasswordVerifyResult)
}

func TestPasswordOpsAreHeavy(t *testing.T) {
	for _, name := range []string{"password-hash", "password-verify"} {
		if op, _ := ciphertools.Lookup(name); !op.Heavy {
			t.Errorf("%s is not Heavy, so it would get the ordinary rate limit", name)
		}
	}
}

// Hash, then verify: every algorithm, with a non-ASCII password so UTF-8 bytes
// are what gets hashed. A wrong password must fail.
func TestPasswordRoundTripEveryAlgorithm(t *testing.T) {
	const pw = "correct horse ☃ battery"
	formats := map[string]*regexp.Regexp{
		"bcrypt":        regexp.MustCompile(`^\$2b\$04\$[./A-Za-z0-9]{53}$`),
		"argon2id":      regexp.MustCompile(`^\$argon2id\$v=19\$m=8,t=1,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$`),
		"scrypt":        regexp.MustCompile(`^\$scrypt\$ln=10,r=1,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$`),
		"pbkdf2-sha256": regexp.MustCompile(`^\$pbkdf2-sha256\$i=1000,l=32\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$`),
		"pbkdf2-sha512": regexp.MustCompile(`^\$pbkdf2-sha512\$i=1000,l=64\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{86}$`),
	}
	for algo, re := range formats {
		t.Run(algo, func(t *testing.T) {
			r := pwHash(t, pwFields(algo, pw))
			if !re.MatchString(r.Encoded) {
				t.Fatalf("encoded %q does not match %s", r.Encoded, re)
			}
			if r.Info.Algorithm != algo || r.PasswordBytes != len(pw) {
				t.Errorf("parsed back as %q, %d bytes", r.Info.Algorithm, r.PasswordBytes)
			}
			if r.Took == "" {
				t.Error("no time taken")
			}
			if v := pwVerify(t, r.Encoded, pw); v.State != ciphertools.PasswordMatch {
				t.Errorf("own hash does not verify: %s: %s", v.State, v.Detail)
			}
			if v := pwVerify(t, r.Encoded, pw+" "); v.State != ciphertools.PasswordNoMatch {
				t.Errorf("wrong password: state %s", v.State)
			}
			// A fresh salt each time: same password, different string.
			if again := pwHash(t, pwFields(algo, pw)); again.Encoded == r.Encoded {
				t.Error("two hashes of the same password are identical: the salt is not random")
			}
		})
	}
}

func TestPasswordDefaultsAreOWASP(t *testing.T) {
	r := pwHash(t, url.Values{"algo": {"argon2id"}, "password": {"x"}})
	if !strings.HasPrefix(r.Encoded, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Errorf("argon2id defaults: %s", r.Encoded)
	}
	if noted(r.Warnings, "OWASP") {
		t.Errorf("OWASP's own minimum warned about: %+v", r.Warnings)
	}
	if algo := r.Info.Algorithm; algo != "argon2id" {
		t.Errorf("algorithm %q", algo)
	}
}

func TestPasswordPasswordEncoding(t *testing.T) {
	// "abc" as hex is the same three bytes as "abc" as text.
	f := pwFields("pbkdf2-sha256", "616263")
	f.Set("password_enc", "hex")
	r := pwHash(t, f)
	if v := pwVerify(t, r.Encoded, "abc"); v.State != ciphertools.PasswordMatch {
		t.Fatalf("hex password did not verify as text: %s", v.State)
	}
}

// Published or independently computed vectors, verified through the op.
func TestPasswordKnownVectors(t *testing.T) {
	b64 := hexB64
	cases := []struct{ name, hash, password, variant string }{
		// OpenBSD / crypt_blowfish test vectors.
		{"bcrypt U*U", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW", "U*U", "$2a$"},
		{"bcrypt U*U*", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK", "U*U*", "$2a$"},
		// Apache htpasswd -B, an independent implementation, writes $2y$.
		{"bcrypt htpasswd", "$2y$04$n.BO6Chu8O0K6tZduwSHIegZ.y6hDk990CAFSuv7nB6NJbWkEvW5y", "correct horse", "$2y$"},
		// The P-H-C reference CLI's vectors: password "password", salt "somesalt", 24-byte tag.
		{"argon2id reference", "$argon2id$v=19$m=64,t=2,p=1$c29tZXNhbHQ$" + b64("068d62b26455936aa6ebe60060b0a65870dbfa3ddf8d41f7"), "password", ""},
		{"argon2i reference", "$argon2i$v=19$m=64,t=2,p=2$c29tZXNhbHQ$" + b64("2089f3e78a799720f80af806553128f29b132cafe40d059f"), "password", ""},
		// Python's hashlib (OpenSSL) for scrypt and PBKDF2.
		{"scrypt", "$scrypt$ln=10,r=8,p=1$MDEyMzQ1Njc4OWFiY2RlZg$ZEBCzLptWM7dhpNJDU2HbQ945ovKHmVEozHkePPbSqw", "password", ""},
		{"pbkdf2-sha256", "$pbkdf2-sha256$i=1000,l=32$MDEyMzQ1Njc4OWFiY2RlZg$hRRjgXWkW8ResfIvBP99J/T4vkgEmMRV/0tJTOjR59I", "password", ""},
		{"pbkdf2-sha512", "$pbkdf2-sha512$i=1000,l=64$MDEyMzQ1Njc4OWFiY2RlZg$38DzhdBT7fPaUGBlsh42VTuuKSFAIYGZJ7l6feCDLIl+K3hdPFgxxu7xuUi4gIuH6cEIoODn18xH9Ig2ryNgUw", "password", ""},
		// passlib's form: bare rounds, and '.' for '+'.
		{"pbkdf2-sha512 passlib", "$pbkdf2-sha512$1000$MDEyMzQ1Njc4OWFiY2RlZg$38DzhdBT7fPaUGBlsh42VTuuKSFAIYGZJ7l6feCDLIl.K3hdPFgxxu7xuUi4gIuH6cEIoODn18xH9Ig2ryNgUw", "password", ""},
		// RFC 7914 §11: PBKDF2-HMAC-SHA256, two output blocks.
		{"pbkdf2 RFC 7914 c=1", "$pbkdf2-sha256$i=1,l=64$c2FsdA$" + b64("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"), "passwd", ""},
		{"pbkdf2 RFC 7914 c=80000", "$pbkdf2-sha256$i=80000,l=64$TmFDbA$" + b64("4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"), "Password", ""},
		// Django's layout, same derivation as its PBKDF2PasswordHasher.
		{"django", "pbkdf2_sha256$1000$seasalt$YIWkt6M1JFXrHg5s0jZjBSc7C2Cz6QvchSJ0h8Y+i7c=", "password", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := pwVerify(t, c.hash, c.password)
			if v.State != ciphertools.PasswordMatch {
				t.Fatalf("state %s: %s", v.State, v.Detail)
			}
			if c.variant != "" && v.Info.Variant != c.variant {
				t.Errorf("variant %q, want %q", v.Info.Variant, c.variant)
			}
			if w := pwVerify(t, c.hash, c.password+"x"); w.State != ciphertools.PasswordNoMatch {
				t.Errorf("wrong password: %s", w.State)
			}
		})
	}
}

// $2a$, $2b$ and $2y$ are one algorithm: the same hash verifies under each.
func TestPasswordBcryptVariantsVerifyAlike(t *testing.T) {
	const body = "05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"
	for _, prefix := range []string{"$2a$", "$2b$", "$2y$"} {
		v := pwVerify(t, prefix+body, "U*U")
		if v.State != ciphertools.PasswordMatch || v.Info.Variant != prefix {
			t.Errorf("%s: %s, variant %q", prefix, v.State, v.Info.Variant)
		}
	}
	v := pwVerify(t, "$2x$"+body, "U*U")
	if !noted(v.Warnings, "pre-2011") {
		t.Error("$2x$ not flagged")
	}
}

func TestPasswordBcryptRefuses72PlusBytes(t *testing.T) {
	ok := pwFields("bcrypt", strings.Repeat("a", 72))
	if _, err := runOp(t, "password-hash", ok, nil); err != nil {
		t.Fatalf("72 bytes refused: %v", err)
	}
	_, err := runOp(t, "password-hash", pwFields("bcrypt", strings.Repeat("a", 73)), nil)
	if err == nil || !strings.Contains(err.Error(), "73 bytes") || !strings.Contains(err.Error(), "at most 72") ||
		!strings.Contains(err.Error(), "silently") {
		t.Fatalf("73 bytes: %v", err)
	}
	// Bytes, not characters: 25 snowmen are 75 bytes.
	_, err = runOp(t, "password-hash", pwFields("bcrypt", strings.Repeat("☃", 25)), nil)
	if err == nil || !strings.Contains(err.Error(), "75 bytes (25 characters") {
		t.Fatalf("multi-byte: %v", err)
	}
	// Other algorithms have no such limit.
	pwHash(t, pwFields("argon2id", strings.Repeat("a", 200)))
}

// crypt_blowfish's vector for exactly this: bytes past 72 play no part, so on
// verify they are ignored and the page says so.
func TestPasswordBcryptVerifyTruncatesAndWarns(t *testing.T) {
	const hash = "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui"
	const first72 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	long := pwVerify(t, hash, first72+"chars after 72 are ignored")
	if long.State != ciphertools.PasswordMatch || !noted(long.Warnings, "only the first 72") {
		t.Fatalf("long: %s %+v", long.State, long.Warnings)
	}
	if short := pwVerify(t, hash, first72); short.State != ciphertools.PasswordMatch || noted(short.Warnings, "first 72") {
		t.Fatalf("72 bytes: %s %+v", short.State, short.Warnings)
	}
}

// Caps are checked before any work: a hash op over a limit is an error, a
// pasted hash over a limit is read but refused.
func TestPasswordCapsEnforced(t *testing.T) {
	over := []struct {
		algo, field, value string
	}{
		{"bcrypt", "bcrypt_cost", "15"},
		{"bcrypt", "bcrypt_cost", "3"},
		{"argon2id", "argon2_m", "65537"},
		{"argon2id", "argon2_m", "7"},
		{"argon2id", "argon2_t", "11"},
		{"argon2id", "argon2_t", "0"},
		{"argon2id", "argon2_p", "5"},
		{"scrypt", "scrypt_n", "262144"},
		{"scrypt", "scrypt_n", "512"},
		{"scrypt", "scrypt_n", "3000"},
		{"scrypt", "scrypt_r", "17"},
		{"scrypt", "scrypt_p", "5"},
		{"pbkdf2-sha256", "pbkdf2_iterations", "2000001"},
		{"pbkdf2-sha512", "pbkdf2_iterations", "999"},
		{"bcrypt", "bcrypt_cost", "twelve"},
	}
	for _, c := range over {
		f := pwFields(c.algo, "pw")
		f.Set(c.field, c.value)
		if _, err := runOp(t, "password-hash", f, nil); err == nil || !strings.Contains(err.Error(), c.field) {
			t.Errorf("%s=%s: err %v", c.field, c.value, err)
		}
	}
	// Within each cap alone but over the memory cap together: 128 × 2^17 × 16 = 256 MiB.
	f := pwFields("scrypt", "pw")
	f.Set("scrypt_n", "131072")
	f.Set("scrypt_r", "16")
	if _, err := runOp(t, "password-hash", f, nil); err == nil || !strings.Contains(err.Error(), "256 MiB") {
		t.Errorf("scrypt memory cap: %v", err)
	}
	// Argon2 needs 8 KiB per lane.
	f = pwFields("argon2id", "pw")
	f.Set("argon2_p", "2")
	if _, err := runOp(t, "password-hash", f, nil); err == nil || !strings.Contains(err.Error(), "per lane") {
		t.Errorf("argon2 m < 8p: %v", err)
	}
	if _, err := runOp(t, "password-hash", url.Values{"algo": {"md5"}, "password": {"x"}}, nil); err == nil {
		t.Error("unknown algo accepted")
	}

	refused := map[string]string{
		"bcrypt cost 15":       "$2b$15$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
		"argon2 256 MiB":       "$argon2id$v=19$m=262144,t=2,p=1$c29tZXNhbHQ$Bo1ismRVk2qm6+YAYLCmWHDb+j3fjUH3",
		"argon2 t=11":          "$argon2id$v=19$m=64,t=11,p=1$c29tZXNhbHQ$Bo1ismRVk2qm6+YAYLCmWHDb+j3fjUH3",
		"argon2 p=8":           "$argon2id$v=19$m=64,t=1,p=8$c29tZXNhbHQ$Bo1ismRVk2qm6+YAYLCmWHDb+j3fjUH3",
		"scrypt ln=20":         "$scrypt$ln=20,r=8,p=1$c29tZXNhbHQ$ZEBCzLptWM7dhpNJDU2HbQ945ovKHmVEozHkePPbSqw",
		"scrypt RFC 7914 p=16": "$scrypt$ln=10,r=8,p=16$TmFDbA$" + hexB64("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"),
		"scrypt 256 MiB":       "$scrypt$ln=17,r=16,p=1$c29tZXNhbHQ$ZEBCzLptWM7dhpNJDU2HbQ945ovKHmVEozHkePPbSqw",
		"pbkdf2 3M":            "$pbkdf2-sha256$i=3000000,l=32$c29tZXNhbHQ$hRRjgXWkW8ResfIvBP99J/T4vkgEmMRV/0tJTOjR59I",
		"pbkdf2 2 blocks":      "$pbkdf2-sha256$i=1500000,l=64$c29tZXNhbHQ$" + strings.Repeat("A", 86),
	}
	for name, h := range refused {
		start := time.Now()
		v := pwVerify(t, h, "password")
		if v.State != ciphertools.PasswordRefused || !strings.Contains(v.Detail, "limit") {
			t.Errorf("%s: state %s, %s", name, v.State, v.Detail)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("%s: took %v; the cap must stop it before the work", name, d)
		}
	}
}

func TestPasswordVerifyWithoutPasswordOnlyParses(t *testing.T) {
	v := pwVerify(t, "  $2y$12$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW\n", "")
	if v.State != ciphertools.PasswordUnchecked {
		t.Fatalf("state %s", v.State)
	}
	i := v.Info
	if i.Algorithm != "bcrypt" || i.Variant != "$2y$" || i.SaltBytes != 16 || i.HashBytes != 23 {
		t.Fatalf("parsed %+v", i)
	}
	params := map[string]string{}
	for _, p := range i.Params {
		params[p.Name] = p.Value
	}
	if params["cost"] != "12" || params["salt"] != "CCCCCCCCCCCCCCCCCCCCC." {
		t.Errorf("params %v", params)
	}

	v = pwVerify(t, "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRzb21lc2FsdA$Bo1ismRVk2qm6+YAYLCmWHDb+j3fjUH3", "")
	params = map[string]string{}
	for _, p := range v.Info.Params {
		params[p.Name] = p.Value
	}
	if v.State != ciphertools.PasswordUnchecked || params["m"] != "65536" || params["t"] != "3" || params["p"] != "4" ||
		v.Info.SaltBytes != 16 || v.Info.HashBytes != 24 {
		t.Errorf("argon2: %s %v %+v", v.State, params, v.Info)
	}
}

func TestPasswordLegacyFormatsRecognised(t *testing.T) {
	cases := map[string]string{
		"$1$saltsalt$qjXMvbEw8oaL.CzflDtaK/":                                        "md5crypt", // openssl passwd -1
		"$apr1$saltsalt$yAAkm4libquA.ZWLHbSBq/":                                     "apr1",
		"$5$saltstring$" + strings.Repeat("a", 43):                                  "sha256crypt",
		"$6$rounds=10000$saltstringsaltst$" + strings.Repeat("a", 86):               "sha512crypt",
		"$y$j9T$F5Jx5fExrKuPp53xLKQ..1$X3DX6M94c7o.9agCG9G317fhZg9SqC.5i5rd.RhAtQ7": "yescrypt",
	}
	for h, algo := range cases {
		v := pwVerify(t, h, "password")
		if v.State != ciphertools.PasswordUnsupported || v.Info.Algorithm != algo || !strings.Contains(v.Detail, "crypt(3)") {
			t.Errorf("%s: %s %q: %s", h, v.State, v.Info.Algorithm, v.Detail)
		}
	}
	if v := pwVerify(t, "$P$BzI4LH2Ww0Xi3F2PmUMcpS7J3w9f4D1", "password"); v.State != ciphertools.PasswordUnsupported || v.Info.Algorithm != "phpass" {
		t.Errorf("phpass: %s %q", v.State, v.Info.Algorithm)
	}
	v := pwVerify(t, "$6$rounds=10000$saltstringsaltst$"+strings.Repeat("a", 86), "")
	if v.Info.Params[0].Value != "10000" || v.Info.SaltBytes != 16 || v.Info.HashBytes != 64 {
		t.Errorf("sha512crypt: %+v", v.Info)
	}
	if v := pwVerify(t, "$P$BzI4LH2Ww0Xi3F2PmUMcpS7J3w9f4D1", ""); len(v.Info.Params) == 0 || v.Info.Params[0].Value != "8,192" {
		t.Errorf("phpass rounds: %+v", v.Info.Params)
	}
	// Argon2d and version 16 are named, not verified.
	for _, h := range []string{
		"$argon2d$v=19$m=64,t=1,p=1$c29tZXNhbHQ$hydAX9B8MseNZPVH8kFQ0/LnA6ifmBoZ",
		"$argon2i$m=64,t=1,p=1$c29tZXNhbHQ$hydAX9B8MseNZPVH8kFQ0/LnA6ifmBoZ",
	} {
		if v := pwVerify(t, h, "password"); v.State != ciphertools.PasswordUnsupported {
			t.Errorf("%s: %s", h, v.State)
		}
	}
}

func TestPasswordParseErrorsNameTheOffset(t *testing.T) {
	cases := map[string]string{
		"$2b$1x$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW": "offset 4",
		"$2b$05$CCCCCCCCCCCCCCCCCCCCC!E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW": "offset 28",
		"$2b$05$CCCCC": "53 characters",
		"$argon2id$v=19$m=64,t=x,p=1$c29tZXNhbHQ$Bo1ismRVk2qm6":           "offset 22",
		"$argon2id$v=19$m=64,t=1,q=1$c29tZXNhbHQ$Bo1ismRVk2qm6":           "offset 24",
		"$argon2id$v=19$m=64,t=1,p=1$c29t!XNhbHQ$Bo1ismRVk2qm6":           "offset 32",
		" $scrypt$ln=10,r=8$c29tZXNhbHQ$ZEBC":                             "no p=",
		"$pbkdf2-sha256$i=1000,l=16$c29tZXNhbHQ$hRRjgXWkW8ResfIvBP99J/T4": "l=16",
	}
	for h, want := range cases {
		_, err := runOp(t, "password-verify", url.Values{"hash": {h}, "password": {"x"}}, nil)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", h, err, want)
		}
	}
}

func TestPasswordUnknownFormat(t *testing.T) {
	_, err := runOp(t, "password-verify", url.Values{"hash": {"5f4dcc3b5aa765d61d8327deb882cf99"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "plain digest") {
		t.Fatalf("hex digest: %v", err)
	}
	if _, err := runOp(t, "password-verify", url.Values{"hash": {"  "}}, nil); err == nil {
		t.Fatal("empty hash accepted")
	}
}

func TestPasswordWeakParametersWarn(t *testing.T) {
	for algo := range cheapParams {
		r := pwHash(t, pwFields(algo, "pw"))
		if !noted(r.Warnings, "OWASP") {
			t.Errorf("%s at minimum parameters: no OWASP warning in %+v", algo, r.Warnings)
		}
	}
	if v := pwVerify(t, "$argon2id$v=19$m=64,t=2,p=1$c29tZXNhbHQ$Bo1ismRVk2qm6+YAYLCmWHDb+j3fjUH3", ""); !noted(v.Warnings, "salt is 8 bytes") {
		t.Errorf("short salt not flagged: %+v", v.Warnings)
	}
	r := pwHash(t, pwFields("pbkdf2-sha256", ""))
	if !noted(r.Warnings, "empty") {
		t.Error("empty password not flagged")
	}
}

func TestRenderPasswordFragments(t *testing.T) {
	html := render(t, "password-verify", url.Values{"hash": {"$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"}, "password": {"U*U"}})
	for _, want := range []string{"Match", "bcrypt", "$2a$", "Salt"} {
		if !strings.Contains(html, want) {
			t.Errorf("verify fragment lacks %q", want)
		}
	}
	html = render(t, "password-hash", pwFields("argon2id", "pw"))
	for _, want := range []string{"Argon2id hash", "$argon2id$v=19$m=8,t=1,p=1$", "data-copy"} {
		if !strings.Contains(html, want) {
			t.Errorf("hash fragment lacks %q", want)
		}
	}
	if strings.Contains(html, "<!DOCTYPE") {
		t.Error("fragment rendered a whole page")
	}
}

func TestPasswordAPIAndNoJSPage(t *testing.T) {
	e := newCipherApp(t)
	// JSON body with a number, as curl --json sends it.
	rec := do(t, e, http.MethodPost, "/password/hash", `{"algo":"bcrypt","bcrypt_cost":4,"password":"pw"}`, "application/json", asAPI)
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d: %s", rec.Code, rec.Body)
	}
	var got struct {
		Encoded string `json:"encoded"`
		Parsed  struct{ Algorithm string }
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || !strings.HasPrefix(got.Encoded, "$2b$04$") || got.Parsed.Algorithm != "bcrypt" {
		t.Fatalf("got %+v (%v)", got, err)
	}

	body := url.Values{"hash": {got.Encoded}, "password": {"pw"}}.Encode()
	html := do(t, e, http.MethodPost, "/password/verify", body, form, asBrowser).Body.String()
	for _, want := range []string{"<!DOCTYPE html>", "Match", `id="password-verify-result"`} {
		if !strings.Contains(html, want) {
			t.Errorf("no-JS page lacks %q", want)
		}
	}
	// The verify result must land in the verify box, not the hash box.
	hashBox := html[strings.Index(html, `id="password-hash-result"`):]
	hashBox = hashBox[:strings.Index(hashBox, "</div>")]
	if strings.Contains(hashBox, "Match") {
		t.Error("verify result rendered in the hash box")
	}
}

// The algorithm menu's starting value is chosen from literals: a crafted algo
// must not reach the Alpine expression.
func TestPasswordPageDoesNotEchoAlgoIntoScript(t *testing.T) {
	e := newCipherApp(t)
	body := url.Values{"algo": {"x' + alert(1) + '"}, "password": {"pw"}}.Encode()
	html := do(t, e, http.MethodPost, "/password/hash", body, form, asBrowser).Body.String()
	i := strings.Index(html, "algo: '")
	if i < 0 || !strings.HasPrefix(html[i:], "algo: 'bcrypt'") {
		t.Fatalf("x-data algo is not a literal: %.40s", html[i:])
	}
}
