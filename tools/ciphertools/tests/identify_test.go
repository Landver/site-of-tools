package tests

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

func identify(t *testing.T, s string) []ciphertools.Candidate {
	t.Helper()
	r, err := ciphertools.Identify(s)
	if err != nil {
		t.Fatalf("Identify(%.40q): %v", s, err)
	}
	return r.Candidates
}

// top is the first candidate; find is the first whose name contains sub.
func top(t *testing.T, s string) ciphertools.Candidate {
	t.Helper()
	c := identify(t, s)
	if len(c) == 0 {
		t.Fatalf("Identify(%.40q): no candidates", s)
	}
	return c[0]
}

// named is the candidate with exactly this name ("LM digest" is inside
// "NTLM digest").
func named(cs []ciphertools.Candidate, name string) (ciphertools.Candidate, int) {
	for i, c := range cs {
		if c.Name == name {
			return c, i
		}
	}
	return ciphertools.Candidate{}, -1
}

func find(cs []ciphertools.Candidate, sub string) (ciphertools.Candidate, int) {
	for i, c := range cs {
		if strings.Contains(c.Name, sub) {
			return c, i
		}
	}
	return ciphertools.Candidate{}, -1
}

// One input per recogniser: the best reading, its confidence and its page.
func TestIdentifyRecognisers(t *testing.T) {
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(edPriv.Public())
	sshLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " alice@laptop"
	spki, _ := x509.MarshalPKIXPublicKey(edPriv.Public())
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))
	p := newPKI(t)
	bc, _ := bcrypt.GenerateFromPassword([]byte("pw"), 4)
	jwe := b64u(`{"alg":"RSA-OAEP","enc":"A256GCM"}`) + ".OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ"

	for _, c := range []struct {
		in, name, conf, page string
	}{
		{jwtioToken, "JWT (signed, JWS)", "high", "/"},
		{"Bearer " + jwtioToken, "JWT (signed, JWS)", "high", "/"},
		{jwe, "JWE", "high", "/"},
		{pemOf(p.leaf), "X.509 certificate", "high", "/cert"},
		{pemOf(p.leaf, p.inter, p.root), "X.509 certificate chain (3 certificates)", "high", "/cert"},
		{pkcs8PEM(t, edPriv), "private key (PKCS#8)", "high", "/keys"},
		{pubPEM, "public key (SPKI)", "high", "/keys"},
		{sshLine, "OpenSSH public key (Ed25519", "high", "/keys"},
		{ssh.FingerprintSHA256(sshPub), "OpenSSH key fingerprint (SHA-256)", "high", "/keys"},
		{string(bc), "bcrypt password hash", "high", "/password"},
		{"$2y$04$n.BO6Chu8O0K6tZduwSHIegZ.y6hDk990CAFSuv7nB6NJbWkEvW5y", "bcrypt password hash", "high", "/password"},
		{"$argon2id$v=19$m=64,t=2,p=1$c29tZXNhbHQ$" + hexB64("068d62b26455936aa6ebe60060b0a65870dbfa3ddf8d41f7"), "Argon2id password hash", "high", "/password"},
		{"$argon2d$v=19$m=64,t=2,p=1$c29tZXNhbHQ$" + hexB64("068d62b26455936aa6ebe60060b0a65870dbfa3ddf8d41f7"), "Argon2d", "high", "/password"},
		{"$scrypt$ln=10,r=8,p=1$MDEyMzQ1Njc4OWFiY2RlZg$ZEBCzLptWM7dhpNJDU2HbQ945ovKHmVEozHkePPbSqw", "scrypt password hash", "high", "/password"},
		{"$pbkdf2-sha256$i=1000,l=32$MDEyMzQ1Njc4OWFiY2RlZg$hRRjgXWkW8ResfIvBP99J/T4vkgEmMRV/0tJTOjR59I", "PBKDF2", "high", "/password"},
		{"$1$saltsalt$qjXMvbEw8oaL.CzflDugX/", "md5crypt password hash", "high", "/password"},
		{"$apr1$saltsalt$Csdd1PwuyYkwi.sDy/jGP.", "Apache MD5 (apr1)", "high", "/password"},
		{"$5$saltsalt$Gcm6FsVtF/Qa77ZKD.iwsJlCVPY0XSMgLJL0Hnww/c1", "SHA-256 crypt", "high", "/password"},
		{"$6$rounds=5000$saltsalt$" + strings.Repeat("a", 86), "SHA-512 crypt", "high", "/password"},
		{"otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example", "otpauth:// URI", "high", "/totp"},
		{"f47ac10b-58cc-4372-a567-0e02b2c3d479", "UUID version 4 (random)", "high", "/random"},
		{"{F47AC10B-58CC-4372-A567-0E02B2C3D479}", "UUID version 4", "high", "/random"},
		{"018f3a2b-7c4d-7e8f-9a0b-1c2d3e4f5a6b", "UUID version 7", "high", "/random"},
		{"00000000-0000-0000-0000-000000000000", "the nil UUID", "high", "/random"},
		{"Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==", "HTTP Basic auth credentials", "high", "/encode"},
		{"Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==", "HTTP Basic auth credentials", "high", "/encode"},
		{"5f4dcc3b5aa765d61d8327deb882cf99", "MD5 digest", "medium", "/hash"},
		{"5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", "SHA-1 digest", "medium", "/hash"},
		{strings.Repeat("ab", 32), "SHA-256 digest", "medium", "/hash"},
		{strings.Repeat("AB:", 31) + "AB", "SHA-256 fingerprint", "medium", "/cert"},
		{strings.Repeat("ab:", 19) + "ab", "SHA-1 fingerprint", "medium", "/cert"},
		{"sha256=" + strings.Repeat("0f", 32), "GitHub webhook signature", "high", "/hmac"},
		{`{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}`, "JWK (EC public key)", "high", "/keys"},
		{`{"keys":[]}`, "JWKS (0 keys)", "high", "/keys"},
		{base64.StdEncoding.EncodeToString([]byte("hello, this is some ordinary text!")), "base64 (standard, padded)", "medium", "/encode"},
		{base64.RawURLEncoding.EncodeToString([]byte("hello, this is some ordinary text!")), "base64", "medium", "/encode"},
		{"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "base32", "medium", "/totp"},
		{"just a sentence someone pasted", "plain text", "low", "/encode"},
	} {
		got := top(t, c.in)
		if !strings.Contains(got.Name, c.name) || got.Confidence != c.conf || got.Page != c.page {
			t.Errorf("%.50q: top %q %s %s, want %q %s %s\n%+v", c.in, got.Name, got.Confidence, got.Page, c.name, c.conf, c.page, identify(t, c.in))
		}
		if got.Why == "" {
			t.Errorf("%.50q: no why", c.in)
		}
		if got.Page != "" && got.PageName == "" {
			t.Errorf("%.50q: page %s has no name", c.in, got.Page)
		}
	}
}

func b64u(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// 32 hex digits is MD5, NTLM, MD4 or LM: all listed, MD5 first, each with the
// hashcat mode it certainly has, and never one verdict.
func TestIdentifyHexDigestsAreAmbiguous(t *testing.T) {
	for _, c := range []struct {
		len   int
		modes map[string]string // name -> hashcat mode ("" = listed, no mode)
	}{
		{32, map[string]string{"MD5": "0", "NTLM": "1000", "MD4": "900", "LM": ""}},
		{40, map[string]string{"SHA-1": "100", "RIPEMD-160": "6000"}},
		{56, map[string]string{"SHA-224": "1300", "SHA3-224": "17300"}},
		{64, map[string]string{"SHA-256": "1400", "SHA3-256": "17400", "Keccak-256": "17800", "BLAKE2s-256": ""}},
		{96, map[string]string{"SHA-384": "10800", "SHA3-384": "17500"}},
		{128, map[string]string{"SHA-512": "1700", "SHA3-512": "17600", "BLAKE2b-512": "600"}},
	} {
		cs := identify(t, strings.Repeat("7", c.len))
		for name, mode := range c.modes {
			got, i := named(cs, name+" digest")
			if i < 0 || got.Hashcat != mode {
				t.Errorf("%d hex: %s mode %q (at %d), want %q", c.len, name, got.Hashcat, i, mode)
			}
		}
		if cs[0].Confidence == "high" {
			t.Errorf("%d hex: a digest guess rated high: %+v", c.len, cs[0])
		}
	}
	cs := identify(t, "5f4dcc3b5aa765d61d8327deb882cf99")
	_, md5 := find(cs, "MD5 digest")
	_, ntlm := find(cs, "NTLM")
	_, md4 := find(cs, "MD4")
	if !(md5 == 0 && md5 < ntlm && ntlm < md4) {
		t.Errorf("order: MD5 %d, NTLM %d, MD4 %d", md5, ntlm, md4)
	}
	if c, _ := find(cs, "MD5 digest"); c.Page != "/hash" {
		t.Errorf("MD5 page %q", c.Page)
	}
	if c, _ := find(cs, "NTLM"); c.Page != "" {
		t.Errorf("NTLM links to %q, which doesn't compute it", c.Page)
	}
}

// Candidates come out most likely first, and confidence never rises down the list.
func TestIdentifyRankingOrder(t *testing.T) {
	rank := map[string]int{"high": 3, "medium": 2, "low": 1}
	for _, in := range []string{
		jwtioToken, "5f4dcc3b5aa765d61d8327deb882cf99", "JBSWY3DPEHPK3PXP", strings.Repeat("ab", 32),
		"hello world", "QWxhZGRpbjpvcGVuIHNlc2FtZQ==", "123456", "f47ac10b58cc4372a5670e02b2c3d479",
	} {
		cs := identify(t, in)
		for i := 1; i < len(cs); i++ {
			if rank[cs[i].Confidence] > rank[cs[i-1].Confidence] {
				t.Errorf("%q: %s (%s) ranked below %s (%s)", in, cs[i].Name, cs[i].Confidence, cs[i-1].Name, cs[i-1].Confidence)
			}
		}
	}
	// A base32 TOTP secret is also valid base64; base32 wins.
	cs := identify(t, "JBSWY3DPEHPK3PXP")
	if !strings.HasPrefix(cs[0].Name, "base32") {
		t.Errorf("JBSWY3DPEHPK3PXP: %+v", cs)
	}
	if _, i := find(cs, "base64"); i <= 0 {
		t.Errorf("the base64 reading is missing: %+v", cs)
	}
	// A JWT is read as a JWT, not as plain text: the fallback only comes when
	// nothing is certain.
	if _, i := find(identify(t, jwtioToken), "plain text"); i >= 0 {
		t.Error("plain text listed beside a certain JWT")
	}
	// 6 digits could be an authenticator code.
	if c, _ := find(identify(t, "123456"), "one-time code"); c.Page != "/totp" {
		t.Errorf("6 digits: %+v", identify(t, "123456"))
	}
	// 32 hex digits with UUID version bits: the UUID reading is listed too.
	if _, i := find(identify(t, "f47ac10b58cc4372a5670e02b2c3d479"), "UUID version 4 (random), without dashes"); i < 0 {
		t.Error("dashless UUID not listed")
	}
}

// Decoded bytes are looked at again: base64 of a JWT, of JSON, of a DER
// certificate, and hex of a DER certificate.
func TestIdentifyLooksInsideEncodings(t *testing.T) {
	p := newPKI(t)
	for _, c := range []struct {
		in, why, page string
	}{
		{base64.StdEncoding.EncodeToString([]byte(jwtioToken)), "a JWT", "/"},
		{base64.StdEncoding.EncodeToString([]byte(`{"user":"alice","admin":false}`)), "JSON", "/encode"},
		{base64.StdEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)), "JWT header", "/"},
		{base64.StdEncoding.EncodeToString(p.leaf), "a DER X.509 certificate", "/cert"},
		{hex.EncodeToString(p.leaf), "a DER X.509 certificate", "/cert"},
		{base64.StdEncoding.EncodeToString([]byte("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP")), "otpauth:// URI", "/totp"},
	} {
		got := top(t, c.in)
		if !strings.Contains(got.Why, c.why) || got.Page != c.page {
			t.Errorf("%.40q: %+v, want why %q page %s", c.in, got, c.why, c.page)
		}
	}
	// The preview shows the start of the decoded text.
	got := top(t, base64.StdEncoding.EncodeToString([]byte(`{"user":"alice"}`)))
	if got.Preview != `{"user":"alice"}` || got.PreviewHex {
		t.Errorf("preview %q", got.Preview)
	}
	long := top(t, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("words and more words ", 20))))
	if !strings.HasSuffix(long.Preview, "…") || len([]rune(long.Preview)) != 81 {
		t.Errorf("long preview %q", long.Preview)
	}
	bin := top(t, base64.StdEncoding.EncodeToString(make([]byte, 64)))
	if !bin.PreviewHex || !strings.HasSuffix(bin.Preview, "…") {
		t.Errorf("binary preview %+v", bin)
	}
}

// Broken versions of each shape are named as broken, not mistaken for
// something else or dropped.
func TestIdentifyDamagedShapes(t *testing.T) {
	for in, want := range map[string]string{
		"-----BEGIN CERTIFICATE-----\nMIIB\n":           "PEM block that doesn't decode (CERTIFICATE)",
		"otpauth://totp/x?issuer=nobody":                "otpauth:// URI that doesn't parse",
		"$2b$12$tooshort":                               "password hash that doesn't parse",
		"$zz$abc$def":                                   "$-delimited hash string",
		"Basic !!!notbase64":                            "HTTP Basic auth header that doesn't decode",
		`{"a": 1,}`:                                     "JSON-like, but not valid JSON",
		"ssh-ed25519 AAAAnotakey":                       "OpenSSH public key line that doesn't parse",
		"otpauth-migration://offline?data=CjEKCkhlbGxv": "Google Authenticator export",
		"Bearer abc.def":                                "Bearer token (opaque)",
	} {
		if got := top(t, in); !strings.Contains(got.Name, want) {
			t.Errorf("%q: top %q, want %q\n%+v", in, got.Name, want, identify(t, in))
		}
	}
}

// Nothing panics: empty, garbage, binary, huge. Identify is called directly,
// so a panic fails the test instead of being turned into an error by Run.
func TestIdentifyNeverPanics(t *testing.T) {
	for _, in := range []string{"", "   \n\t "} {
		if _, err := ciphertools.Identify(in); err == nil || !strings.Contains(err.Error(), "nothing to identify") {
			t.Errorf("%q: err = %v", in, err)
		}
	}
	if _, err := ciphertools.Identify(strings.Repeat("a", 1<<20+1)); err == nil || !strings.Contains(err.Error(), "up to 1 MiB") {
		t.Errorf("huge: err = %v", err)
	}
	garbage := []string{
		"-----BEGIN ", "-----BEGIN -----", "-----BEGIN X-----\n-----END X-----", "$", "$$", "$$$$$$", "$2b$", "$argon2id$",
		"$pbkdf2-sha256$", "pbkdf2_sha256$", "otpauth://", "otpauth://totp", "otpauth:%zz", "eyJ.eyJ.", "..", "....",
		"eyJhbGciOiJub25lIn0..", "{", "[", "{}", "[]", "null", "Basic", "Basic ", "Bearer ", "Authorization:", "SHA256:",
		"MD5:", "MD5:zz:zz", "ssh-rsa", "ssh-ed25519", "# comment\nssh-rsa", "t=,v1=", "sha256=", "v0=", "urn:uuid:",
		"{--------------------------------}", strings.Repeat("-", 36), "0x", "0X0", "=", "==", "====", "\x00", "\xff\xfe\xfd",
		"é", strings.Repeat("☃", 50), "A B C D E F G H", "ABCD EFGH IJKL MNOP", "1", strings.Repeat("9", 40),
		":", "::", "ab:", ":ab", "ab::cd", strings.Repeat("ab:", 1000) + "ab",
	}
	buf := make([]byte, 4096)
	for i := 0; i < 50; i++ {
		_, _ = rand.Read(buf[:1+i*80])
		garbage = append(garbage, string(buf[:1+i*80]), base64.StdEncoding.EncodeToString(buf[:1+i*80]), hex.EncodeToString(buf[:1+i*40]))
	}
	big := make([]byte, 1<<20)
	_, _ = rand.Read(big)
	garbage = append(garbage, string(big), base64.StdEncoding.EncodeToString(big[:700_000]), strings.Repeat("A", 1<<20),
		strings.Repeat("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", 20000)[:1<<20])
	for _, in := range garbage {
		r, err := ciphertools.Identify(in)
		if err != nil {
			if strings.TrimSpace(in) != "" {
				t.Errorf("%.40q: %v", in, err)
			}
			continue
		}
		if len(r.Candidates) == 0 {
			t.Errorf("%.40q: no candidates at all", in)
		}
		for _, c := range r.Candidates {
			if c.Confidence == "" || c.Name == "" {
				t.Errorf("%.40q: incomplete candidate %+v", in, c)
			}
		}
	}
}

func TestRenderIdentify(t *testing.T) {
	html := render(t, "identify", url.Values{"text": {"5f4dcc3b5aa765d61d8327deb882cf99"}})
	for _, want := range []string{"MD5 digest", "NTLM digest", "-m 1000", `href="/hash"`, "medium confidence"} {
		if !strings.Contains(html, want) {
			t.Errorf("fragment lacks %q", want)
		}
	}
	html = render(t, "identify", url.Values{"text": {base64.StdEncoding.EncodeToString([]byte("<script>alert(1)</script> text"))}})
	if strings.Contains(html, "<script>alert") {
		t.Error("decoded preview reached the fragment unescaped")
	}
	if html := render(t, "identify", url.Values{"text": {""}}); !strings.Contains(html, "alert-error") {
		t.Error("empty input isn't an error fragment")
	}
}

func TestIdentifyPageAndAPI(t *testing.T) {
	e := newCipherApp(t)
	rec := do(t, e, http.MethodPost, "/identify", "text=5f4dcc3b5aa765d61d8327deb882cf99", form, asAPI)
	var got struct {
		Candidates []struct {
			Name, Confidence, Why, Page, Hashcat string
		} `json:"candidates"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got.Candidates) < 3 || got.Candidates[0].Hashcat != "0" {
		t.Fatalf("code %d: %s", rec.Code, rec.Body)
	}
	rec = do(t, e, http.MethodPost, "/identify", url.Values{"text": {jwtioToken}}.Encode(), form, asBrowser)
	if html := rec.Body.String(); rec.Code != http.StatusOK || !strings.Contains(html, "JWT (signed, JWS)") || !strings.Contains(html, "<!DOCTYPE html>") {
		t.Fatalf("no-JS page: code %d", rec.Code)
	}
	page := do(t, e, http.MethodGet, "/identify", "", "", asBrowser).Body.String()
	if !strings.Contains(page, `data-cipher="identify" data-live`) {
		t.Error("identify form isn't live")
	}
}

// Each "Open it on the … page" button carries the value to the field that reads
// it, so the visitor never pastes twice. A candidate with a page but no field
// (a fingerprint, a UUID) keeps a plain link.
func TestIdentifyCarryTargets(t *testing.T) {
	for in, want := range map[string]struct{ page, field, set string }{
		jwtioToken: {"/", "token", ""},
		"$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW": {"/password", "hash", ""},
		"Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==":                           {"/encode", "header", ""},
		"otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP": {"/totp", "secret", ""},
	} {
		r, err := ciphertools.Identify(in)
		if err != nil {
			t.Fatal(err)
		}
		c := r.Candidates[0]
		if c.Page != want.page || c.Field != want.field || c.Set != want.set {
			t.Errorf("%.30q: top candidate %q -> page %q field %q set %q, want %+v", in, c.Name, c.Page, c.Field, c.Set, want)
		}
	}
}
