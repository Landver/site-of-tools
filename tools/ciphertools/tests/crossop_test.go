package tests

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

// Enum fields read trimmed and case-insensitively, and a refusal names every choice.
func TestEnumFieldsReadLoosely(t *testing.T) {
	for _, c := range []struct {
		op, field, ok, want string
		base                url.Values
	}{
		{"random", "kind", " UUID ", `kind: want token, password or uuid, got "bogus"`, nil},
		{"random", "format", "ALNUM", `format: want hex, base64url, base64 or alnum, got "bogus"`, nil},
		{"totp", "mode", "\tHOTP\n", `mode: want totp or hotp, got "bogus"`, url.Values{"secret": {"JBSWY3DPEHPK3PXP"}}},
		{"encrypt", "algo", " AES-CBC ", `algo: want aes-gcm, chacha20-poly1305 or aes-cbc, got "bogus"`, url.Values{"text": {"hi"}}},
	} {
		for _, v := range []string{c.ok, " BOGUS "} {
			f := url.Values{c.field: {v}}
			for k, vv := range c.base {
				f[k] = vv
			}
			_, err := runOp(t, c.op, f, nil)
			if v == c.ok && err != nil || v != c.ok && (err == nil || err.Error() != c.want) {
				t.Errorf("%s %s=%q: got %v", c.op, c.field, v, err)
			}
		}
	}
}

// A pbkdf2 id the Passwords page can't read still counts as a password hash; a bare $ string doesn't.
func TestIdentifyPasswordFamilies(t *testing.T) {
	for in, want := range map[string]string{
		"$pbkdf2$1000$c2FsdA$aGFzaA": "password hash that doesn't parse",
		"pbkdf2_sha256$":             "password hash that doesn't parse",
		"$2b$04$short":               "password hash that doesn't parse",
		"$foo$bar":                   "$-delimited hash string",
		"$$x":                        "",
		"$x":                         "",
	} {
		r, err := ciphertools.Identify(in)
		if err != nil {
			t.Fatal(err)
		}
		got := ""
		for _, c := range r.Candidates {
			if c.Page == "/password" {
				got = c.Name
			}
		}
		if got != want {
			t.Errorf("%q: password candidate %q, want %q", in, got, want)
		}
	}
}

// Blank and # lines are skipped but still counted in an OpenSSH paste's line numbers.
func TestOpenSSHLinesSkipCommentsButCount(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := ssh.NewPublicKey(pub)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
	in := "# deploy keys\n\n  " + line + " a\r\n" + line + " b\n"

	r, err := ciphertools.Identify(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Candidates) == 0 {
		t.Fatal("identify: no candidates")
	}
	if c := r.Candidates[0]; !strings.HasPrefix(c.Name, "OpenSSH public key") || !strings.Contains(c.Why, "; 2 lines") || c.Preview != "a" {
		t.Errorf("identify: %+v", c)
	}
	if ks := opOf[ciphertools.KeyInspectResult](t, "keys-inspect", url.Values{"key": {in}}, nil).Keys; len(ks) != 2 || !strings.HasSuffix(ks[1].OpenSSH, " b") {
		t.Errorf("keys-inspect: %+v", ks)
	}
	if _, err := runOp(t, "keys-inspect", url.Values{"key": {in + "ssh-ed25519 AAAA\n"}}, nil); err == nil || !strings.HasPrefix(err.Error(), "line 5: ") {
		t.Errorf("bad fifth line: %v", err)
	}
}

// A key block pasted with the certificate is matched unless the key field gives one.
func TestCertKeyPastedAlongside(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cert.example"},
		DNSNames: []string{"cert.example"}, NotBefore: time.Unix(1700000000, 0), NotAfter: time.Unix(1800000000, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(k)
	certPEM, keyPEM := pemBlock("CERTIFICATE", der), pemBlock("PRIVATE KEY", keyDER)

	m := opOf[ciphertools.CertResult](t, "cert", url.Values{"cert": {certPEM + keyPEM}, "now": {"1750000000"}}, nil).KeyMatch
	if m == nil || m.State != "match" || !strings.Contains(m.Detail, "certificate 1 (cert.example)") || !strings.HasSuffix(m.Detail, "(Checked with the key found among the pasted PEM blocks.)") {
		t.Errorf("key alongside: %+v", m)
	}
	if r := opOf[ciphertools.CertResult](t, "cert", url.Values{"cert": {certPEM + keyPEM}, "key": {"not a key"}, "now": {"1750000000"}}, nil); r.KeyMatch == nil || r.KeyMatch.State != "error" || !noted(r.Warnings, "the key field was used for the match instead") {
		t.Errorf("key field wins: %+v %+v", r.KeyMatch, r.Warnings)
	}
}

// An HS256 secret that reads three ways is tried all three ways, and named back as read.
func TestJWTSecretReadings(t *testing.T) {
	tok := opOf[ciphertools.JWTSigned](t, "jwt-sign", url.Values{"key": {"deadbeef"}, "now": {"1700000000"}}, nil).Token
	detail := func(tok, enc string) string {
		j, err := ciphertools.DecodeJWT(tok, "deadbeef", enc, time.Unix(1700000000, 0), time.Minute)
		if err != nil {
			t.Fatalf("enc %q: %v", enc, err)
		}
		return j.Verification.Detail
	}
	if d := detail(tok[:len(tok)-2]+"AA", ""); !strings.HasSuffix(d, " Tried the secret as UTF-8 text, base64 and hex.") {
		t.Errorf("auto: %s", d)
	}
	if d := detail(tok, "hex"); !strings.Contains(d, "with the secret read as hex, but it DOES with the secret read as UTF-8 text") {
		t.Errorf("hex: %s", d)
	}
}
