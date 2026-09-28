package tests

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

// RFC 7638 §3.1: the RSA key whose thumbprint the RFC works out by hand.
const (
	rfc7638Key        = `{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}`
	rfc7638Thumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	// RFC 8037 A.3: the thumbprint of the A.1 Ed25519 key (rfcEdKey).
	rfc8037Thumbprint = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
)

// One key of every kind the page handles, made once: RSA generation is slow
// under -race.
var testSigners = sync.OnceValue(func() map[string]crypto.Signer {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	out := map[string]crypto.Signer{"rsa": rsaKey}
	for name, c := range map[string]elliptic.Curve{"p256": elliptic.P256(), "p384": elliptic.P384(), "p521": elliptic.P521()} {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			panic(err)
		}
		out[name] = k
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	out["ed25519"] = ed
	return out
})

func pkcs8PEM(t *testing.T, k crypto.Signer) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func inspect(t *testing.T, key string) *ciphertools.KeyInspectResult {
	t.Helper()
	res, err := runOp(t, "keys-inspect", url.Values{"key": {key}}, nil)
	if err != nil {
		t.Fatalf("keys-inspect: %v", err)
	}
	return res.(*ciphertools.KeyInspectResult)
}

func inspectOne(t *testing.T, key string) ciphertools.KeyView {
	t.Helper()
	r := inspect(t, key)
	if len(r.Keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(r.Keys))
	}
	return r.Keys[0]
}

func TestJWKThumbprintRFC7638(t *testing.T) {
	v := inspectOne(t, rfc7638Key)
	if v.Thumbprint != rfc7638Thumbprint {
		t.Fatalf("thumbprint %s, want %s", v.Thumbprint, rfc7638Thumbprint)
	}
	// The JWK's own kid and alg are kept; they aren't part of the thumbprint.
	if v.PublicJWK.Kid != "2011-04-29" || v.Alg != "RS256" || v.Name != "RSA 2048-bit" {
		t.Fatalf("kid %q alg %q name %q", v.PublicJWK.Kid, v.Alg, v.Name)
	}
	// Direct API: over the re-encoded public members.
	keys, err := ciphertools.ParseKeys(rfc7638Key)
	if err != nil {
		t.Fatal(err)
	}
	j, err := ciphertools.PublicJWK(keys[0].Public)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := ciphertools.JWKThumbprint(j); got != rfc7638Thumbprint {
		t.Fatalf("JWKThumbprint = %s", got)
	}
	if v := inspectOne(t, rfcEdKey); v.Thumbprint != rfc8037Thumbprint {
		t.Fatalf("Ed25519 thumbprint %s, want %s", v.Thumbprint, rfc8037Thumbprint)
	}
}

// With no kid of its own, a key's kid is its thumbprint.
func TestKidDefaultsToThumbprint(t *testing.T) {
	v := inspectOne(t, rfcESKey)
	if v.PublicJWK.Kid != v.Thumbprint || v.Alg != "ES256" {
		t.Fatalf("kid %q thumbprint %q alg %q", v.PublicJWK.Kid, v.Thumbprint, v.Alg)
	}
}

var privateMembers = []string{`"d"`, `"p"`, `"q"`, `"dp"`, `"dq"`, `"qi"`}

func assertNoPrivateMembers(t *testing.T, where, s string) {
	t.Helper()
	for _, m := range privateMembers {
		if strings.Contains(s, m+":") {
			t.Errorf("%s carries private member %s: %s", where, m, s)
		}
	}
}

// A private key in; the public JWK out, in the struct, the display JSON and
// the API's JSON, has no d, p, q, dp, dq or qi.
func TestPublicJWKHasNoPrivateMembers(t *testing.T) {
	inputs := map[string]string{"RFC 8037 private OKP JWK": rfcEdKey}
	for name, k := range testSigners() {
		inputs[name+" PKCS#8"] = pkcs8PEM(t, k)
		if pj, err := ciphertools.PrivateJWK(k); err == nil {
			b, _ := json.Marshal(pj)
			inputs[name+" private JWK"] = string(b)
		} else {
			t.Fatalf("%s: PrivateJWK: %v", name, err)
		}
	}
	for name, in := range inputs {
		r := inspect(t, in)
		v := r.Keys[0]
		if !v.Private || v.PrivateJWK == nil || v.PrivateJWK.D == "" {
			t.Fatalf("%s: private forms missing", name)
		}
		j := v.PublicJWK
		if j.D != "" || j.P != "" || j.Q != "" || j.DP != "" || j.DQ != "" || j.QI != "" {
			t.Errorf("%s: public JWK struct %+v", name, j)
		}
		assertNoPrivateMembers(t, name+" public JWK text", v.PublicJWKJSON)
		pub, _ := json.Marshal(v.PublicJWK)
		assertNoPrivateMembers(t, name+" public JWK JSON", string(pub))
		if strings.Contains(v.PublicPEM, "PRIVATE") {
			t.Errorf("%s: public PEM is a private key", name)
		}
	}
}

// PEM → JWK → PEM gives back the same key, private and public, for every kind.
func TestPEMJWKRoundTrip(t *testing.T) {
	for name, k := range testSigners() {
		t.Run(name, func(t *testing.T) {
			first := inspectOne(t, pkcs8PEM(t, k))
			fromJWK := inspectOne(t, first.PrivateJWKJSON)
			if fromJWK.PrivatePEM != first.PrivatePEM {
				t.Fatalf("private JWK → PEM differs:\n%s\n%s", first.PrivatePEM, fromJWK.PrivatePEM)
			}
			fromPub := inspectOne(t, first.PublicJWKJSON)
			if fromPub.Private || fromPub.PublicPEM != first.PublicPEM || fromPub.Thumbprint != first.Thumbprint {
				t.Fatalf("public JWK → PEM differs")
			}
			back := inspectOne(t, first.PublicPEM)
			if back.PublicJWKJSON != first.PublicJWKJSON {
				t.Fatalf("SPKI → JWK differs:\n%s\n%s", first.PublicJWKJSON, back.PublicJWKJSON)
			}
			der, _ := x509.MarshalPKIXPublicKey(k.Public())
			if sum := sha256.Sum256(der); first.SPKISHA256 != strings.ToUpper(colonHex(sum[:])) {
				t.Fatalf("SPKI SHA-256 %s", first.SPKISHA256)
			}
		})
	}
}

// The legacy PEM types convert to the same PKCS#8 as the modern ones.
func TestLegacyPEMConverts(t *testing.T) {
	signers := testSigners()
	rsaKey := signers["rsa"].(*rsa.PrivateKey)
	ecKey := signers["p256"].(*ecdsa.PrivateKey)
	sec1, _ := x509.MarshalECPrivateKey(ecKey)
	for name, c := range map[string]struct {
		pem  string
		want crypto.Signer
	}{
		"PKCS#1": {string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})), rsaKey},
		"SEC 1":  {string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})), ecKey},
	} {
		v := inspectOne(t, c.pem)
		if v.PrivatePEM != pkcs8PEM(t, c.want) {
			t.Errorf("%s: PKCS#8 differs", name)
		}
		if !strings.HasPrefix(v.Source, name) || !noted(v.Warnings, "older format") {
			t.Errorf("%s: source %q warnings %v", name, v.Source, v.Warnings)
		}
	}
	pkcs1pub := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)}))
	if v := inspectOne(t, pkcs1pub); v.Private || v.PrivatePEM != "" || !strings.Contains(v.PublicPEM, "BEGIN PUBLIC KEY") {
		t.Errorf("PKCS#1 public: %+v", v)
	}
}

// An encrypted PEM gets a clear refusal naming the fix, in both of its forms:
// PKCS#8's own type and the legacy Proc-Type header.
func TestEncryptedPEMRefused(t *testing.T) {
	for name, in := range map[string]string{
		"PKCS#8":    "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n",
		"Proc-Type": "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\nAAAA\n-----END RSA PRIVATE KEY-----\n",
	} {
		_, err := runOp(t, "keys-inspect", url.Values{"key": {in}}, nil)
		if err == nil || !strings.Contains(err.Error(), "encrypted with a passphrase") || !strings.Contains(err.Error(), "openssl pkey") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// EC members are fixed-length in a JWK (RFC 7518 §6.2.1.2), unlike RSA's
// integers. A P-521 value's top byte is 0 or 1, so minimal big-endian bytes
// would come out short about half the time; eight keys make a miss 1 in 2^24.
func TestECJWKMembersAreFixedLength(t *testing.T) {
	for range 8 {
		k, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		var j struct{ X, Y, D string }
		if err := json.Unmarshal([]byte(inspectOne(t, pkcs8PEM(t, k)).PrivateJWKJSON), &j); err != nil {
			t.Fatal(err)
		}
		for name, v := range map[string]string{"x": j.X, "y": j.Y, "d": j.D} {
			if b, _ := base64.RawURLEncoding.DecodeString(v); len(b) != 66 {
				t.Fatalf("P-521 %s is %d bytes, want 66", name, len(b))
			}
		}
	}
}

// The OpenSSH line parses back to the same key, both with x/crypto/ssh and
// through the page itself, and the fingerprint is ssh-keygen's.
func TestOpenSSHLineParsesBack(t *testing.T) {
	for name, k := range testSigners() {
		v := inspectOne(t, pkcs8PEM(t, k))
		pk, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(v.OpenSSH))
		if err != nil {
			t.Fatalf("%s: %q: %v", name, v.OpenSSH, err)
		}
		if comment != "" {
			t.Errorf("%s: comment %q from a PEM key", name, comment)
		}
		if !pk.(ssh.CryptoPublicKey).CryptoPublicKey().(interface{ Equal(crypto.PublicKey) bool }).Equal(k.Public()) {
			t.Errorf("%s: OpenSSH line is a different key", name)
		}
		if v.SSHFingerprint != ssh.FingerprintSHA256(pk) || !strings.HasPrefix(v.SSHFingerprint, "SHA256:") {
			t.Errorf("%s: fingerprint %s", name, v.SSHFingerprint)
		}
		back := inspectOne(t, v.OpenSSH+" alice@laptop")
		if back.SPKISHA256 != v.SPKISHA256 || back.OpenSSH != v.OpenSSH+" alice@laptop" || back.Private {
			t.Errorf("%s: line read back as %+v", name, back)
		}
	}
}

func TestOpenSSHInput(t *testing.T) {
	ed := testSigners()["ed25519"]
	pk, _ := ssh.NewPublicKey(ed.Public())
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))

	// An authorized_keys file: comments, blank lines, options, several keys.
	ec, _ := ssh.NewPublicKey(testSigners()["p384"].Public())
	file := "# deploy keys\n\n" + line + " a@b\n" + `from="10.0.0.1" ` + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ec))) + " c@d\n"
	r := inspect(t, file)
	if len(r.Keys) != 2 || r.Keys[0].Name != "Ed25519" || r.Keys[1].Name != "ECDSA P-384" || r.PublicJWKS == nil {
		t.Fatalf("authorized_keys: %+v", r.Keys)
	}

	for in, want := range map[string]string{
		"ssh-ed25519 AAAAC3Nz!aC1lZDI1NTE5 x": "offset 20",
		"ssh-ed25519":                         "no key data",
		"# only\nssh-rsa AAAA":                "line 2",
		skLine():                              "security-key",
	} {
		_, err := runOp(t, "keys-inspect", url.Values{"key": {in}}, nil)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err %v, want %q", in, err, want)
		}
	}

	// OpenSSH's own private key format, unencrypted.
	block, err := ssh.MarshalPrivateKey(ed, "me@host")
	if err != nil {
		t.Fatal(err)
	}
	v := inspectOne(t, string(pem.EncodeToMemory(block)))
	if !v.Private || v.OpenSSH != line || v.PrivatePEM != pkcs8PEM(t, ed) {
		t.Fatalf("OPENSSH PRIVATE KEY: %+v", v)
	}
	enc, _ := ssh.MarshalPrivateKeyWithPassphrase(ed, "", []byte("pw"))
	if _, err := runOp(t, "keys-inspect", url.Values{"key": {string(pem.EncodeToMemory(enc))}}, nil); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("encrypted OpenSSH key: %v", err)
	}
}

// An OpenSSH public line is key material everywhere ParseKeys is used: it
// verifies an EdDSA JWT, and offered for an HS256 token it is refused rather
// than used as an HMAC secret.
func TestOpenSSHKeyVerifiesJWT(t *testing.T) {
	keys, _ := ciphertools.ParseKeys(rfcEdKey)
	pk, _ := ssh.NewPublicKey(keys[0].Public)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))) + " rfc8037"
	if j := decode(t, rfcEdToken, line, "", rfcNow); j.Verification.State != ciphertools.VerifyValid {
		t.Fatalf("EdDSA with OpenSSH key: %+v", j.Verification)
	}
	if j := decode(t, jwtioToken, line, "", rfcNow); j.Verification.State != ciphertools.VerifyRefused {
		t.Fatalf("HS256 with OpenSSH key: %+v", j.Verification)
	}
	// "ssh-" inside a real secret is still a secret.
	if j := decode(t, jwtioToken, "not an ssh-key secret", "", rfcNow); j.Verification.State != ciphertools.VerifyInvalid {
		t.Fatalf("secret containing ssh-: %+v", j.Verification)
	}
}

func TestKeysGenerateEveryType(t *testing.T) {
	want := map[string]struct{ name, alg string }{
		"ed25519":  {"Ed25519", "EdDSA"},
		"ec-p256":  {"ECDSA P-256", "ES256"},
		"ec-p384":  {"ECDSA P-384", "ES384"},
		"ec-p521":  {"ECDSA P-521", "ES512"},
		"rsa-2048": {"RSA 2048-bit", "RS256"},
	}
	for typ, w := range want {
		t.Run(typ, func(t *testing.T) {
			res, err := runOp(t, "keys-generate", url.Values{"type": {typ}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			g := res.(*ciphertools.KeyGenResult)
			v := g.Key
			if g.Where != "server" || v.Name != w.name || v.Alg != w.alg || !v.Private || !v.Generated {
				t.Fatalf("%+v", g)
			}
			b, _ := pem.Decode([]byte(v.PrivatePEM))
			priv, err := x509.ParsePKCS8PrivateKey(b.Bytes)
			if err != nil || b.Type != "PRIVATE KEY" {
				t.Fatalf("private PEM: %v", err)
			}
			b, _ = pem.Decode([]byte(v.PublicPEM))
			pub, err := x509.ParsePKIXPublicKey(b.Bytes)
			if err != nil || !priv.(crypto.Signer).Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(pub) {
				t.Fatalf("public PEM: %v", err)
			}
			if v.PublicJWK.Kid != v.Thumbprint || v.PublicJWK.Alg != w.alg || v.PrivateJWK.Kid != v.Thumbprint {
				t.Fatalf("kid/alg: %+v", v.PublicJWK)
			}
			assertNoPrivateMembers(t, "generated public JWK", v.PublicJWKJSON)
			if again := inspectOne(t, v.PrivateJWKJSON); again.PrivatePEM != v.PrivatePEM {
				t.Fatal("private JWK doesn't read back to the same key")
			}
			pk, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(v.OpenSSH))
			if err != nil || comment == "" || ssh.FingerprintSHA256(pk) != v.SSHFingerprint {
				t.Fatalf("OpenSSH %q: %v", v.OpenSSH, err)
			}
		})
	}
	for _, bad := range []string{"rsa-1024", "rsa-8192", "ec-p224", "x25519"} {
		if _, err := runOp(t, "keys-generate", url.Values{"type": {bad}}, nil); err == nil || !strings.Contains(err.Error(), "rsa-4096") {
			t.Errorf("type %s: %v", bad, err)
		}
	}
	op, _ := ciphertools.Lookup("keys-generate")
	if !op.Heavy {
		t.Error("keys-generate must be Heavy")
	}
	if op, _ := ciphertools.Lookup("keys-inspect"); op.Heavy {
		t.Error("keys-inspect is cheap and live")
	}
}

func TestKeysWarnings(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if v := inspectOne(t, pkcs8PEM(t, small)); !noted(v.Warnings, "below 2048") || !noted(v.Warnings, "private key") {
		t.Errorf("RSA 1024: %v", v.Warnings)
	}
	mislabelled := strings.Replace(rfcESKey, `"kty":"EC"`, `"kty":"EC","alg":"ES384"`, 1)
	if v := inspectOne(t, mislabelled); !noted(v.Warnings, "alg ES384") || v.Alg != "ES384" {
		t.Errorf("ES384 on P-256: %v", v.Warnings)
	}
	if v := inspectOne(t, rfcHSKey); v.Kind != "secret" || v.PublicPEM != "" || v.OpenSSH != "" || v.Thumbprint == "" {
		t.Errorf("oct JWK: %+v", v)
	}
	// The key count is capped, in every input form.
	pub := inspectOne(t, rfcESKey)
	for name, in := range map[string]string{
		"PEM":     strings.Repeat(pub.PublicPEM, 65),
		"JWKS":    `{"keys":[` + strings.TrimSuffix(strings.Repeat(rfcESKey+",", 65), ",") + `]}`,
		"OpenSSH": strings.Repeat(pub.OpenSSH+"\n", 65),
	} {
		if _, err := runOp(t, "keys-inspect", url.Values{"key": {in}}, nil); err == nil || !strings.Contains(err.Error(), "more than 64") {
			t.Errorf("65 keys as %s: %v", name, err)
		}
	}
	if r := inspect(t, strings.Repeat(pub.PublicPEM, 64)); len(r.Keys) != 64 {
		t.Errorf("64 keys: got %d", len(r.Keys))
	}
	for _, in := range []string{"", "hello", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"} {
		if _, err := runOp(t, "keys-inspect", url.Values{"key": {in}}, nil); err == nil {
			t.Errorf("%q: no error", in)
		}
	}
}

func TestRenderKeys(t *testing.T) {
	html := render(t, "keys-generate", url.Values{"type": {"ed25519"}})
	for _, want := range []string{"for testing", "KMS", "BEGIN PRIVATE KEY", "ssh-ed25519", "<details", " open"} {
		if !strings.Contains(html, want) {
			t.Errorf("generate fragment lacks %q", want)
		}
	}
	html = render(t, "keys-inspect", url.Values{"key": {rfcEdKey}})
	if !strings.Contains(html, "<details") || strings.Contains(html, " open>") || !strings.Contains(html, rfc8037Thumbprint) {
		t.Errorf("inspect fragment: private forms must start folded")
	}
}

func TestKeysAPI(t *testing.T) {
	e := newCipherApp(t)
	rec := do(t, e, http.MethodPost, "/keys/generate", "type=ec-p256", form, asAPI)
	if rec.Code != http.StatusOK {
		t.Fatalf("generate: %d %s", rec.Code, rec.Body)
	}
	var got struct {
		Where string
		Key   struct {
			Alg       string         `json:"alg"`
			PublicJWK map[string]any `json:"public_jwk"`
		}
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.Where != "server" || got.Key.Alg != "ES256" || got.Key.PublicJWK["d"] != nil {
		t.Fatalf("generate: %v %+v", err, got)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control %q", cc)
	}
	rec = do(t, e, http.MethodPost, "/keys/inspect", url.Values{"key": {rfcEdKey}}.Encode(), form, asBrowser)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), rfc8037Thumbprint) || !strings.Contains(rec.Body.String(), "<!DOCTYPE html>") {
		t.Fatalf("no-JS inspect: %d", rec.Code)
	}
}

// skLine is a FIDO sk-ssh-ed25519 public key line: type, key, application.
func skLine() string {
	var b []byte
	put := func(s []byte) {
		b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
		b = append(b, s...)
	}
	put([]byte("sk-ssh-ed25519@openssh.com"))
	put(make([]byte, 32))
	put([]byte("ssh:"))
	return "sk-ssh-ed25519@openssh.com " + base64.StdEncoding.EncodeToString(b) + " yubikey"
}

func colonHex(b []byte) string {
	var sb strings.Builder
	for i, c := range b {
		if i > 0 {
			sb.WriteByte(':')
		}
		const digits = "0123456789abcdef"
		sb.WriteByte(digits[c>>4])
		sb.WriteByte(digits[c&15])
	}
	return sb.String()
}

// The OpenSSH private key is what ssh-keygen writes to ~/.ssh/id_*: it must
// parse back with x/crypto/ssh, carry the comment, and belong to the public
// line shown beside it. With a passphrase it must need that passphrase, and the
// unencrypted PKCS#8/JWK forms must be gone.
func TestGenerateOpenSSHPrivateKey(t *testing.T) {
	for _, typ := range []string{"ed25519", "ec-p256", "rsa-2048"} {
		t.Run(typ, func(t *testing.T) {
			res, err := runOp(t, "keys-generate", url.Values{"type": {typ}, "comment": {"me@laptop"}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			v := res.(*ciphertools.KeyGenResult).Key
			if !strings.HasPrefix(v.OpenSSHPrivate, "-----BEGIN OPENSSH PRIVATE KEY-----") || v.OpenSSHEncrypted {
				t.Fatalf("openssh private = %.60q, encrypted %v", v.OpenSSHPrivate, v.OpenSSHEncrypted)
			}
			signer, err := ssh.ParsePrivateKey([]byte(v.OpenSSHPrivate))
			if err != nil {
				t.Fatal(err)
			}
			line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
			if !strings.HasPrefix(v.OpenSSH, line) || !strings.HasSuffix(v.OpenSSH, " me@laptop") {
				t.Fatalf("public line %q does not match the private key %q, or lost the comment", v.OpenSSH, line)
			}
		})
	}

	res, err := runOp(t, "keys-generate", url.Values{"type": {"ed25519"}, "passphrase": {"correct horse"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	v := res.(*ciphertools.KeyGenResult).Key
	if !v.OpenSSHEncrypted || v.PrivatePEM != "" || v.PrivateJWK != nil {
		t.Fatalf("encrypted %v, PKCS#8 %d bytes, JWK %v", v.OpenSSHEncrypted, len(v.PrivatePEM), v.PrivateJWK)
	}
	var missing *ssh.PassphraseMissingError
	if _, err := ssh.ParseRawPrivateKey([]byte(v.OpenSSHPrivate)); !errors.As(err, &missing) {
		t.Fatalf("parsed without the passphrase: %v", err)
	}
	if _, err := ssh.ParseRawPrivateKeyWithPassphrase([]byte(v.OpenSSHPrivate), []byte("correct horse")); err != nil {
		t.Fatal(err)
	}

	if _, err := runOp(t, "keys-generate", url.Values{"type": {"ed25519"}, "comment": {"two\nlines"}}, nil); err == nil {
		t.Fatal("a multi-line comment was accepted")
	}
}
