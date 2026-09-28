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
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

// Published vectors, so the ECDSA raw r‖s handling and the JWK readers are
// checked against someone else's bytes, not only against our own signer.
const (
	// jwt.io's default token, secret "your-256-bit-secret".
	jwtioToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	// RFC 7515 A.1 (HS256, oct JWK).
	rfcHSKey   = `{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}`
	rfcHSToken = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	// RFC 7515 A.3 (ES256, public EC JWK).
	rfcESKey = `{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}`
	// The same point with a d that belongs to a different one. Must be refused,
	// not signed with.
	mismatchedECKey = `{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cLnT8EgfH3cTzP9kGkoFtM"}`
	rfcESToken      = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"

	// RFC 8037 A.4 (EdDSA over a non-JSON payload).
	rfcEdKey   = `{"kty":"OKP","crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
	rfcEdToken = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
)

// rfcNow sits before the RFC tokens' exp (1300819380), so "expired" can't mask
// a signature result.
var rfcNow = time.Unix(1300819000, 0)

func decode(t *testing.T, token, key, enc string, now time.Time) *ciphertools.JWT {
	t.Helper()
	j, err := ciphertools.DecodeJWT(token, key, enc, now, ciphertools.DefaultLeeway)
	if err != nil {
		t.Fatalf("DecodeJWT: %v", err)
	}
	return j
}

func TestJWTVerifyPublishedVectors(t *testing.T) {
	cases := []struct {
		name, token, key, enc, want string
	}{
		{"jwt.io HS256", jwtioToken, "your-256-bit-secret", "utf8", ciphertools.VerifyValid},
		{"jwt.io wrong secret", jwtioToken, "not-the-secret", "utf8", ciphertools.VerifyInvalid},
		// The same secret read as base64 is different bytes: the classic mismatch.
		{"jwt.io secret as base64", jwtioToken, "your-256-bit-secret", "base64", ciphertools.VerifyInvalid},
		{"jwt.io no key", jwtioToken, "", "", ciphertools.VerifyUnchecked},
		{"RFC 7515 A.1 oct JWK", rfcHSToken, rfcHSKey, "", ciphertools.VerifyValid},
		{"RFC 7515 A.3 EC JWK", rfcESToken, rfcESKey, "", ciphertools.VerifyValid},
		{"RFC 8037 A.4 OKP JWK", rfcEdToken, rfcEdKey, "", ciphertools.VerifyValid},
		{"ES256 token, wrong kind of key", rfcESToken, rfcEdKey, "", ciphertools.VerifyRefused},
		{"EC JWK whose d doesn't match x/y", rfcESToken, mismatchedECKey, "", ciphertools.VerifyError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			j := decode(t, c.token, c.key, c.enc, rfcNow)
			if j.Verification.State != c.want {
				t.Fatalf("state = %q (%s), want %q", j.Verification.State, j.Verification.Detail, c.want)
			}
		})
	}
}

func TestJWTNonJSONPayload(t *testing.T) {
	j := decode(t, rfcEdToken, rfcEdKey, "", rfcNow)
	if j.PayloadText == nil || j.PayloadText.Value != "Example of Ed25519 signing" {
		t.Fatalf("payload text = %+v", j.PayloadText)
	}
	if j.Claims != nil || j.Validity != nil {
		t.Fatalf("non-JSON payload grew claims or a validity verdict")
	}
}

func TestJWTClaimsKeepOrderAndTimes(t *testing.T) {
	j := decode(t, jwtioToken, "", "", time.Unix(1516239022+120, 0))
	var names []string
	for _, c := range j.Claims {
		names = append(names, c.Name)
	}
	if got := strings.Join(names, ","); got != "sub,name,iat" {
		t.Fatalf("claim order = %s, want the token's own order", got)
	}
	if !strings.Contains(j.Claims[2].When, "2018-01-18 01:30:22 UTC") || !strings.Contains(j.Claims[2].When, "2 minutes ago") {
		t.Fatalf("iat When = %q", j.Claims[2].When)
	}
	if j.Validity.State != "no-expiry" {
		t.Fatalf("validity = %q, want no-expiry", j.Validity.State)
	}
}

func TestJWTExpiryAndLeeway(t *testing.T) {
	exp := int64(1300819380)
	cases := []struct {
		now  int64
		want string
	}{
		{exp - 10, "valid"},
		{exp + 30, "valid"}, // inside the default 60s leeway
		{exp + 61, "expired"},
	}
	for _, c := range cases {
		j := decode(t, rfcHSToken, "", "", time.Unix(c.now, 0))
		if j.Validity.State != c.want {
			t.Errorf("now=exp%+d: validity %q, want %q", c.now-exp, j.Validity.State, c.want)
		}
	}
}

// token builds header.payload.sig from raw JSON, for tokens no honest signer
// would make.
func token(header, payload, sig string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(header)) + "." + enc([]byte(payload)) + "." + sig
}

func TestJWTAlgNoneIsRefusedEvenWithAKey(t *testing.T) {
	for _, alg := range []string{"none", "None", "NONE"} {
		j := decode(t, token(`{"alg":"`+alg+`"}`, `{"sub":"x"}`, ""), "anything", "", rfcNow)
		if j.Verification.State != ciphertools.VerifyRefused {
			t.Errorf("alg %q: state %q, want refused", alg, j.Verification.State)
		}
		if !hasLevel(j.Warnings, ciphertools.LevelDanger, "none") {
			t.Errorf("alg %q: no danger warning", alg)
		}
	}
}

// The attack: an RS256 verifier handed an HS256 token whose "secret" is the
// server's public key. The key's kind must pick the algorithm, not the token.
func TestJWTAlgorithmConfusionRefused(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	spki, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))

	j := decode(t, jwtioToken, pubPEM, "", rfcNow)
	if j.Verification.State != ciphertools.VerifyRefused || !strings.Contains(j.Verification.Detail, "algorithm-confusion") {
		t.Fatalf("HS256 token + RSA public key: %q %q", j.Verification.State, j.Verification.Detail)
	}

	// And the reverse: an RS256 token with something that reads as a secret.
	rs := signed(t, "RS256", pkcs8PEM(t, priv), "")
	j = decode(t, rs, "just-a-string", "", time.Now())
	if j.Verification.State != ciphertools.VerifyRefused {
		t.Fatalf("RS256 token + secret: %q", j.Verification.State)
	}
}

// A malformed PEM must be reported as a malformed PEM, never used as an HMAC
// secret, which would be algorithm confusion by accident.
func TestJWTBrokenPEMIsNotASecret(t *testing.T) {
	j := decode(t, jwtioToken, "-----BEGIN PUBLIC KEY-----\nnot base64\n-----END PUBLIC KEY-----", "", rfcNow)
	if j.Verification.State != ciphertools.VerifyError {
		t.Fatalf("state %q, want error", j.Verification.State)
	}
}

func TestJWTCritRefused(t *testing.T) {
	j := decode(t, token(`{"alg":"HS256","crit":["exp"]}`, `{}`, "AAAA"), "k", "", rfcNow)
	if j.Verification.State != ciphertools.VerifyRefused {
		t.Fatalf("state %q, want refused", j.Verification.State)
	}
}

func TestJWTCleansPastedToken(t *testing.T) {
	j := decode(t, "  Bearer \""+jwtioToken[:40]+"\n"+jwtioToken[40:]+"\"\n", "your-256-bit-secret", "", rfcNow)
	if j.Verification.State != ciphertools.VerifyValid {
		t.Fatalf("state %q after cleaning", j.Verification.State)
	}
	if !hasLevel(j.Warnings, ciphertools.LevelInfo, "Bearer") {
		t.Fatalf("cleaning happened silently")
	}
}

func TestJWTStructureErrors(t *testing.T) {
	for _, bad := range []string{"", "abc", "a.b", "a.b.c.d", "!!.e30.x"} {
		if _, err := ciphertools.DecodeJWT(bad, "", "", rfcNow, 0); err == nil {
			t.Errorf("%q decoded without error", bad)
		}
	}
	// Five parts is a JWE: recognised, not an error.
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RSA-OAEP","enc":"A256GCM"}`))
	j, err := ciphertools.DecodeJWT(hdr+".a.b.c.d", "", "", rfcNow, 0)
	if err != nil || j.Kind != "JWE" || j.Verification.State != ciphertools.VerifyUnchecked {
		t.Fatalf("JWE: %+v err %v", j, err)
	}
}

func TestJWTShortHMACSecretWarned(t *testing.T) {
	j := decode(t, jwtioToken, "your-256-bit-secret", "", rfcNow) // 19 bytes < 32
	if !hasLevel(j.Warnings, ciphertools.LevelWarn, "RFC 7518") {
		t.Fatalf("no short-secret warning: %+v", j.Warnings)
	}
}

// Editing a claim keeps the old signature, which then no longer matches. The
// RFC 7515 A.1 vector above covers the other half: its payload has CRLFs inside
// the JSON and still verifies, because the check runs over the segments as
// pasted, never over re-serialised claims.
func TestJWTEditedPayloadNoLongerVerifies(t *testing.T) {
	parts := strings.Split(jwtioToken, ".")
	edited := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1234567890","name":"John Doe","admin":true}`)) + "." + parts[2]
	if j := decode(t, edited, "your-256-bit-secret", "utf8", rfcNow); j.Verification.State != ciphertools.VerifyInvalid {
		t.Fatalf("edited payload: %q %s", j.Verification.State, j.Verification.Detail)
	}
}

// exp/nbf/iat may be floats or, in sloppy tokens, strings; aud is a string or
// an array. All of it is shown, none of it crashes.
func TestJWTSloppyClaimsAreShown(t *testing.T) {
	j := decode(t, token(`{"alg":"HS256"}`, `{"aud":["api","web"],"exp":1300819380.5,"iat":"1300819000"}`, "AAAA"), "", "", rfcNow)
	rows := map[string]ciphertools.Row{}
	for _, r := range j.Claims {
		rows[r.Name] = r
	}
	if rows["aud"].Value != `["api","web"]` {
		t.Errorf("aud array shown as %q", rows["aud"].Value)
	}
	if !strings.HasPrefix(rows["exp"].When, "2011-03-22 18:43:00 UTC") || j.Validity.State != "valid" {
		t.Errorf("float exp: %q, validity %q", rows["exp"].When, j.Validity.State)
	}
	if rows["iat"].When != "" || !strings.Contains(rows["iat"].Note, "not a NumericDate") || rows["iat"].Value != "1300819000" {
		t.Errorf("string iat: %+v", rows["iat"])
	}
	j = decode(t, token(`{"alg":"HS256"}`, `{"aud":"api"}`, "AAAA"), "", "", rfcNow)
	if j.Claims[0].Value != "api" {
		t.Errorf("aud string shown as %q", j.Claims[0].Value)
	}
}

// PS* uses a salt as long as the hash (RFC 7518 §3.5). The signer's output
// verifies under exactly that rule, and a signature with any other salt length
// is refused, even though Go's own PSSSaltLengthAuto would take it.
func TestJWTPSSSaltLengthEqualsHash(t *testing.T) {
	k := testSigners()["rsa"].(*rsa.PrivateKey)
	parts := strings.Split(signed(t, "PS256", pkcs8PEM(t, k), ""), ".")
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if err := rsa.VerifyPSS(&k.PublicKey, crypto.SHA256, sum[:], sig, &rsa.PSSOptions{SaltLength: sha256.Size}); err != nil {
		t.Fatalf("signer's salt is not 32 bytes: %v", err)
	}
	long, err := rsa.SignPSS(rand.Reader, k, crypto.SHA256, sum[:], &rsa.PSSOptions{SaltLength: 64})
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	pub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))
	tok := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(long)
	if j := decode(t, tok, pub, "", time.Now()); j.Verification.State != ciphertools.VerifyInvalid {
		t.Fatalf("64-byte salt: %q %s", j.Verification.State, j.Verification.Detail)
	}
}

// --- signing ----------------------------------------------------------------

func sign(t *testing.T, fields map[string]string) (*ciphertools.JWTSigned, error) {
	t.Helper()
	op, ok := ciphertools.Lookup("jwt-sign")
	if !ok {
		t.Fatal("jwt-sign not registered")
	}
	v := url.Values{}
	for k, s := range fields {
		v.Set(k, s)
	}
	res, err := ciphertools.Run(op, ciphertools.Input{Fields: v})
	if err != nil {
		return nil, err
	}
	return res.(*ciphertools.JWTSigned), nil
}

func signed(t *testing.T, alg, key, enc string) string {
	t.Helper()
	s, err := sign(t, map[string]string{"alg": alg, "key": key, "key_enc": enc, "payload": `{"sub":"42"}`, "exp": "1h"})
	if err != nil {
		t.Fatalf("sign %s: %v", alg, err)
	}
	return s.Token
}

// Every algorithm the sign menu offers must round-trip: sign, then verify with
// the public key alone (not the private key the signer had).
func TestJWTSignRoundTripEveryAlg(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ec := map[string]*ecdsa.PrivateKey{}
	for alg, c := range map[string]elliptic.Curve{"ES256": elliptic.P256(), "ES384": elliptic.P384(), "ES512": elliptic.P521()} {
		ec[alg], _ = ecdsa.GenerateKey(c, rand.Reader)
	}
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	pubPEM := func(k any) string {
		der, _ := x509.MarshalPKIXPublicKey(k)
		return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}

	for _, alg := range ciphertools.SignAlgs {
		t.Run(alg, func(t *testing.T) {
			var priv, pub string
			switch alg[:2] {
			case "HS":
				priv, pub = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", ""
				pub = priv
			case "RS", "PS":
				priv, pub = pkcs8PEM(t, rsaKey), pubPEM(&rsaKey.PublicKey)
			case "ES":
				priv, pub = pkcs8PEM(t, ec[alg]), pubPEM(&ec[alg].PublicKey)
			default:
				priv, pub = pkcs8PEM(t, edKey), pubPEM(edKey.Public())
			}
			tok := signed(t, alg, priv, "utf8")
			if strings.ContainsAny(tok, "+/=") {
				t.Fatalf("%s token is not unpadded base64url: %s", alg, tok)
			}
			j := decode(t, tok, pub, "utf8", time.Now())
			if j.Verification.State != ciphertools.VerifyValid || j.Alg != alg {
				t.Fatalf("alg %s: %q %s", j.Alg, j.Verification.State, j.Verification.Detail)
			}
			if alg[:2] == "ES" {
				want := map[string]int{"ES256": 64, "ES384": 96, "ES512": 132}[alg]
				if j.SigBytes != want {
					t.Fatalf("%s signature is %d bytes, want raw r||s of %d", alg, j.SigBytes, want)
				}
			}
		})
	}
}

func TestJWTSignRefusals(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	spki, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	pub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))
	cases := map[string]map[string]string{
		"alg none":        {"alg": "none", "key": "k"},
		"public key":      {"alg": "RS256", "key": pub},
		"secret for RS":   {"alg": "RS256", "key": "secret"},
		"payload array":   {"alg": "HS256", "key": "k", "payload": "[1,2]"},
		"no key":          {"alg": "HS256"},
		"curve mismatch":  {"alg": "ES384", "key": pkcs8PEM(t, p256)},
		"unknown preset":  {"alg": "HS256", "key": "k", "exp": "3w"},
		"header not JSON": {"alg": "HS256", "key": "k", "header": "{nope"},
	}
	for name, f := range cases {
		if _, err := sign(t, f); err == nil {
			t.Errorf("%s: signed without error", name)
		}
	}
}

// Header and payload keep the order the visitor typed; alg and typ lead.
func TestJWTSignKeepsMemberOrder(t *testing.T) {
	s, err := sign(t, map[string]string{
		"alg": "HS256", "key": "k", "kid": "key-1", "now": "1700000000", "iat": "on", "exp": "15m",
		"header":  `{"zzz": 1, "aaa": {"b": 2}}`,
		"payload": `{"sub": "42", "admin": true}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(s.Token, ".")
	h, _ := base64.RawURLEncoding.DecodeString(parts[0])
	p, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if got, want := string(h), `{"alg":"HS256","typ":"JWT","kid":"key-1","zzz":1,"aaa":{"b":2}}`; got != want {
		t.Errorf("header = %s\n   want %s", got, want)
	}
	if got, want := string(p), `{"sub":"42","admin":true,"iat":1700000000,"exp":1700000900}`; got != want {
		t.Errorf("payload = %s\n    want %s", got, want)
	}
	if !json.Valid(p) {
		t.Errorf("payload is not valid JSON")
	}
}

func TestJWTJWKSPicksByKid(t *testing.T) {
	// Two oct keys; only the second signed the token.
	jwks := `{"keys":[{"kty":"oct","kid":"a","k":"` + base64.RawURLEncoding.EncodeToString([]byte("wrong-wrong-wrong-wrong-wrong-32")) +
		`"},{"kty":"oct","kid":"b","k":"` + base64.RawURLEncoding.EncodeToString([]byte("right-right-right-right-right-32")) + `"}]}`
	s, err := sign(t, map[string]string{"alg": "HS256", "key": "right-right-right-right-right-32", "kid": "b"})
	if err != nil {
		t.Fatal(err)
	}
	j := decode(t, s.Token, jwks, "", time.Now())
	if j.Verification.State != ciphertools.VerifyValid || !strings.Contains(j.Verification.Key, `kid "b"`) {
		t.Fatalf("%q via %q", j.Verification.State, j.Verification.Key)
	}
	// A kid no key carries is a clear miss, not "invalid signature".
	s, _ = sign(t, map[string]string{"alg": "HS256", "key": "right-right-right-right-right-32", "kid": "c"})
	j = decode(t, s.Token, jwks, "", time.Now())
	if j.Verification.State != ciphertools.VerifyInvalid || !strings.Contains(j.Verification.Detail, `kid "c"`) {
		t.Fatalf("unknown kid: %q %s", j.Verification.State, j.Verification.Detail)
	}
}

// An exp that is present but not a NumericDate is not "no exp claim": the
// issuer did set an expiry, just in a form nothing can check.
func TestJWTMalformedExpIsNotMissing(t *testing.T) {
	j := decode(t, token(`{"alg":"HS256"}`, `{"sub":"x","exp":"tomorrow"}`, "AAAA"), "", "", rfcNow)
	if j.Validity.State != "bad-expiry" {
		t.Fatalf("validity = %q (%s), want bad-expiry", j.Validity.State, j.Validity.Detail)
	}
	for _, w := range j.Warnings {
		if strings.Contains(w.Text, "No exp claim") {
			t.Fatalf("malformed exp reported as missing: %q", w.Text)
		}
	}
}

// A token never says how its HMAC secret was written down, and a secret like
// this one is valid both as text and as base64 (26 letters: 26 bytes of text,
// or 19 bytes of base64). Left on "detect", the verifier tries each reading and
// says which one matched; with an explicit reading that fails, it still says
// which reading would have matched rather than a bare "invalid".
func TestJWTSecretEncodingDetected(t *testing.T) {
	const pasted = "hkjlhlkjhjklhkljhlkjhlkhlk"
	meant, err := base64.RawStdEncoding.DecodeString(pasted)
	if err != nil {
		t.Fatal(err)
	}
	s, err := sign(t, map[string]string{"alg": "HS256", "key": hex.EncodeToString(meant), "key_enc": "hex", "kid": "k1"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	for _, enc := range []string{"", "auto"} {
		j := decode(t, s.Token, pasted, enc, now)
		if j.Verification.State != ciphertools.VerifyValid || !strings.Contains(j.Verification.Key, "read as base64") ||
			!strings.Contains(j.Verification.Detail, "base64") {
			t.Fatalf("enc %q: %s — %s (key %s)", enc, j.Verification.State, j.Verification.Detail, j.Verification.Key)
		}
	}

	j := decode(t, s.Token, pasted, "utf8", now)
	if j.Verification.State != ciphertools.VerifyInvalid || !strings.Contains(j.Verification.Detail, "DOES with the secret read as base64") {
		t.Fatalf("explicit utf8: %s — %s", j.Verification.State, j.Verification.Detail)
	}

	j = decode(t, s.Token, "wrong-but-also-26-letters", "", now)
	if j.Verification.State != ciphertools.VerifyInvalid || !strings.Contains(j.Verification.Detail, "Tried the secret as UTF-8 text") {
		t.Fatalf("wrong secret: %s — %s", j.Verification.State, j.Verification.Detail)
	}
}
