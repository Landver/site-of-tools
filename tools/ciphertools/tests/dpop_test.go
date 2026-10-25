package tests

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

func TestDPoPGenerate_SuccessAndDefaults(t *testing.T) {
	// 1. Default ephemeral ES256 generation
	res := opOf[ciphertools.DPoPGenerateResult](t, "dpop-generate", url.Values{
		"htm": {"GET"},
		"htu": {"https://api.example.com/user/profile?query=1#frag"},
	}, nil)

	if res.Alg != "ES256" {
		t.Errorf("default alg: want ES256, got %s", res.Alg)
	}
	if res.HTM != "GET" {
		t.Errorf("htm: want GET, got %s", res.HTM)
	}
	// Normalization must strip query and fragment
	if res.HTU != "https://api.example.com/user/profile" {
		t.Errorf("htu normalization: want https://api.example.com/user/profile, got %s", res.HTU)
	}
	if len(res.Token) == 0 {
		t.Fatalf("token structure empty: %q", res.Token)
	}
	if res.JWKThumbprint == "" {
		t.Errorf("missing jwk thumbprint")
	}

	// 2. RS256 generation with provided RSA private key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	rsaJWK, err := json.Marshal(map[string]any{
		"kty": "RSA",
		"n":   b64urlTest(rsaKey.N.Bytes()),
		"e":   "AQAB",
		"d":   b64urlTest(rsaKey.D.Bytes()),
		"p":   b64urlTest(rsaKey.Primes[0].Bytes()),
		"q":   b64urlTest(rsaKey.Primes[1].Bytes()),
	})
	if err != nil {
		t.Fatalf("marshaling RSA JWK: %v", err)
	}

	resRSA := opOf[ciphertools.DPoPGenerateResult](t, "dpop-generate", url.Values{
		"htm":          {"POST"},
		"htu":          {"https://auth.example.com/token"},
		"alg":          {"RS256"},
		"key":          {string(rsaJWK)},
		"access_token": {"my-access-token-xyz"},
	}, nil)

	if resRSA.Alg != "RS256" {
		t.Errorf("alg: want RS256, got %s", resRSA.Alg)
	}
	if got := claimsOf(t, resRSA.Payload)["ath"]; got != s256Test("my-access-token-xyz") {
		t.Errorf("ath = %v, want the access token's SHA-256", got)
	}
	if resRSA.Key != "" {
		t.Errorf("a pasted key came back as key: %q", resRSA.Key)
	}
	if es := opOf[ciphertools.DPoPGenerateResult](t, "dpop-generate", url.Values{
		"htm": {"GET"}, "htu": {"https://api.example.com"}, "alg": {"es256"},
	}, nil); es.Alg != "ES256" {
		t.Errorf("alg es256 reads as %q, want ES256", es.Alg)
	}
}

func TestDPoPGenerate_ErrorsAndValidation(t *testing.T) {
	wantErr(t, "dpop-generate", url.Values{"htu": {"https://api.example.com"}}, "HTTP method (htm) is required")
	wantErr(t, "dpop-generate", url.Values{"htm": {"GET"}}, "HTTP URI (htu) is required")
	wantErr(t, "dpop-generate", url.Values{"htm": {"GET"}, "htu": {"invalid-uri"}}, "invalid htu URI")
	wantErr(t, "dpop-generate", url.Values{
		"htm": {"GET"},
		"htu": {"https://api.example.com"},
		"alg": {"HS256"},
	}, "want ES256, RS256 or EdDSA")
	wantErr(t, "dpop-generate", url.Values{
		"htm": {"GET"},
		"htu": {"https://api.example.com"},
		"alg": {"none"},
	}, "want ES256, RS256 or EdDSA")
	wantErr(t, "dpop-generate", url.Values{
		"htm": {"GET"},
		"htu": {"https://api.example.com"},
		"alg": {"EdDSA"},
		"key": {pemBlock("PRIVATE KEY", pkcs8(t, mustEC(t)))},
	}, "EdDSA needs an Ed25519 key")
}

// Without a key, each alg gets a key of its own kind, returned as PKCS#8 PEM that signs the next proof.
func TestDPoPGenerate_KeyForEachAlg(t *testing.T) {
	now := fmt.Sprint(time.Now().Unix())
	for alg, kty := range map[string]string{"ES256": "EC", "RS256": "RSA", "EdDSA": "OKP"} {
		gen := opOf[ciphertools.DPoPGenerateResult](t, "dpop-generate", url.Values{
			"htm": {"GET"}, "htu": {"https://api.example.com/r"}, "alg": {alg}, "now": {now},
		}, nil)
		var hdr struct {
			Typ, Alg string
			JWK      ciphertools.JWK
		}
		if err := json.Unmarshal(gen.Header, &hdr); err != nil || hdr.Typ != "dpop+jwt" || hdr.Alg != alg || hdr.JWK.Kty != kty || gen.PublicJWK.Kty != kty {
			t.Errorf("%s: header %s (%v), public_jwk kty %q; want alg %s with a %s jwk", alg, gen.Header, err, gen.PublicJWK.Kty, alg, kty)
		}
		blk, _ := pem.Decode([]byte(gen.Key))
		if blk == nil || blk.Type != "PRIVATE KEY" {
			t.Fatalf("%s: key is not PKCS#8 PEM: %q", alg, gen.Key)
		}
		if _, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err != nil {
			t.Errorf("%s: key: %v", alg, err)
		}
		if v := verifyProof(t, gen.Token, "GET", "https://api.example.com/r", "", now); !v.Valid {
			t.Errorf("%s: own proof does not verify: %+v", alg, v.Checks)
		}
		again := opOf[ciphertools.DPoPGenerateResult](t, "dpop-generate", url.Values{
			"htm": {"GET"}, "htu": {"https://api.example.com/r"}, "alg": {alg}, "key": {gen.Key},
		}, nil)
		if again.JWKThumbprint != gen.JWKThumbprint || again.Key != "" {
			t.Errorf("%s: the returned key passed back signs as %s, want %s", alg, again.JWKThumbprint, gen.JWKThumbprint)
		}
	}
}

// A 32-byte random token is 43 base64url characters, the shape of an ath; it is still hashed.
func TestDPoPGenerate_HashesEveryAccessToken(t *testing.T) {
	tok := b64urlTest([]byte(strings.Repeat("\x07", 32)))
	now := fmt.Sprint(time.Now().Unix())
	gen := opOf[ciphertools.DPoPGenerateResult](t, "dpop-generate", url.Values{
		"htm": {"GET"}, "htu": {"https://api.example.com/r"}, "access_token": {tok}, "now": {now},
	}, nil)
	if got := claimsOf(t, gen.Payload)["ath"]; got != s256Test(tok) {
		t.Errorf("ath = %v, want SHA-256 of the token %s", got, s256Test(tok))
	}
	if !strings.Contains(gen.Curl, "'Authorization: DPoP "+tok+"'") {
		t.Errorf("curl does not send the token itself:\n%s", gen.Curl)
	}
	if v := verifyProof(t, gen.Token, "GET", "https://api.example.com/r", tok, now); !v.Valid {
		t.Errorf("proof with ath fails its own verify: %+v", v.Checks)
	}
}

func TestDPoPVerify_FullLifecycleAndTampering(t *testing.T) {
	nowUnix := time.Now().Unix()
	gen := opOf[ciphertools.DPoPGenerateResult](t, "dpop-generate", url.Values{
		"htm":          {"POST"},
		"htu":          {"https://api.example.com/transfer"},
		"access_token": {"secret-access-token-42"},
		"nonce":        {"server-challenge-123"},
		"now":          {fmt.Sprintf("%d", nowUnix)},
	}, nil)

	// 1. Valid Verification
	vOK := opOf[ciphertools.DPoPVerifyResult](t, "dpop-verify", url.Values{
		"token":        {gen.Token},
		"htm":          {"POST"},
		"htu":          {"https://api.example.com/transfer"},
		"access_token": {"secret-access-token-42"},
		"now":          {fmt.Sprintf("%d", nowUnix)},
	}, nil)

	if !vOK.Valid || vOK.Status != "valid" {
		t.Fatalf("expected valid verification, got: %+v", vOK)
	}
	if string(vOK.Payload) != string(gen.Payload) || string(vOK.Header) != string(gen.Header) {
		t.Errorf("verify shows header %s payload %s, want them as signed: %s %s", vOK.Header, vOK.Payload, gen.Header, gen.Payload)
	}

	// 2. Method Mismatch (HTM)
	vBadHTM := opOf[ciphertools.DPoPVerifyResult](t, "dpop-verify", url.Values{
		"token":        {gen.Token},
		"htm":          {"GET"}, // Expected POST
		"htu":          {"https://api.example.com/transfer"},
		"access_token": {"secret-access-token-42"},
		"now":          {fmt.Sprintf("%d", nowUnix)},
	}, nil)
	if vBadHTM.Valid {
		t.Errorf("expected HTM mismatch failure")
	}

	// 3. URI Mismatch (HTU)
	vBadHTU := opOf[ciphertools.DPoPVerifyResult](t, "dpop-verify", url.Values{
		"token":        {gen.Token},
		"htm":          {"POST"},
		"htu":          {"https://api.example.com/other-resource"},
		"access_token": {"secret-access-token-42"},
		"now":          {fmt.Sprintf("%d", nowUnix)},
	}, nil)
	if vBadHTU.Valid {
		t.Errorf("expected HTU mismatch failure")
	}

	// 4. Access Token Mismatch (ATH)
	vBadATH := opOf[ciphertools.DPoPVerifyResult](t, "dpop-verify", url.Values{
		"token":        {gen.Token},
		"htm":          {"POST"},
		"htu":          {"https://api.example.com/transfer"},
		"access_token": {"wrong-access-token"},
		"now":          {fmt.Sprintf("%d", nowUnix)},
	}, nil)
	if vBadATH.Valid {
		t.Errorf("expected ATH mismatch failure")
	}

	// 5. Signature Tampering (tamper with payload)
	parts := strings.Split(gen.Token, ".")
	tamperedToken := parts[0] + "." + parts[1] + "tamper" + "." + parts[2]
	wantErr(t, "dpop-verify", url.Values{
		"token": {tamperedToken},
		"htm":   {"POST"},
		"htu":   {"https://api.example.com/transfer"},
	}, "")

	// 6. A payload that still decodes, under the old signature.
	forged := parts[0] + "." + b64urlTest([]byte(strings.Replace(string(gen.Payload), `"POST"`, `"GET"`, 1))) + "." + parts[2]
	if v := verifyProof(t, forged, "GET", "https://api.example.com/transfer", "secret-access-token-42", fmt.Sprint(nowUnix)); v.Valid || failed(v) != "Signature verification" {
		t.Errorf("re-encoded payload: failed %q, want only the signature: %+v", failed(v), v.Checks)
	}
}

func TestDPoPVerify_FreshnessAndClockSkew(t *testing.T) {
	now := time.Now()
	tokenTime := now.Unix()

	gen := opOf[ciphertools.DPoPGenerateResult](t, "dpop-generate", url.Values{
		"htm": {"GET"},
		"htu": {"https://api.example.com/feed"},
		"now": {fmt.Sprintf("%d", tokenTime)},
	}, nil)

	// Past beyond leeway (token is 120s old, leeway is default 60s)
	vOld := opOf[ciphertools.DPoPVerifyResult](t, "dpop-verify", url.Values{
		"token": {gen.Token},
		"htm":   {"GET"},
		"htu":   {"https://api.example.com/feed"},
		"now":   {fmt.Sprintf("%d", tokenTime+120)},
	}, nil)
	if vOld.Valid {
		t.Errorf("expected token from past to be rejected as expired")
	}

	// Future beyond leeway (token issued 120s into the future)
	vFuture := opOf[ciphertools.DPoPVerifyResult](t, "dpop-verify", url.Values{
		"token": {gen.Token},
		"htm":   {"GET"},
		"htu":   {"https://api.example.com/feed"},
		"now":   {fmt.Sprintf("%d", tokenTime-120)},
	}, nil)
	if vFuture.Valid {
		t.Errorf("expected token from future to be rejected")
	}

	// Within custom leeway (token is 90s old, custom leeway is 180s)
	vLeeway := opOf[ciphertools.DPoPVerifyResult](t, "dpop-verify", url.Values{
		"token":  {gen.Token},
		"htm":    {"GET"},
		"htu":    {"https://api.example.com/feed"},
		"leeway": {"180"},
		"now":    {fmt.Sprintf("%d", tokenTime+90)},
	}, nil)
	if !vLeeway.Valid {
		t.Errorf("expected token to pass within extended leeway: %+v", vLeeway)
	}
}

func TestDPoPVerify_SecurityPrivateKeyInJWK(t *testing.T) {
	privKey := mustEC(t)
	headerJSON := fmt.Sprintf(`{"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"%s","y":"%s","d":"%s"}}`,
		b64urlTest(privKey.X.Bytes()), b64urlTest(privKey.Y.Bytes()), b64urlTest(privKey.D.Bytes()))
	payloadJSON := `{"jti":"test-jti","htm":"GET","htu":"https://api.example.com","iat":1700000000}`

	vRes := verifyProof(t, signES256(t, privKey, headerJSON, payloadJSON), "GET", "https://api.example.com", "", "1700000000")
	if vRes.Valid {
		t.Fatalf("security violation: proof with private key 'd' in JWK must be rejected")
	}
	foundLeakWarning := false
	for _, c := range vRes.Checks {
		if strings.Contains(c.Detail, "security violation: private key material") {
			foundLeakWarning = true
			break
		}
	}
	if !foundLeakWarning {
		t.Errorf("expected security violation warning for 'd' parameter in JWK, got: %+v", vRes.Checks)
	}
}

// RFC 9449 requires jti; the payload comes back as signed, unknown claims kept and absent ones not invented.
func TestDPoPVerify_RequiresJTI(t *testing.T) {
	k := mustEC(t)
	payload := `{"htm":"GET","htu":"https://api.example.com/r","iat":1700000000,"extra":"kept"}`
	v := verifyProof(t, signES256(t, k, esHeader(k), payload), "GET", "https://api.example.com/r", "", "1700000000")
	if v.Valid || failed(v) != "Unique identifier (jti)" {
		t.Errorf("proof without jti: failed %q, want only the jti check: %+v", failed(v), v.Checks)
	}
	if string(v.Payload) != payload || strings.Contains(v.PayloadJSON, "ath") {
		t.Errorf("payload = %s, want it as signed: %s", v.Payload, payload)
	}
	if strings.Contains(v.Summary, "conforms") {
		t.Errorf("summary claims more than was checked: %q", v.Summary)
	}
}

// htu is compared without query or fragment, its scheme and host in any case, its path exactly.
func TestDPoPVerify_HTUComparison(t *testing.T) {
	k := mustEC(t)
	tok := signES256(t, k, esHeader(k), `{"jti":"j","htm":"GET","htu":"https://api.example.com/Resource","iat":1700000000}`)
	for expected, ok := range map[string]bool{
		"https://api.example.com/Resource":              true,
		"HTTPS://API.Example.COM:443/Resource?page=2#x": true,
		"https://api.example.com/resource":              false,
		"https://api.example.com:8443/Resource":         false,
		"http://api.example.com/Resource":               false,
	} {
		if v := verifyProof(t, tok, "GET", expected, "", "1700000000"); v.Valid != ok {
			t.Errorf("expected htu %s: valid %v, want %v: %+v", expected, v.Valid, ok, v.Checks)
		}
	}
	withQuery := signES256(t, k, esHeader(k), `{"jti":"j","htm":"GET","htu":"https://api.example.com/Resource?a=1","iat":1700000000}`)
	if v := verifyProof(t, withQuery, "GET", "https://api.example.com/Resource", "", "1700000000"); v.Valid {
		t.Errorf("an htu with a query passed")
	}
	wantErr(t, "dpop-verify", url.Values{"token": {tok}, "htm": {"GET"}, "htu": {"not a url at all"}}, "invalid htu URI")
}

func verifyProof(t *testing.T, token, htm, htu, accessToken, now string) *ciphertools.DPoPVerifyResult {
	t.Helper()
	return opOf[ciphertools.DPoPVerifyResult](t, "dpop-verify", url.Values{
		"token": {token}, "htm": {htm}, "htu": {htu}, "access_token": {accessToken}, "now": {now},
	}, nil)
}

// failed names the failed checks, comma-separated.
func failed(v *ciphertools.DPoPVerifyResult) string {
	var names []string
	for _, c := range v.Checks {
		if !c.Passed {
			names = append(names, c.Name)
		}
	}
	return strings.Join(names, ", ")
}

func claimsOf(t *testing.T, payload json.RawMessage) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatalf("payload %s: %v", payload, err)
	}
	return m
}

func mustEC(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pkcs8(t *testing.T, k any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func esHeader(k *ecdsa.PrivateKey) string {
	return fmt.Sprintf(`{"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"%s","y":"%s"}}`,
		b64urlTest(k.X.FillBytes(make([]byte, 32))), b64urlTest(k.Y.FillBytes(make([]byte, 32))))
}

func signES256(t *testing.T, k *ecdsa.PrivateKey, header, payload string) string {
	t.Helper()
	input := b64urlTest([]byte(header)) + "." + b64urlTest([]byte(payload))
	hash := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, k, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64urlTest(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}

func s256Test(s string) string {
	sum := sha256.Sum256([]byte(s))
	return b64urlTest(sum[:])
}

func b64urlTest(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

// The curl line is pasted into a shell, so a quote in any value must not end its quoting.
func TestDPoPCurlLineIsShellSafe(t *testing.T) {
	gen := opOf[ciphertools.DPoPGenerateResult](t, "dpop-generate", url.Values{
		"htm": {"GET"}, "htu": {"https://api.example.com/$HOME"}, "access_token": {`x'; touch /tmp/p; echo "`},
	}, nil)
	for _, want := range []string{`'Authorization: DPoP x'\''; touch /tmp/p; echo "'`, `'https://api.example.com/$HOME'`} {
		if !strings.Contains(gen.Curl, want) {
			t.Errorf("curl line lacks %s:\n%s", want, gen.Curl)
		}
	}
}

func TestDPoPVerify_RefusesNonUTF8(t *testing.T) {
	token := b64urlTest([]byte("{\"typ\":\"\xff\",\"alg\":\"ES256\"}")) + "." + b64urlTest([]byte("{}")) + ".AA"
	wantErr(t, "dpop-verify", url.Values{"token": {token}, "htm": {"GET"}, "htu": {"https://api.example.com/r"}}, "the header is not UTF-8")
}
