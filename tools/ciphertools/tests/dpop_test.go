package tests

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
		"htm": {"POST"},
		"htu": {"https://auth.example.com/token"},
		"alg": {"RS256"},
		"key": {string(rsaJWK)},
		"ath": {"my-access-token-xyz"},
	}, nil)

	if resRSA.Alg != "RS256" {
		t.Errorf("alg: want RS256, got %s", resRSA.Alg)
	}
	if !strings.Contains(resRSA.PayloadJSON, `"ath"`) {
		t.Errorf("payload missing ath claim: %s", resRSA.PayloadJSON)
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
}

func TestDPoPVerify_FullLifecycleAndTampering(t *testing.T) {
	nowUnix := time.Now().Unix()
	gen := opOf[ciphertools.DPoPGenerateResult](t, "dpop-generate", url.Values{
		"htm":   {"POST"},
		"htu":   {"https://api.example.com/transfer"},
		"ath":   {"secret-access-token-42"},
		"nonce": {"server-challenge-123"},
		"now":   {fmt.Sprintf("%d", nowUnix)},
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
		"now":   {fmt.Sprintf("%d", tokenTime + 120)},
	}, nil)
	if vOld.Valid {
		t.Errorf("expected token from past to be rejected as expired")
	}

	// Future beyond leeway (token issued 120s into the future)
	vFuture := opOf[ciphertools.DPoPVerifyResult](t, "dpop-verify", url.Values{
		"token": {gen.Token},
		"htm":   {"GET"},
		"htu":   {"https://api.example.com/feed"},
		"now":   {fmt.Sprintf("%d", tokenTime - 120)},
	}, nil)
	if vFuture.Valid {
		t.Errorf("expected token from future to be rejected")
	}

	// Within custom leeway (token is 90s old, custom leeway is 180s)
	vLeeway := opOf[ciphertools.DPoPVerifyResult](t, "dpop-verify", url.Values{
		"token":   {gen.Token},
		"htm":     {"GET"},
		"htu":     {"https://api.example.com/feed"},
		"leeway":  {"180"},
		"now":     {fmt.Sprintf("%d", tokenTime + 90)},
	}, nil)
	if !vLeeway.Valid {
		t.Errorf("expected token to pass within extended leeway: %+v", vLeeway)
	}
}

func TestDPoPVerify_SecurityPrivateKeyInJWK(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	headerJSON := fmt.Sprintf(`{"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"%s","y":"%s","d":"%s"}}`,
		b64urlTest(privKey.X.Bytes()), b64urlTest(privKey.Y.Bytes()), b64urlTest(privKey.D.Bytes()))
	payloadJSON := `{"jti":"test-jti","htm":"GET","htu":"https://api.example.com","iat":1700000000}`

	signingInput := b64urlTest([]byte(headerJSON)) + "." + b64urlTest([]byte(payloadJSON))
	hash := sha256.Sum256([]byte(signingInput))
	r, s, _ := ecdsa.Sign(rand.Reader, privKey, hash[:])
	rBytes, sBytes := r.Bytes(), s.Bytes()
	sigBytes := make([]byte, 64)
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)
	token := signingInput + "." + b64urlTest(sigBytes)

	vRes := opOf[ciphertools.DPoPVerifyResult](t, "dpop-verify", url.Values{
		"token": {token},
		"htm":   {"GET"},
		"htu":   {"https://api.example.com"},
		"now":   {"1700000000"},
	}, nil)

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

func b64urlTest(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}
