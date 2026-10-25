package tests

import (
	"crypto/sha256"
	"net/url"
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

func TestPKCEGenerate_BoundariesAndMethods(t *testing.T) {
	// 1. Min length boundary (43)
	res43 := opOf[ciphertools.PKCEGenerateResult](t, "pkce-generate", url.Values{
		"length": {"43"},
		"method": {"S256"},
	}, nil)
	if len(res43.CodeVerifier) != 43 {
		t.Errorf("verifier length: want 43, got %d", len(res43.CodeVerifier))
	}
	if len(res43.CodeChallenge) != 43 {
		t.Errorf("S256 challenge length: want 43, got %d", len(res43.CodeChallenge))
	}

	// 2. Max length boundary (128)
	res128 := opOf[ciphertools.PKCEGenerateResult](t, "pkce-generate", url.Values{
		"length": {"128"},
		"method": {"S256"},
	}, nil)
	if len(res128.CodeVerifier) != 128 {
		t.Errorf("verifier length: want 128, got %d", len(res128.CodeVerifier))
	}

	// 3. Out of boundary: length 42 (< 43)
	wantErr(t, "pkce-generate", url.Values{"length": {"42"}}, "43")

	// 4. Out of boundary: length 129 (> 128)
	wantErr(t, "pkce-generate", url.Values{"length": {"129"}}, "128")

	// 5. Plain method
	resPlain := opOf[ciphertools.PKCEGenerateResult](t, "pkce-generate", url.Values{
		"length": {"50"},
		"method": {"plain"},
	}, nil)
	if resPlain.CodeChallenge != resPlain.CodeVerifier {
		t.Errorf("plain challenge must match verifier exactly")
	}

	// 6. Invalid method
	wantErr(t, "pkce-generate", url.Values{"method": {"none"}}, "want S256 or plain")

	// 7. The method in any case reads as RFC 7636 spells it.
	resLower := opOf[ciphertools.PKCEGenerateResult](t, "pkce-generate", url.Values{"method": {"s256"}}, nil)
	sum := sha256.Sum256([]byte(resLower.CodeVerifier))
	if resLower.Method != "S256" || resLower.CodeChallenge != b64urlTest(sum[:]) || !strings.Contains(resLower.ExampleURL, "code_challenge_method=S256") {
		t.Errorf("method s256: %+v", resLower)
	}
	if strings.Trim(resLower.CodeVerifier, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~") != "" || len(resLower.CodeVerifier) != 64 {
		t.Errorf("default verifier %q: want 64 unreserved characters", resLower.CodeVerifier)
	}
}

func TestPKCEVerify_RFC7636Vector(t *testing.T) {
	// RFC 7636 Appendix B test vector
	const (
		verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)

	res := opOf[ciphertools.PKCEVerifyResult](t, "pkce-verify", url.Values{
		"code_verifier":  {verifier},
		"code_challenge": {challenge},
		"method":         {"S256"},
	}, nil)

	if !res.Valid || res.Status != "valid" {
		t.Fatalf("RFC 7636 Appendix B vector failed verification: %+v", res)
	}
	if res.CalculatedChallenge != challenge {
		t.Errorf("calculated challenge mismatch: want %s, got %s", challenge, res.CalculatedChallenge)
	}
}

func TestPKCEVerify_EdgeCasesAndCharsetViolations(t *testing.T) {
	// Valid base verifier of length 43
	validVerifier := strings.Repeat("a", 43)
	sum := sha256.Sum256([]byte(validVerifier))
	validChallenge := b64urlTest(sum[:])

	// 1. Length < 43
	resShort := opOf[ciphertools.PKCEVerifyResult](t, "pkce-verify", url.Values{
		"code_verifier":  {strings.Repeat("a", 42)},
		"code_challenge": {validChallenge},
		"method":         {"S256"},
	}, nil)
	if resShort.Valid {
		t.Errorf("expected short verifier (<43) to fail")
	}

	// 2. Length > 128
	resLong := opOf[ciphertools.PKCEVerifyResult](t, "pkce-verify", url.Values{
		"code_verifier":  {strings.Repeat("a", 129)},
		"code_challenge": {validChallenge},
		"method":         {"S256"},
	}, nil)
	if resLong.Valid {
		t.Errorf("expected long verifier (>128) to fail")
	}

	// 3. Prohibited characters in verifier (e.g. '+', '=', ' ', emoji)
	badChars := []string{
		strings.Repeat("a", 42) + "+",
		strings.Repeat("a", 42) + "=",
		strings.Repeat("a", 42) + " ",
		strings.Repeat("a", 41) + "🔐",
	}
	for _, bad := range badChars {
		resBad := opOf[ciphertools.PKCEVerifyResult](t, "pkce-verify", url.Values{
			"code_verifier":  {bad},
			"code_challenge": {validChallenge},
			"method":         {"S256"},
		}, nil)
		if resBad.Valid {
			t.Errorf("expected verifier with illegal characters %q to fail", bad)
		}
	}
	if r := opOf[ciphertools.PKCEVerifyResult](t, "pkce-verify", url.Values{
		"code_verifier": {strings.Repeat("a", 41) + "🔐"}, "code_challenge": {validChallenge},
	}, nil); !strings.Contains(r.Detail, `'🔐'`) {
		t.Errorf("a multi-byte character is named whole: %q", r.Detail)
	}

	// 4. Challenge mismatch
	resMismatch := opOf[ciphertools.PKCEVerifyResult](t, "pkce-verify", url.Values{
		"code_verifier":  {validVerifier},
		"code_challenge": {"wrong-challenge-string-12345678901234567890"},
		"method":         {"S256"},
	}, nil)
	if resMismatch.Valid {
		t.Errorf("expected challenge mismatch to fail")
	}

	// 5. Plain method match vs mismatch
	resPlainMatch := opOf[ciphertools.PKCEVerifyResult](t, "pkce-verify", url.Values{
		"code_verifier":  {validVerifier},
		"code_challenge": {validVerifier},
		"method":         {"plain"},
	}, nil)
	if !resPlainMatch.Valid {
		t.Errorf("expected plain match to pass")
	}

	resPlainMismatch := opOf[ciphertools.PKCEVerifyResult](t, "pkce-verify", url.Values{
		"code_verifier":  {validVerifier},
		"code_challenge": {validVerifier + "x"},
		"method":         {"plain"},
	}, nil)
	if resPlainMismatch.Valid {
		t.Errorf("expected plain mismatch to fail")
	}
}
