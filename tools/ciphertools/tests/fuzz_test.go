package tests

import (
	"net/url"
	"testing"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

func FuzzDPoPVerify(f *testing.F) {
	f.Add("eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiYWFhIiwieSI6ImJmYiJ9fQ.eyJqdGkiOiIxMjM0IiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsImlhdCI6MTcwMDAwMDAwMH0.c2ln", "GET", "https://example.com", "token123")
	f.Add("malformed.jwt", "POST", "https://api.example.com", "")
	f.Add("", "", "", "")

	op, ok := ciphertools.Lookup("dpop-verify")
	if !ok {
		f.Fatal("no dpop-verify op")
	}

	f.Fuzz(func(t *testing.T, token, htm, htu, accessToken string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("PANIC on token %q: %v", token, r)
			}
		}()
		in := ciphertools.Input{
			Fields: url.Values{
				"token":        {token},
				"htm":          {htm},
				"htu":          {htu},
				"access_token": {accessToken},
			},
		}
		_, _ = ciphertools.Run(op, in)
	})
}

func FuzzPKCEVerify(f *testing.F) {
	f.Add("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256")
	f.Add("plainverifierplainverifierplainverifierplain1234", "plainverifierplainverifierplainverifierplain1234", "plain")
	f.Add("short", "challenge", "S256")
	f.Add("", "", "S256")

	op, ok := ciphertools.Lookup("pkce-verify")
	if !ok {
		f.Fatal("no pkce-verify op")
	}

	f.Fuzz(func(t *testing.T, verifier, challenge, method string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("PANIC on verifier %q: %v", verifier, r)
			}
		}()
		in := ciphertools.Input{
			Fields: url.Values{
				"code_verifier":  {verifier},
				"code_challenge": {challenge},
				"method":         {method},
			},
		}
		_, _ = ciphertools.Run(op, in)
	})
}
