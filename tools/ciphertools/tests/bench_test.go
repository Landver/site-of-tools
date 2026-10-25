package tests

import (
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

func BenchmarkDPoPGenerate(b *testing.B) {
	op, _ := ciphertools.Lookup("dpop-generate")
	in := ciphertools.Input{
		Fields: url.Values{
			"htm":          {"POST"},
			"htu":          {"https://api.example.com/oauth/token"},
			"access_token": {"my-secret-access-token-12345"},
			"nonce":        {"srv-nonce-9876"},
			"now":          {fmt.Sprintf("%d", time.Now().Unix())},
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ciphertools.Run(op, in); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDPoPVerify(b *testing.B) {
	genOp, _ := ciphertools.Lookup("dpop-generate")
	verifyOp, _ := ciphertools.Lookup("dpop-verify")
	nowUnix := time.Now().Unix()

	genRes, err := ciphertools.Run(genOp, ciphertools.Input{
		Fields: url.Values{
			"htm":          {"POST"},
			"htu":          {"https://api.example.com/oauth/token"},
			"access_token": {"my-secret-access-token-12345"},
			"now":          {fmt.Sprintf("%d", nowUnix)},
		},
	})
	if err != nil {
		b.Fatal(err)
	}
	token := genRes.(*ciphertools.DPoPGenerateResult).Token

	in := ciphertools.Input{
		Fields: url.Values{
			"token":        {token},
			"htm":          {"POST"},
			"htu":          {"https://api.example.com/oauth/token"},
			"access_token": {"my-secret-access-token-12345"},
			"now":          {fmt.Sprintf("%d", nowUnix)},
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ciphertools.Run(verifyOp, in); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPKCEGenerate(b *testing.B) {
	op, _ := ciphertools.Lookup("pkce-generate")
	in := ciphertools.Input{
		Fields: url.Values{"length": {"64"}, "method": {"S256"}},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ciphertools.Run(op, in); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPKCEVerify(b *testing.B) {
	op, _ := ciphertools.Lookup("pkce-verify")
	in := ciphertools.Input{
		Fields: url.Values{
			"code_verifier":  {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
			"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
			"method":         {"S256"},
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ciphertools.Run(op, in); err != nil {
			b.Fatal(err)
		}
	}
}
