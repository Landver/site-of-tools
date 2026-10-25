package ciphertools

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"
)

// RFC 7636 unreserved characters for PKCE code_verifier: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
const pkceCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

var pkceLengthField = Field{Name: "length", Kind: KindInt, Min: ptr(43), Max: ptr(128),
	Description: "The length of the code verifier in characters, between 43 and 128 (default 64)."}.withDefault(64)

var pkceMethodField = Field{Name: "method", Kind: KindEnum, Enum: []string{"S256", "plain"}, Default: "S256",
	Description: "The transformation method: S256 (SHA-256 base64url-unpadded, strongly recommended) or plain."}

func init() {
	register(Op{Name: "pkce-generate", Path: "/pkce/generate", Page: "pkce", Fragment: "cipher/pkce-generated",
		Fields: []Field{
			pkceLengthField,
			pkceMethodField,
		},
		Run: runPKCEGenerate,
	})

	register(Op{Name: "pkce-verify", Path: "/pkce/verify", Page: "pkce", Fragment: "cipher/pkce-verified",
		Fields: []Field{
			{
				Name:        "code_verifier",
				Kind:        KindString,
				Required:    true,
				Description: "The high-entropy cryptographic code_verifier string (43 to 128 characters).",
			},
			{
				Name:        "code_challenge",
				Kind:        KindString,
				Required:    true,
				Description: "The expected code_challenge string to verify against the code_verifier.",
			},
			pkceMethodField,
		},
		Run: runPKCEVerify,
	})
}

// PKCEGenerateResult holds the generated code_verifier and code_challenge.
type PKCEGenerateResult struct {
	CodeVerifier  string `json:"code_verifier"`
	CodeChallenge string `json:"code_challenge"`
	Method        string `json:"method"`
	EntropyBits   int    `json:"entropy_bits"`
	ExampleURL    string `json:"example_url"`
}

func runPKCEGenerate(in Input) (any, error) {
	length, err := intField(in, pkceLengthField)
	if err != nil {
		return nil, err
	}
	method, err := enumField(in.Get("method"), pkceMethodField)
	if err != nil {
		return nil, err
	}
	verifier := randomPick(pkceCharset, length)
	challenge := pkceChallenge(verifier, method)
	return &PKCEGenerateResult{
		CodeVerifier:  verifier,
		CodeChallenge: challenge,
		Method:        method,
		EntropyBits:   int(float64(length) * math.Log2(float64(len(pkceCharset)))),
		ExampleURL: fmt.Sprintf(
			"https://auth.example.com/oauth/authorize?client_id=example-client&code_challenge=%s&code_challenge_method=%s&redirect_uri=https%%3A%%2F%%2Fapp.example.com%%2Fcallback&response_type=code&scope=openid+profile+email",
			challenge, method),
	}, nil
}

// PKCEVerifyResult holds the verification check outcome.
type PKCEVerifyResult struct {
	Valid               bool   `json:"valid"`
	Status              string `json:"status"` // "valid" or "invalid"
	Method              string `json:"method"`
	CalculatedChallenge string `json:"calculated_challenge"`
	Detail              string `json:"detail"`
}

func runPKCEVerify(in Input) (any, error) {
	method, err := enumField(in.Get("method"), pkceMethodField)
	if err != nil {
		return nil, err
	}
	verifier := strings.TrimSpace(in.Get("code_verifier"))
	challenge := strings.TrimSpace(in.Get("code_challenge"))
	switch {
	case verifier == "":
		return nil, errors.New("no code_verifier given")
	case challenge == "":
		return nil, errors.New("no code_challenge given")
	}
	r := &PKCEVerifyResult{Method: method}
	bad := strings.IndexFunc(verifier, func(c rune) bool { return !strings.ContainsRune(pkceCharset, c) })
	switch {
	case len(verifier) < *pkceLengthField.Min || len(verifier) > *pkceLengthField.Max:
		r.Detail = fmt.Sprintf("Invalid code_verifier length: %d characters (RFC 7636 requires between 43 and 128 characters)", len(verifier))
	case bad >= 0:
		c, _ := utf8.DecodeRuneInString(verifier[bad:])
		r.Detail = fmt.Sprintf("Invalid character %q in code_verifier: RFC 7636 permits only [A-Z], [a-z], [0-9], '-', '.', '_', '~'", c)
	default:
		r.CalculatedChallenge = pkceChallenge(verifier, method)
		r.Valid = subtle.ConstantTimeCompare([]byte(r.CalculatedChallenge), []byte(challenge)) == 1
		switch {
		case !r.Valid:
			r.Detail = "Challenge mismatch: the calculated challenge does not match the provided challenge string."
		case method == "plain":
			r.Detail = "Challenge matches code_verifier (plain method). Note: OAuth 2.1 deprecates plain; S256 should be used instead."
		default:
			r.Detail = "Challenge successfully verified: matches base64url(sha256(code_verifier))."
		}
	}
	r.Status = ifElse(r.Valid, "valid", "invalid")
	return r, nil
}

// pkceChallenge is RFC 7636 §4.2's code_challenge of verifier under method.
func pkceChallenge(verifier, method string) string {
	if method == "plain" {
		return verifier
	}
	return s256(verifier)
}

// s256 is unpadded base64url(SHA-256(s)): PKCE's S256 challenge and DPoP's ath alike.
func s256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return b64url.EncodeToString(sum[:])
}

func ifElse[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}
