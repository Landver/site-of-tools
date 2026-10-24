package ciphertools

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"
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
	method := strings.TrimSpace(in.Get("method"))
	if method == "" {
		method = "S256"
	} else if method != "S256" && method != "plain" {
		return nil, fmt.Errorf("method: want S256 or plain, got %q", method)
	}

	verifier, err := generateRandomVerifier(length)
	if err != nil {
		return nil, fmt.Errorf("generating verifier: %w", err)
	}

	var challenge string
	if method == "plain" {
		challenge = verifier
	} else {
		sum := sha256.Sum256([]byte(verifier))
		challenge = b64url.EncodeToString(sum[:])
	}

	// 66 possible chars: log2(66) ~= 6.044 bits of entropy per character
	entropy := int(math.Floor(float64(length) * 6.044))

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", "example-client")
	params.Set("redirect_uri", "https://app.example.com/callback")
	params.Set("scope", "openid profile email")
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", method)

	exampleURL := "https://auth.example.com/oauth/authorize?" + params.Encode()

	return &PKCEGenerateResult{
		CodeVerifier:  verifier,
		CodeChallenge: challenge,
		Method:        method,
		EntropyBits:   entropy,
		ExampleURL:    exampleURL,
	}, nil
}

// PKCEVerifyResult holds the verification check outcome.
type PKCEVerifyResult struct {
	Valid               bool   `json:"valid"`
	Status              string `json:"status"` // "valid", "invalid", "error"
	Method              string `json:"method"`
	CalculatedChallenge string `json:"calculated_challenge"`
	Detail              string `json:"detail"`
}

func runPKCEVerify(in Input) (any, error) {
	verifier := strings.TrimSpace(in.Get("code_verifier"))
	challenge := strings.TrimSpace(in.Get("code_challenge"))
	method := strings.TrimSpace(in.Get("method"))
	if method == "" {
		method = "S256"
	} else if method != "S256" && method != "plain" {
		return nil, fmt.Errorf("method: want S256 or plain, got %q", method)
	}

	if verifier == "" {
		return nil, errors.New("no code_verifier given")
	}
	if challenge == "" {
		return nil, errors.New("no code_challenge given")
	}

	if len(verifier) < 43 || len(verifier) > 128 {
		return &PKCEVerifyResult{
			Valid:   false,
			Status:  "invalid",
			Method:  method,
			Detail:  fmt.Sprintf("Invalid code_verifier length: %d characters (RFC 7636 requires between 43 and 128 characters)", len(verifier)),
		}, nil
	}

	for i := 0; i < len(verifier); i++ {
		c := verifier[i]
		if !strings.ContainsRune(pkceCharset, rune(c)) {
			return &PKCEVerifyResult{
				Valid:  false,
				Status: "invalid",
				Method: method,
				Detail: fmt.Sprintf("Invalid character %q in code_verifier: RFC 7636 permits only [A-Z], [a-z], [0-9], '-', '.', '_', '~'", c),
			}, nil
		}
	}

	var expected string
	if method == "plain" {
		expected = verifier
	} else {
		sum := sha256.Sum256([]byte(verifier))
		expected = b64url.EncodeToString(sum[:])
	}

	// Constant-time compare to prevent side-channel timing leaks
	valid := subtle.ConstantTimeCompare([]byte(expected), []byte(challenge)) == 1

	var detail string
	if valid {
		if method == "plain" {
			detail = "Challenge matches code_verifier (plain method). Note: OAuth 2.1 deprecates plain; S256 should be used instead."
		} else {
			detail = "Challenge successfully verified: matches base64url(sha256(code_verifier))."
		}
	} else {
		detail = "Challenge mismatch: the calculated challenge does not match the provided challenge string."
	}

	return &PKCEVerifyResult{
		Valid:               valid,
		Status:              ifElse(valid, "valid", "invalid"),
		Method:              method,
		CalculatedChallenge: expected,
		Detail:              detail,
	}, nil
}

func generateRandomVerifier(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	var sb strings.Builder
	sb.Grow(length)
	charsetLen := byte(len(pkceCharset))
	for _, b := range bytes {
		sb.WriteByte(pkceCharset[b%charsetLen])
	}
	return sb.String(), nil
}

func ifElse[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}
