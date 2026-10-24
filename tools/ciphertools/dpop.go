package ciphertools

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
)

var dpopLeewayField = Field{Name: "leeway", Kind: KindInt, Min: ptr(0), Max: ptr(86400),
	Description: "Clock skew in seconds allowed when checking the iat creation timestamp."}.withDefault(60)

func init() {
	register(Op{Name: "dpop-generate", Path: "/dpop/generate", Page: "dpop", Fragment: "cipher/dpop-generated", Heavy: true,
		Fields: []Field{
			{
				Name:        "htm",
				Kind:        KindString,
				Required:    true,
				Description: "The HTTP request method (e.g. GET, POST, PUT, DELETE, PATCH).",
			},
			{
				Name:        "htu",
				Kind:        KindString,
				Required:    true,
				Description: "The target HTTP request URI without query parameters or fragment (e.g. https://api.example.com/resource).",
			},
			{
				Name:        "ath",
				Kind:        KindString,
				Description: "Optional access token string to calculate ath from, or a precomputed base64url SHA-256 access token hash.",
			},
			{
				Name:        "nonce",
				Kind:        KindString,
				Description: "An optional server-provided DPoP nonce challenge string from a DPoP-Nonce response header.",
			},
			{
				Name:        "alg",
				Kind:        KindEnum,
				Enum:        []string{"ES256", "RS256", "EdDSA"},
				Default:     "ES256",
				Description: "The asymmetric signing algorithm for the DPoP proof (ES256 is the default for RFC 9449).",
			},
			{
				Name:        "key",
				Kind:        KindString,
				Description: "An optional private key as PEM or JWK; if omitted, a fresh ephemeral ECDSA P-256 key pair is generated.",
			},
			nowField,
		},
		Run: runDPoPGenerate,
	})

	register(Op{Name: "dpop-verify", Path: "/dpop/verify", Page: "dpop", Fragment: "cipher/dpop-verified",
		Fields: []Field{
			{
				Name:        "token",
				Kind:        KindString,
				Required:    true,
				Description: "The DPoP proof JWT string to verify (header.payload.signature).",
			},
			{
				Name:        "htm",
				Kind:        KindString,
				Required:    true,
				Description: "The expected HTTP request method that the proof was issued for (e.g. GET, POST).",
			},
			{
				Name:        "htu",
				Kind:        KindString,
				Required:    true,
				Description: "The expected target HTTP request URI without query parameters or fragment.",
			},
			{
				Name:        "access_token",
				Kind:        KindString,
				Description: "The optional raw access token presented with the request, to verify against the ath claim.",
			},
			dpopLeewayField,
			nowField,
		},
		Run: runDPoPVerify,
	})
}

// DPoPCheck represents an individual validation check on a DPoP proof.
type DPoPCheck struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// DPoPGenerateResult holds the output of a generated DPoP proof.
type DPoPGenerateResult struct {
	Token         string      `json:"token"`
	HTM           string      `json:"htm"`
	HTU           string      `json:"htu"`
	Alg           string      `json:"alg"`
	HeaderJSON    string      `json:"header_json"`
	PayloadJSON   string      `json:"payload_json"`
	PublicJWKJSON string      `json:"public_jwk_json"`
	JWKThumbprint string      `json:"jwk_thumbprint"`
	Curl          string      `json:"curl"`
	Key           string      `json:"key"` // Private key in PEM/JWK format for reuse
	Parts         []JWTPart   `json:"-"`
}

// DPoPVerifyResult holds the outcome of a DPoP verification.
type DPoPVerifyResult struct {
	Valid         bool        `json:"valid"`
	Status        string      `json:"status"` // "valid", "invalid", "error"
	HTM           string      `json:"htm,omitempty"`
	HTU           string      `json:"htu,omitempty"`
	Summary       string      `json:"summary"`
	JWKThumbprint string      `json:"jwk_thumbprint,omitempty"`
	HeaderJSON    string      `json:"header_json,omitempty"`
	PayloadJSON   string      `json:"payload_json,omitempty"`
	Checks        []DPoPCheck `json:"checks"`
}

func runDPoPGenerate(in Input) (any, error) {
	now, err := in.now()
	if err != nil {
		return nil, err
	}

	htm := strings.ToUpper(strings.TrimSpace(in.Get("htm")))
	if htm == "" {
		return nil, errors.New("HTTP method (htm) is required")
	}

	rawHTU := strings.TrimSpace(in.Get("htu"))
	if rawHTU == "" {
		return nil, errors.New("HTTP URI (htu) is required")
	}

	normalizedHTU, err := normalizeDPoPUri(rawHTU)
	if err != nil {
		return nil, fmt.Errorf("invalid htu URI: %w", err)
	}

	alg := strings.TrimSpace(in.Get("alg"))
	if alg == "" {
		alg = "ES256"
	}
	if !slices.Contains([]string{"ES256", "RS256", "EdDSA"}, alg) {
		return nil, fmt.Errorf("alg: want ES256, RS256 or EdDSA, got %q", alg)
	}
	spec, ok := jwsAlgs[alg]
	if !ok || spec.kind == KindSecret {
		return nil, fmt.Errorf("unsupported or symmetric algorithm %q: RFC 9449 mandates asymmetric algorithms (ES256, RS256, EdDSA)", alg)
	}

	var signingPrivKey Key
	var generatedPrivatePEM string
	userKeyInput := strings.TrimSpace(in.Get("key"))

	if userKeyInput == "" {
		// Generate ephemeral ECDSA P-256 key pair
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating key: %w", err)
		}
		signingPrivKey = Key{Kind: KindEC, Private: priv, Public: &priv.PublicKey}
		alg = "ES256"
		spec = jwsAlgs["ES256"]
	} else {
		keys, err := ParseKeys(userKeyInput)
		if err != nil {
			return nil, fmt.Errorf("parsing key: %w", err)
		}
		found := false
		for _, k := range keys {
			if k.Private != nil && jwtKeyFits(spec, k) {
				signingPrivKey = k
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("no matching private key found for %s", alg)
		}
	}

	// Extract strictly public JWK
	pubJWK, err := PublicJWK(signingPrivKey.Public)
	if err != nil {
		return nil, fmt.Errorf("deriving public JWK: %w", err)
	}

	// Hard security assertion: ensure no private key components exist in the public JWK
	if pubJWK.D != "" || pubJWK.P != "" || pubJWK.Q != "" {
		return nil, errors.New("security assertion failed: private key parameters present in public JWK")
	}

	// Calculate RFC 7638 thumbprint
	thumbprint, err := JWKThumbprint(pubJWK)
	if err != nil {
		return nil, fmt.Errorf("calculating jkt thumbprint: %w", err)
	}

	// Generate random jti
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return nil, err
	}
	jti := b64url.EncodeToString(jtiBytes)

	// Build Header
	headerMap := map[string]any{
		"typ": "dpop+jwt",
		"alg": alg,
		"jwk": pubJWK,
	}
	headerBytes, err := json.Marshal(headerMap)
	if err != nil {
		return nil, fmt.Errorf("marshaling header: %w", err)
	}

	// Build Payload
	payloadMap := map[string]any{
		"jti": jti,
		"htm": htm,
		"htu": normalizedHTU,
		"iat": now.Unix(),
	}

	nonce := strings.TrimSpace(in.Get("nonce"))
	if nonce != "" {
		payloadMap["nonce"] = nonce
	}

	rawATH := strings.TrimSpace(in.Get("ath"))
	if rawATH != "" {
		// If length is 43 chars and base64url, it might already be an ath hash; otherwise compute hash
		if len(rawATH) == 43 && isBase64URL(rawATH) {
			payloadMap["ath"] = rawATH
		} else {
			sum := sha256.Sum256([]byte(rawATH))
			payloadMap["ath"] = b64url.EncodeToString(sum[:])
		}
	}

	payloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		return nil, fmt.Errorf("marshaling payload: %w", err)
	}

	// Sign token
	signingInput := b64url.EncodeToString(headerBytes) + "." + b64url.EncodeToString(payloadBytes)
	sig, err := signJWS(spec, signingPrivKey, []byte(signingInput))
	if err != nil {
		return nil, fmt.Errorf("signing DPoP proof: %w", err)
	}

	token := signingInput + "." + b64url.EncodeToString(sig)

	// Formatted JSON outputs
	headerPretty, _ := json.MarshalIndent(headerMap, "", "  ")
	payloadPretty, _ := json.MarshalIndent(payloadMap, "", "  ")
	pubJWKPretty, _ := json.MarshalIndent(pubJWK, "", "  ")

	// Curl example
	var curlBuilder strings.Builder
	curlBuilder.WriteString(fmt.Sprintf("curl -X %s \\\n  -H \"DPoP: %s\" \\\n", htm, token))
	if rawATH != "" {
		curlBuilder.WriteString(fmt.Sprintf("  -H \"Authorization: DPoP %s\" \\\n", rawATH))
	}
	curlBuilder.WriteString(fmt.Sprintf("  \"%s\"", normalizedHTU))

	parts := []JWTPart{
		{Label: "Header", Value: b64url.EncodeToString(headerBytes)},
		{Label: "Payload", Value: b64url.EncodeToString(payloadBytes)},
		{Label: "Signature", Value: b64url.EncodeToString(sig)},
	}

	return &DPoPGenerateResult{
		Token:         token,
		HTM:           htm,
		HTU:           normalizedHTU,
		Alg:           alg,
		Parts:         parts,
		HeaderJSON:    string(headerPretty),
		PayloadJSON:   string(payloadPretty),
		PublicJWKJSON: string(pubJWKPretty),
		JWKThumbprint: thumbprint,
		Curl:          curlBuilder.String(),
		Key:           generatedPrivatePEM,
	}, nil
}

func runDPoPVerify(in Input) (any, error) {
	now, err := in.now()
	if err != nil {
		return nil, err
	}
	leewayInt, err := intField(in, dpopLeewayField)
	if err != nil {
		return nil, err
	}
	leeway := time.Duration(leewayInt) * time.Second

	rawToken := strings.TrimSpace(in.Get("token"))
	expectedHTM := strings.ToUpper(strings.TrimSpace(in.Get("htm")))
	expectedHTU := strings.TrimSpace(in.Get("htu"))
	expectedAccessToken := strings.TrimSpace(in.Get("access_token"))

	if rawToken == "" {
		return nil, errors.New("no DPoP token given")
	}
	if expectedHTM == "" {
		return nil, errors.New("no htm given")
	}
	if expectedHTU == "" {
		return nil, errors.New("no htu given")
	}

	token := strings.TrimPrefix(rawToken, "DPoP ")
	token = strings.TrimPrefix(token, "Bearer ")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return &DPoPVerifyResult{
			Valid:   false,
			Status:  "invalid",
			Summary: "Malformed JWT: expected exactly 3 dot-separated segments.",
			Checks: []DPoPCheck{
				{Name: "JWT Structure", Passed: false, Detail: fmt.Sprintf("Found %d segments instead of 3", len(parts))},
			},
		}, nil
	}

	headerBytes, err := b64url.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding header: %w", err)
	}
	payloadBytes, err := b64url.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding payload: %w", err)
	}
	sigBytes, err := b64url.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decoding signature: %w", err)
	}

	var header struct {
		Typ string          `json:"typ"`
		Alg string          `json:"alg"`
		JWK json.RawMessage `json:"jwk"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("parsing header JSON: %w", err)
	}

	var payload struct {
		JTI   string `json:"jti"`
		HTM   string `json:"htm"`
		HTU   string `json:"htu"`
		IAT   int64  `json:"iat"`
		ATH   string `json:"ath"`
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("parsing payload JSON: %w", err)
	}

	var checks []DPoPCheck
	allPassed := true

	// Check 1: Header typ == "dpop+jwt"
	typPassed := strings.EqualFold(header.Typ, "dpop+jwt")
	checks = append(checks, DPoPCheck{
		Name:   "Header typ is dpop+jwt",
		Passed: typPassed,
		Detail: fmt.Sprintf("typ is %q (RFC 9449 requires %q)", header.Typ, "dpop+jwt"),
	})
	if !typPassed {
		allPassed = false
	}

	// Check 2: Asymmetric alg
	spec, hasSpec := jwsAlgs[header.Alg]
	algPassed := hasSpec && spec.kind != KindSecret && !strings.EqualFold(header.Alg, "none")
	checks = append(checks, DPoPCheck{
		Name:   "Asymmetric algorithm",
		Passed: algPassed,
		Detail: fmt.Sprintf("alg is %q (must be an asymmetric signature algorithm: ES*, RS*, PS*, EdDSA)", header.Alg),
	})
	if !algPassed {
		allPassed = false
	}

	// Check 3: Public JWK present and clean of private key material
	var rawJWK map[string]any
	var pubJWK JWK
	var thumbprint string
	jwkPassed := false
	var jwkDetail string

	if len(header.JWK) == 0 {
		jwkDetail = "Header is missing embedded 'jwk' public key"
	} else if err := json.Unmarshal(header.JWK, &rawJWK); err != nil {
		jwkDetail = fmt.Sprintf("Malformed jwk in header: %v", err)
	} else if rawJWK["d"] != nil || rawJWK["p"] != nil || rawJWK["q"] != nil {
		jwkDetail = "RFC 9449 security violation: private key material ('d', 'p', or 'q') detected in header jwk"
	} else if err := json.Unmarshal(header.JWK, &pubJWK); err != nil {
		jwkDetail = fmt.Sprintf("Invalid JWK structure: %v", err)
	} else {
		parsedKeys, err := ParseKeys(string(header.JWK))
		if err != nil || len(parsedKeys) == 0 || parsedKeys[0].Public == nil {
			jwkDetail = "Failed to parse public key from embedded JWK"
		} else {
			jwkPassed = true
			jwkDetail = fmt.Sprintf("Valid %s embedded public key (%s)", pubJWK.Kty, keyName(parsedKeys[0].Public))
			thumbprint, _ = JWKThumbprint(pubJWK)
		}
	}
	checks = append(checks, DPoPCheck{
		Name:   "Embedded public JWK",
		Passed: jwkPassed,
		Detail: jwkDetail,
	})
	if !jwkPassed {
		allPassed = false
	}

	// Check 4: Cryptographic signature verification
	sigPassed := false
	var sigDetail string
	if jwkPassed && algPassed {
		parsedKeys, _ := ParseKeys(string(header.JWK))
		signedPayload := []byte(parts[0] + "." + parts[1])
		if verifyJWS(spec, parsedKeys[0], signedPayload, sigBytes) {
			sigPassed = true
			sigDetail = "Cryptographic signature is valid for embedded public key."
		} else {
			sigDetail = "Signature verification failed: proof has been altered or signed with a different key."
		}
	} else {
		sigDetail = "Skipped because algorithm or JWK is invalid."
	}
	checks = append(checks, DPoPCheck{
		Name:   "Signature verification",
		Passed: sigPassed,
		Detail: sigDetail,
	})
	if !sigPassed {
		allPassed = false
	}

	// Check 5: HTTP Method (htm)
	htmPassed := true
	var htmDetail string
	if expectedHTM != "" {
		htmPassed = strings.EqualFold(payload.HTM, expectedHTM)
		htmDetail = fmt.Sprintf("Proof method %q matches expected %q.", payload.HTM, expectedHTM)
		if !htmPassed {
			htmDetail = fmt.Sprintf("Proof method %q does NOT match expected %q.", payload.HTM, expectedHTM)
		}
	} else {
		htmDetail = fmt.Sprintf("Proof specifies method %q (no expected method provided to check against).", payload.HTM)
	}
	checks = append(checks, DPoPCheck{
		Name:   "HTTP method (htm)",
		Passed: htmPassed,
		Detail: htmDetail,
	})
	if !htmPassed {
		allPassed = false
	}

	// Check 6: HTTP URI (htu) without query or fragment
	htuPassed := true
	var htuDetail string
	if strings.ContainsAny(payload.HTU, "?#") {
		htuPassed = false
		htuDetail = fmt.Sprintf("RFC 9449 violation: htu (%q) must NOT contain query parameters or fragments.", payload.HTU)
	} else if expectedHTU != "" {
		normExpected, err := normalizeDPoPUri(expectedHTU)
		if err == nil && !strings.EqualFold(payload.HTU, normExpected) {
			htuPassed = false
			htuDetail = fmt.Sprintf("Proof URI %q does NOT match expected %q.", payload.HTU, normExpected)
		} else {
			htuDetail = fmt.Sprintf("Proof URI matches %q.", payload.HTU)
		}
	} else {
		htuDetail = fmt.Sprintf("Proof specifies URI %q (syntactically valid without query/fragment).", payload.HTU)
	}
	checks = append(checks, DPoPCheck{
		Name:   "HTTP URI (htu)",
		Passed: htuPassed,
		Detail: htuDetail,
	})
	if !htuPassed {
		allPassed = false
	}

	// Check 7: Creation time (iat) freshness
	iatTime := time.Unix(payload.IAT, 0)
	earliest := now.Add(-leeway)
	latest := now.Add(leeway)
	iatPassed := !iatTime.Before(earliest) && !iatTime.After(latest)
	iatDetail := fmt.Sprintf("iat (%s) is within acceptable leeway of current time (%s).", iatTime.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	if !iatPassed {
		iatDetail = fmt.Sprintf("iat (%s) is outside acceptable clock skew of current time (%s ± %s).", iatTime.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339), leeway)
	}
	checks = append(checks, DPoPCheck{
		Name:   "Creation timestamp (iat)",
		Passed: iatPassed,
		Detail: iatDetail,
	})
	if !iatPassed {
		allPassed = false
	}

	// Check 8: Access Token Hash (ath)
	if expectedAccessToken != "" || payload.ATH != "" {
		athPassed := false
		var athDetail string
		if expectedAccessToken == "" {
			athDetail = fmt.Sprintf("Proof contains ath (%s), but no access token was supplied to verify it against.", payload.ATH)
		} else if payload.ATH == "" {
			athDetail = "Access token was provided, but proof is missing mandatory 'ath' claim."
		} else {
			sum := sha256.Sum256([]byte(expectedAccessToken))
			expectedATH := b64url.EncodeToString(sum[:])
			if subtle.ConstantTimeCompare([]byte(payload.ATH), []byte(expectedATH)) == 1 {
				athPassed = true
				athDetail = "Access token hash (ath) matches SHA-256 digest of provided token."
			} else {
				athDetail = fmt.Sprintf("Access token hash mismatch: proof has %q, calculated %q.", payload.ATH, expectedATH)
			}
		}
		checks = append(checks, DPoPCheck{
			Name:   "Access token hash (ath)",
			Passed: athPassed,
			Detail: athDetail,
		})
		if !athPassed {
			allPassed = false
		}
	}

	headerPretty, _ := json.MarshalIndent(header, "", "  ")
	payloadPretty, _ := json.MarshalIndent(payload, "", "  ")

	var summary string
	if allPassed {
		summary = "DPoP proof is valid and conforms to RFC 9449."
	} else {
		summary = "DPoP proof verification failed. See checks below."
	}

	return &DPoPVerifyResult{
		Valid:         allPassed,
		Status:        ifElse(allPassed, "valid", "invalid"),
		HTM:           expectedHTM,
		HTU:           expectedHTU,
		Summary:       summary,
		JWKThumbprint: thumbprint,
		HeaderJSON:    string(headerPretty),
		PayloadJSON:   string(payloadPretty),
		Checks:        checks,
	}, nil
}

func normalizeDPoPUri(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", errors.New("URI must include scheme and host")
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func isBase64URL(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
